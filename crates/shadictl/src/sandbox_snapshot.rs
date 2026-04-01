use super::*;
use agent_transport_slim::{
    start_bridge_with_io, BridgeArgs as SlimBridgeArgs, BridgeReport as SlimBridgeReport,
    NativeSlimBootstrap, RunningBridge,
};
use shadi_sandbox::SandboxedChild;

#[cfg(all(not(test), unix))]
fn install_interrupt_flag() -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};

    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] {
        if let Err(err) = signal_hook::flag::register(signal, std::sync::Arc::clone(&interrupted)) {
            eprintln!("warning: failed to install signal handler for {}: {}", signal, err);
            return None;
        }
    }

    Some(interrupted)
}

#[cfg(all(not(test), windows))]
fn install_interrupt_flag() -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler_flag = std::sync::Arc::clone(&interrupted);
    if let Err(err) = ctrlc::set_handler(move || {
        handler_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }) {
        eprintln!("warning: failed to install signal handler: {}", err);
        return None;
    }
    Some(interrupted)
}

#[cfg(test)]
fn install_interrupt_flag() -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
    None
}

#[derive(Debug)]
enum ChildWaitOutcome {
    Exited(std::process::ExitStatus),
    RestartRequested,
    Terminated(std::process::ExitStatus),
}

fn wait_for_child_or_interrupt(
    child: &mut SandboxedChild,
    interrupted: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
    terminate_requested: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
    restart_requested: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> std::io::Result<ChildWaitOutcome> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(ChildWaitOutcome::Exited(status));
        }

        if interrupted.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst))
            || terminate_requested.is_some_and(|flag| {
                flag.load(std::sync::atomic::Ordering::SeqCst)
            })
        {
            let _ = child.kill();
            return child.wait().map(ChildWaitOutcome::Terminated);
        }

        if restart_requested.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst)) {
            let _ = child.kill();
            let _ = child.wait()?;
            return Ok(ChildWaitOutcome::RestartRequested);
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn prepare_sandbox_launch(
    cli: &Cli,
    file_policy: &PolicyFile,
    cwd: &Path,
    base_policy: &SandboxPolicy,
    net_proxy: Option<&NetProxy>,
) -> Result<
    (
        Command,
        Option<PendingTrustedSecretDelivery>,
        SandboxPolicy,
        Option<SlimBridgeArgs>,
    ),
    String,
> {
    let slim_bridge = resolve_internal_slim_bridge_args(cli)?;
    let cmd_name = cli.run_command.first().map(|cmd| cmd.as_str()).unwrap_or("");
    let mut command = Command::new(cmd_name);
    if cli.run_command.len() > 1 {
        command.args(&cli.run_command[1..]);
    }
    command.current_dir(cwd);
    if slim_bridge.is_some() {
        command.stdin(std::process::Stdio::piped());
        command.stdout(std::process::Stdio::piped());
    }
    #[cfg(test)]
    scrub_test_secret_backend_env(&mut command);

    // Inject proxy environment variables so SOCKS5-aware clients in the child
    // process route all TCP through the loopback proxy where the allowlist is
    // enforced.  ALL_PROXY/all_proxy covers both HTTP and HTTPS (and any other
    // TCP protocol); http_proxy/https_proxy are also set for older clients that
    // don't honour ALL_PROXY.
    if let Some(proxy) = net_proxy {
        let proxy_url = proxy.proxy_url(); // socks5h://127.0.0.1:<port>
        command.env("ALL_PROXY", &proxy_url);
        command.env("all_proxy", &proxy_url);
        // Curl and many HTTP libraries also check these; socks5h:// forwards
        // the hostname to the proxy (no local DNS), which is required for
        // hostname-based allowlist enforcement.
        command.env("http_proxy", &proxy_url);
        command.env("https_proxy", &proxy_url);
        command.env("HTTP_PROXY", &proxy_url);
        command.env("HTTPS_PROXY", &proxy_url);
    }

    // Strip any env vars the preset has explicitly opted out of (e.g. a
    // Node.js SEA runtime that doesn't support `socks5h://` in HTTPS_PROXY).
    for var in &file_policy.env_remove {
        command.env_remove(var);
    }

    let secret_config = resolve_launch_secret_config(&command, cli, file_policy)?;
    let pending_trusted_secrets = PendingTrustedSecretDelivery::new(
        &mut command,
        &secret_config.trusted_secret,
        &secret_config.trusted_secret_exec,
        &secret_config.trusted_secret_fd_env,
        &secret_config.process_secret_policy,
    )?;

    let mut runtime_policy = base_policy.clone();
    // When a proxy is active, configure the kernel sandbox to allow outbound
    // TCP only to the proxy's loopback port, not to arbitrary destinations.
    if let Some(proxy) = net_proxy {
        runtime_policy = runtime_policy.with_net_proxy_port(proxy.port());
    }
    if let Some(pending) = pending_trusted_secrets.as_ref() {
        for path in pending.endpoint_paths() {
            runtime_policy = runtime_policy
                .allow_read_path(&path)
                .allow_write_path(&path);
        }
    }

    #[cfg(target_os = "macos")]
    if pending_trusted_secrets.is_some() {
        runtime_policy = runtime_policy.allow_local_unix_sockets();
    }

    inject_keychain_secrets(&mut command, &secret_config.inject_keychain)?;

    Ok((command, pending_trusted_secrets, runtime_policy, slim_bridge))
}

pub(crate) fn run_sandboxed_command(
    cli: &Cli,
    resolved: &ResolvedPolicy,
    file_policy: &PolicyFile,
    cwd: &Path,
) -> ExitCode {
    let cmd_name = cli.run_command.first().map(|cmd| cmd.as_str()).unwrap_or("");
    let policy_source = cli
        .policy_file
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "default".to_string());
    let mut allowed_paths = BTreeSet::new();
    allowed_paths.extend(resolved.policy.allow_read().iter().cloned());
    allowed_paths.extend(resolved.policy.allow_write().iter().cloned());
    let network_mode = if resolved.policy.net_blocked() {
        "blocked"
    } else {
        "allowed"
    };

    let mut snapshot = GitSnapshotSession::start(cli, resolved, cwd);
    let snapshot_enabled = snapshot.is_some();

    // Start the control socket for dynamic policy updates if requested.
    let mut control_live = None;
    let mut terminate_requested = None;
    let mut restart_requested = None;
    // The proxy is kept alive for the lifetime of `run_sandboxed_command`.
    // It is restarted on the same port when the child is relaunched —
    // required on macOS where the Seatbelt profile bakes in the proxy port,
    // and consistent on Linux (Landlock rule also contains the port).
    let mut net_proxy_handle: Option<NetProxy>;
    let _control_handle = if cli.watch_policy {
        let terminate_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let restart_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Start the network enforcement proxy.  The kernel sandbox
        // (Landlock on Linux, Seatbelt on macOS) is set to allow outbound TCP
        // only to this loopback port, so the proxy is the sole exit gate.
        // DNS-name allowlist is enforced here; policy patches update the shared
        // allowlist in-place without restarting the child.
        // On Windows: kernel channel enforcement is not available without
        // elevated privileges; proxy env vars are set but can be bypassed.
        let (net_allowlist, proxy_opt) = {
            let initial = resolved.policy.net_allow().to_vec();
            let al = NetAllowlist::new(initial);
            match NetProxy::start(al.clone()) {
                Ok(proxy) => {
                    eprintln!(
                        "network proxy (DNS-name enforcement gate): 127.0.0.1:{}",
                        proxy.port()
                    );
                    (Some(al), Some(proxy))
                }
                Err(err) => {
                    eprintln!("warning: failed to start network enforcement proxy: {err}; network policy changes will require restart");
                    (None, None)
                }
            }
        };
        net_proxy_handle = proxy_opt;

        let live = std::sync::Arc::new(std::sync::Mutex::new(LivePolicy {
            policy: resolved.policy.clone(),
            blocked: resolved.blocked.clone(),
            allow: resolved.allow.clone(),
            terminate_requested: std::sync::Arc::clone(&terminate_flag),
            restart_requested: std::sync::Arc::clone(&restart_flag),
            child_pid: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: net_allowlist,
        }));
        let pid = std::process::id();
        let sock_path = match cli.session_name.as_deref() {
            Some(name) => policy_watch::named_socket_path(name),
            None => default_socket_path(pid),
        };
        match start_control_socket(&sock_path, std::sync::Arc::clone(&live)) {
            Ok(handle) => {
                if let Some(name) = cli.session_name.as_deref() {
                    eprintln!("session name: {}", name);
                } else {
                    eprintln!("control socket: {}", handle.path().display());
                }
                if let Some(record_ref) = cli.record_ref.as_deref() {
                    eprintln!("record: {}", record_ref);
                }
                control_live = Some(live);
                restart_requested = Some(restart_flag);
                terminate_requested = Some(terminate_flag);
                Some(handle)
            }
            Err(err) => {
                eprintln!("warning: failed to start control socket: {}", err);
                None
            }
        }
    } else {
        net_proxy_handle = None;
        None
    };

    let span = info_span!(
        "shadi.sandbox.run",
        command = %cmd_name,
        cwd = %cwd.display(),
        policy.source = %policy_source,
        policy.allowed_paths = allowed_paths.len() as i64,
        network.mode = %network_mode,
        snapshot.enabled = snapshot_enabled,
        exit.code = field::Empty,
        snapshot.path = field::Empty,
    );
    let _guard = span.enter();

    let interrupted = install_interrupt_flag();

    loop {
        let base_policy = match control_live.as_ref() {
            Some(live) => match snapshot_live_policy(live) {
                Ok(policy) => policy,
                Err(err) => {
                    span.record("exit.code", &-1);
                    let snapshot_path = finalize_git_snapshot(
                        snapshot.as_mut(),
                        None,
                        Some(format!("failed to read live policy: {}", err)),
                    );
                    if let Some(path) = snapshot_path {
                        span.record("snapshot.path", &path.display().to_string());
                    }
                    eprintln!("failed to read live policy: {}", err);
                    return ExitCode::from(1);
                }
            },
            None => resolved.policy.clone(),
        };

        let (mut command, mut pending_trusted_secrets, runtime_policy, slim_bridge_args) = match prepare_sandbox_launch(
            cli,
            file_policy,
            cwd,
            &base_policy,
            net_proxy_handle.as_ref(),
        ) {
            Ok(launch) => launch,
            Err(err) => {
                let exit_code = if err.starts_with("failed to inject keychain secrets")
                    || err.starts_with("failed to resolve launch secret policy")
                    || err.starts_with("failed to configure trusted secret delivery")
                {
                    2
                } else {
                    2
                };
                eprintln!("{}", err);
                return ExitCode::from(exit_code);
            }
        };

        let mut child = match spawn_sandboxed(&mut command, &runtime_policy) {
            Ok(child) => child,
            Err(err) => {
                span.record("exit.code", &-1);
                let snapshot_path = finalize_git_snapshot(
                    snapshot.as_mut(),
                    None,
                    Some(format!("failed to start sandboxed command: {}", err)),
                );
                if let Some(path) = snapshot_path {
                    span.record("snapshot.path", &path.display().to_string());
                }
                eprintln!("failed to start sandboxed command: {}", err);
                return ExitCode::from(1);
            }
        };

        // Update the child PID so the control socket can query resources.
        if let Some(ref live) = control_live {
            if let Ok(guard) = live.lock() {
                guard
                    .child_pid
                    .store(child.id(), std::sync::atomic::Ordering::SeqCst);
            }
        }

        if let Some(pending) = pending_trusted_secrets.as_mut() {
            if let Err(err) = pending.deliver_after_spawn(child.id()) {
                let _ = child.kill();
                let _ = child.wait();
                pending.close_parent_fds();
                span.record("exit.code", &-1);
                let snapshot_path = finalize_git_snapshot(
                    snapshot.as_mut(),
                    None,
                    Some(format!("failed to deliver trusted secret: {}", err)),
                );
                if let Some(path) = snapshot_path {
                    span.record("snapshot.path", &path.display().to_string());
                }
                eprintln!("failed to deliver trusted secret: {}", err);
                return ExitCode::from(1);
            }
        }

        let mut slim_bridge = match slim_bridge_args {
            Some(args) => match start_internal_slim_bridge(&mut child, args) {
                Ok(bridge) => {
                    let info = bridge.session_info().clone();
                    eprintln!(
                        "connected internal SLIM bridge as {} to {} {} session {}",
                        info.local_name, info.mode, info.target, info.session_id
                    );
                    Some(bridge)
                }
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(pending) = pending_trusted_secrets.as_mut() {
                        pending.close_parent_fds();
                    }
                    span.record("exit.code", &-1);
                    let snapshot_path = finalize_git_snapshot(
                        snapshot.as_mut(),
                        None,
                        Some(format!("failed to start internal SLIM bridge: {}", err)),
                    );
                    if let Some(path) = snapshot_path {
                        span.record("snapshot.path", &path.display().to_string());
                    }
                    eprintln!("failed to start internal SLIM bridge: {}", err);
                    return ExitCode::from(1);
                }
            },
            None => None,
        };

        match wait_for_child_or_interrupt(
            &mut child,
            interrupted.as_ref(),
            terminate_requested.as_ref(),
            restart_requested.as_ref(),
        ) {
            Ok(ChildWaitOutcome::RestartRequested) => {
                let bridge_report = match stop_internal_slim_bridge(slim_bridge.take()) {
                    Ok(report) => report,
                    Err(err) => {
                        if let Some(pending) = pending_trusted_secrets.as_mut() {
                            pending.close_parent_fds();
                        }
                        span.record("exit.code", &-1);
                        let snapshot_path = finalize_git_snapshot(
                            snapshot.as_mut(),
                            None,
                            Some(format!("failed to stop internal SLIM bridge: {}", err)),
                        );
                        if let Some(path) = snapshot_path {
                            span.record("snapshot.path", &path.display().to_string());
                        }
                        eprintln!("failed to stop internal SLIM bridge: {}", err);
                        return ExitCode::from(1);
                    }
                };
                if let Some(report) = bridge_report.as_ref() {
                    print_internal_slim_bridge_summary(report);
                }
                if let Some(pending) = pending_trusted_secrets.as_mut() {
                    pending.close_parent_fds();
                }
                // Restart the proxy on the same port.  The new child will get a
                // fresh kernel sandbox rule with the same port number, so the
                // proxy must rebind there (mandatory on macOS / Seatbelt).
                if let Some(proxy) = net_proxy_handle.take() {
                    let allowlist = control_live
                        .as_ref()
                        .and_then(|live| live.lock().ok())
                        .and_then(|guard| guard.live_net_allowlist.clone())
                        .unwrap_or_else(|| NetAllowlist::new(vec![]));
                    match proxy.restart(allowlist) {
                        Ok(new_proxy) => {
                            net_proxy_handle = Some(new_proxy);
                        }
                        Err(err) => {
                            eprintln!("warning: failed to restart network proxy on same port: {err}");
                        }
                    }
                }
                if let Some(live) = control_live.as_ref() {
                    if let Err(err) = apply_staged_policy_updates(live) {
                        span.record("exit.code", &-1);
                        let snapshot_path = finalize_git_snapshot(
                            snapshot.as_mut(),
                            None,
                            Some(format!("failed to apply staged policy update: {}", err)),
                        );
                        if let Some(path) = snapshot_path {
                            span.record("snapshot.path", &path.display().to_string());
                        }
                        eprintln!("failed to apply staged policy update: {}", err);
                        return ExitCode::from(1);
                    }
                }
                eprintln!("policy update requires sandbox relaunch; restarting process");
            }
            Ok(ChildWaitOutcome::Exited(status)) | Ok(ChildWaitOutcome::Terminated(status)) => {
                let exit_code = status.code().unwrap_or(1);
                let bridge_report = match stop_internal_slim_bridge(slim_bridge.take()) {
                    Ok(report) => report,
                    Err(err) => {
                        span.record("exit.code", &-1);
                        let snapshot_path = finalize_git_snapshot(
                            snapshot.as_mut(),
                            None,
                            Some(format!("failed to stop internal SLIM bridge: {}", err)),
                        );
                        if let Some(path) = snapshot_path {
                            span.record("snapshot.path", &path.display().to_string());
                        }
                        eprintln!("failed to stop internal SLIM bridge: {}", err);
                        return ExitCode::from(1);
                    }
                };
                if let Some(report) = bridge_report.as_ref() {
                    print_internal_slim_bridge_summary(report);
                }
                if let Some(pending) = pending_trusted_secrets.as_mut() {
                    if let Err(err) = pending.wait_for_background_delivery() {
                        span.record("exit.code", &-1);
                        let snapshot_path = finalize_git_snapshot(
                            snapshot.as_mut(),
                            None,
                            Some(format!("failed to complete trusted secret delivery: {}", err)),
                        );
                        if let Some(path) = snapshot_path {
                            span.record("snapshot.path", &path.display().to_string());
                        }
                        pending.close_parent_fds();
                        eprintln!("failed to complete trusted secret delivery: {}", err);
                        return ExitCode::from(1);
                    }
                    pending.close_parent_fds();
                }
                span.record("exit.code", &exit_code);
                let snapshot_path = finalize_git_snapshot(snapshot.as_mut(), status.code(), None);
                if let Some(path) = snapshot_path {
                    span.record("snapshot.path", &path.display().to_string());
                }
                return ExitCode::from(status.code().unwrap_or(1) as u8);
            }
            Err(err) => {
                if let Some(bridge) = slim_bridge.take() {
                    bridge.request_stop();
                    let _ = bridge.wait();
                }
                span.record("exit.code", &-1);
                let snapshot_path = finalize_git_snapshot(
                    snapshot.as_mut(),
                    None,
                    Some(format!("failed to wait for child: {}", err)),
                );
                if let Some(path) = snapshot_path {
                    span.record("snapshot.path", &path.display().to_string());
                }
                eprintln!("failed to wait for child: {}", err);
                return ExitCode::from(1);
            }
        }
    }
}

fn resolve_internal_slim_bridge_args(cli: &Cli) -> Result<Option<SlimBridgeArgs>, String> {
    let timeout = match cli.slim_timeout {
        Some(0) => None,
        Some(seconds) => Some(std::time::Duration::from_secs(seconds)),
        None => Some(std::time::Duration::from_secs(30)),
    };

    match (&cli.slim_channel, &cli.slim_destination) {
        (Some(_), Some(_)) => {
            Err("use either --slim-channel or --slim-destination, not both".to_string())
        }
        (Some(channel), None) => Ok(Some(SlimBridgeArgs {
            bootstrap: NativeSlimBootstrap::GroupJoin {
                channel: channel.clone(),
                timeout,
            },
            payload_type: cli.slim_payload_type.clone(),
            allow_empty: cli.slim_allow_empty,
        })),
        (None, Some(destination)) => {
            if cli.slim_timeout.is_some() {
                return Err("--slim-timeout is only valid with --slim-channel".to_string());
            }
            Ok(Some(SlimBridgeArgs {
                bootstrap: NativeSlimBootstrap::PointToPoint {
                    destination: destination.clone(),
                },
                payload_type: cli.slim_payload_type.clone(),
                allow_empty: cli.slim_allow_empty,
            }))
        }
        (None, None) => {
            if cli.slim_timeout.is_some() {
                return Err("--slim-timeout requires --slim-channel".to_string());
            }
            if cli.slim_payload_type.is_some() {
                return Err(
                    "--slim-payload-type requires --slim-channel or --slim-destination"
                        .to_string(),
                );
            }
            if cli.slim_allow_empty {
                return Err(
                    "--slim-allow-empty requires --slim-channel or --slim-destination"
                        .to_string(),
                );
            }
            Ok(None)
        }
    }
}

fn start_internal_slim_bridge(
    child: &mut SandboxedChild,
    args: SlimBridgeArgs,
) -> Result<RunningBridge, String> {
    let child_stdout = child
        .take_stdout()
        .ok_or_else(|| "internal SLIM bridge requires piped child stdout".to_string())?;
    let child_stdin = child
        .take_stdin()
        .ok_or_else(|| "internal SLIM bridge requires piped child stdin".to_string())?;
    start_bridge_with_io(args, child_stdout, child_stdin, None)
}

fn stop_internal_slim_bridge(
    bridge: Option<RunningBridge>,
) -> Result<Option<SlimBridgeReport>, String> {
    match bridge {
        Some(bridge) => {
            bridge.request_stop();
            bridge.wait().map(Some)
        }
        None => Ok(None),
    }
}

fn print_internal_slim_bridge_summary(report: &SlimBridgeReport) {
    eprintln!(
        "internal SLIM bridge published {} SLIM messages and received {} SLIM messages",
        report.published, report.received
    );
}

pub(crate) fn finalize_git_snapshot(
    snapshot: Option<&mut GitSnapshotSession>,
    exit_code: Option<i32>,
    error: Option<String>,
) -> Option<PathBuf> {
    if let Some(snapshot) = snapshot {
        match snapshot.finish(exit_code, error) {
            Ok(path) => Some(path),
            Err(err) => {
                eprintln!("warning: failed to write git snapshot artifact: {}", err);
                None
            }
        }
    } else {
        None
    }
}

#[derive(Debug)]
pub(crate) struct GitSnapshotConfig {
    output_dir: PathBuf,
    include_untracked: bool,
}

impl GitSnapshotConfig {
    fn from_cli(cli: &Cli) -> Option<Self> {
        if !cli.git_snapshot {
            return None;
        }

        Some(Self {
            output_dir: cli
                .git_snapshot_dir
                .clone()
                .unwrap_or_else(default_git_snapshot_dir),
            include_untracked: cli.git_snapshot_untracked,
        })
    }
}

#[derive(Debug)]
pub(crate) struct GitSnapshotSession {
    artifact: GitSnapshotArtifact,
    pub(crate) output_dir: PathBuf,
}

impl GitSnapshotSession {
    pub(crate) fn start(cli: &Cli, resolved: &ResolvedPolicy, cwd: &Path) -> Option<Self> {
        let config = GitSnapshotConfig::from_cli(cli)?;
        let started_at_ms = unix_timestamp_ms();
        let policy = snapshot_policy_value(&resolved.policy, &resolved.blocked, &resolved.allow);
        let git = capture_git_snapshot(cwd, config.include_untracked);

        Some(Self {
            artifact: GitSnapshotArtifact {
                schema_version: 1,
                artifact_id: build_snapshot_artifact_id(&cli.run_command, started_at_ms),
                command: cli.run_command.clone(),
                cwd: cwd.display().to_string(),
                policy,
                timestamps: GitSnapshotTimestamps {
                    started_at_ms,
                    finished_at_ms: None,
                    duration_ms: None,
                },
                outcome: GitSnapshotOutcome {
                    exit_code: None,
                    error: None,
                },
                git,
                layout: GitSnapshotLayout::default(),
            },
            output_dir: config.output_dir,
        })
    }

    pub(crate) fn finish(&mut self, exit_code: Option<i32>, error: Option<String>) -> Result<PathBuf, String> {
        let finished_at_ms = unix_timestamp_ms();
        self.artifact.timestamps.finished_at_ms = Some(finished_at_ms);
        self.artifact.timestamps.duration_ms =
            Some(finished_at_ms.saturating_sub(self.artifact.timestamps.started_at_ms));
        self.artifact.outcome.exit_code = exit_code;
        self.artifact.outcome.error = error;

        for repository in &mut self.artifact.git.repositories {
            if repository.capture_error.is_none() {
                match collect_git_repo_state(
                    Path::new(&repository.repo_root),
                    self.artifact.git.include_untracked_inventory,
                ) {
                    Ok(after) => {
                        let summary = summarize_status_lines(&after.status_porcelain);
                        repository.diff_summary = Some(summary);
                        repository.after = Some(after);
                    }
                    Err(err) => {
                        repository.capture_error = Some(err);
                    }
                }
            }

            repository.comparison =
                build_git_state_comparison(repository.before.as_ref(), repository.after.as_ref());
        }

        self.artifact.git.sync_primary_repository_fields();
        self.artifact.git.refresh_change_summary();

        std::fs::create_dir_all(&self.output_dir)
            .map_err(|err| format!("failed to create {}: {}", self.output_dir.display(), err))?;

        let run_dir = self.output_dir.join("runs").join(&self.artifact.artifact_id);
        std::fs::create_dir_all(&run_dir)
            .map_err(|err| format!("failed to create {}: {}", run_dir.display(), err))?;

        let path = run_dir.join("snapshot.json");
        let latest = self.output_dir.join("latest.json");
        self.artifact.layout.root_dir = self.output_dir.display().to_string();
        self.artifact.layout.run_dir = run_dir.display().to_string();
        self.artifact.layout.snapshot_file = path.display().to_string();
        self.artifact.layout.latest_file = latest.display().to_string();

        let payload = serde_json::to_string_pretty(&self.artifact).map_err(|err| err.to_string())?;
        std::fs::write(&path, format!("{}\n", payload))
            .map_err(|err| format!("failed to write {}: {}", path.display(), err))?;

        std::fs::write(&latest, format!("{}\n", payload))
            .map_err(|err| format!("failed to write {}: {}", latest.display(), err))?;
        Ok(path)
    }
}

#[derive(Debug, Serialize)]
struct GitSnapshotArtifact {
    schema_version: u32,
    artifact_id: String,
    command: Vec<String>,
    cwd: String,
    policy: Value,
    timestamps: GitSnapshotTimestamps,
    outcome: GitSnapshotOutcome,
    git: GitSnapshotRecord,
    layout: GitSnapshotLayout,
}

#[derive(Debug, Serialize)]
pub(crate) struct GitSnapshotLayout {
    pub(crate) root_dir: String,
    pub(crate) run_dir: String,
    pub(crate) snapshot_file: String,
    pub(crate) latest_file: String,
}

impl Default for GitSnapshotLayout {
    fn default() -> Self {
        Self {
            root_dir: String::new(),
            run_dir: String::new(),
            snapshot_file: String::new(),
            latest_file: String::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct GitSnapshotTimestamps {
    started_at_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
}

#[derive(Debug, Serialize)]
struct GitSnapshotOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GitSnapshotRecord {
    detected: bool,
    changed_repositories: usize,
    any_repo_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_root: Option<String>,
    include_untracked_inventory: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_summary: Option<GitDiffSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<GitStateComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capture_error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    repositories: Vec<GitTrackedRepository>,
}

impl GitSnapshotRecord {
    fn sync_primary_repository_fields(&mut self) {
        if let Some(primary) = self.repositories.first() {
            self.repo_root = Some(primary.repo_root.clone());
            self.before = primary.before.clone();
            self.after = primary.after.clone();
            self.diff_summary = primary.diff_summary.clone();
            self.comparison = primary.comparison.clone();
            self.capture_error = primary.capture_error.clone();
        } else {
            self.repo_root = None;
            self.before = None;
            self.after = None;
            self.diff_summary = None;
            self.comparison = None;
            self.capture_error = None;
        }
    }

    fn refresh_change_summary(&mut self) {
        self.changed_repositories = self
            .repositories
            .iter()
            .filter(|repository| {
                repository
                    .comparison
                    .as_ref()
                    .map(|comparison| comparison.overall_changed)
                    .unwrap_or(false)
            })
            .count();
        self.any_repo_changed = self.changed_repositories > 0;
        self.detected = !self.repositories.is_empty();
    }
}

#[derive(Debug, Clone, Serialize)]
struct GitTrackedRepository {
    repo_root: String,
    relative_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_summary: Option<GitDiffSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<GitStateComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capture_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct GitRepoState {
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<String>,
    status_porcelain: Vec<String>,
    diff_binary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked_inventory: Option<Vec<String>>,
    hashes: GitRepoStateHashes,
}

#[derive(Debug, Clone, Serialize)]
struct GitRepoStateHashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    head_sha256: Option<String>,
    status_sha256: String,
    diff_binary_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked_inventory_sha256: Option<String>,
    state_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct GitStateComparison {
    #[serde(skip_serializing_if = "Option::is_none")]
    before_state_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_state_sha256: Option<String>,
    head_changed: bool,
    status_changed: bool,
    diff_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked_changed: Option<bool>,
    overall_changed: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct GitDiffSummary {
    pub(crate) added: usize,
    pub(crate) modified: usize,
    pub(crate) deleted: usize,
    pub(crate) renamed: usize,
    pub(crate) copied: usize,
    pub(crate) unmerged: usize,
    pub(crate) untracked: usize,
    pub(crate) other: usize,
    pub(crate) changed: bool,
}

fn default_git_snapshot_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./.tmp"))
        .join("git-snapshots")
}

fn build_snapshot_artifact_id(command: &[String], started_at_ms: u128) -> String {
    let cmd = command
        .first()
        .map(|value| sanitize_snapshot_component(value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "command".to_string());
    format!("{}-{}-{}", started_at_ms, std::process::id(), cmd)
}

fn sanitize_snapshot_component(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').chars().take(48).collect()
}

fn snapshot_policy_value(policy: &SandboxPolicy, blocked: &HashSet<String>, allow: &HashSet<String>) -> Value {
    match format_policy(policy, blocked, allow) {
        Ok(output) => serde_json::from_str(&output).unwrap_or_else(|_| Value::String(output)),
        Err(err) => Value::String(err),
    }
}

fn capture_git_snapshot(cwd: &Path, include_untracked: bool) -> GitSnapshotRecord {
    match discover_git_repo_roots(cwd) {
        Ok(repo_roots) if repo_roots.is_empty() => GitSnapshotRecord {
            detected: false,
            changed_repositories: 0,
            any_repo_changed: false,
            repo_root: None,
            include_untracked_inventory: include_untracked,
            before: None,
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: None,
            repositories: Vec::new(),
        },
        Ok(repo_roots) => {
            let repositories = repo_roots
                .into_iter()
                .map(|repo_root| capture_git_repository_snapshot(cwd, &repo_root, include_untracked))
                .collect::<Vec<_>>();

            let mut record = GitSnapshotRecord {
                detected: true,
                changed_repositories: 0,
                any_repo_changed: false,
                repo_root: None,
                include_untracked_inventory: include_untracked,
                before: None,
                after: None,
                diff_summary: None,
                comparison: None,
                capture_error: None,
                repositories,
            };
            record.sync_primary_repository_fields();
            record.refresh_change_summary();
            record
        }
        Err(err) => GitSnapshotRecord {
            detected: false,
            changed_repositories: 0,
            any_repo_changed: false,
            repo_root: None,
            include_untracked_inventory: include_untracked,
            before: None,
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: Some(err),
            repositories: Vec::new(),
        },
    }
}

fn capture_git_repository_snapshot(cwd: &Path, repo_root: &Path, include_untracked: bool) -> GitTrackedRepository {
    let repo_root_string = repo_root.display().to_string();
    match collect_git_repo_state(repo_root, include_untracked) {
        Ok(before) => GitTrackedRepository {
            repo_root: repo_root_string,
            relative_path: repo_relative_path(cwd, repo_root),
            before: Some(before),
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: None,
        },
        Err(err) => GitTrackedRepository {
            repo_root: repo_root_string,
            relative_path: repo_relative_path(cwd, repo_root),
            before: None,
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: Some(err),
        },
    }
}

fn repo_relative_path(cwd: &Path, repo_root: &Path) -> String {
    match repo_root.strip_prefix(cwd) {
        Ok(relative) if relative.as_os_str().is_empty() => ".".to_string(),
        Ok(relative) => relative.display().to_string(),
        Err(_) if cwd.starts_with(repo_root) => ".".to_string(),
        Err(_) => repo_root.display().to_string(),
    }
}

fn discover_git_repo_roots(cwd: &Path) -> Result<Vec<PathBuf>, String> {
    let mut repo_roots = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(primary_root) = detect_git_repo_root(cwd)? {
        let normalized = canonicalize_or_clone(&primary_root);
        seen.insert(normalized.clone());
        repo_roots.push(normalized);
    }

    let scope_root = canonicalize_or_clone(cwd);
    let mut nested_roots = find_nested_git_repo_roots(&scope_root)?;
    nested_roots.sort();

    for repo_root in nested_roots {
        if seen.insert(repo_root.clone()) {
            repo_roots.push(repo_root);
        }
    }

    Ok(repo_roots)
}

fn find_nested_git_repo_roots(scope_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut repo_roots = Vec::new();
    let mut stack = vec![scope_root.to_path_buf()];

    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|err| format!("failed to scan {}: {}", directory.display(), err))?;

        for entry in entries {
            let entry = entry.map_err(|err| format!("failed to scan {}: {}", directory.display(), err))?;
            let path = entry.path();
            let file_name = entry.file_name();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("failed to inspect {}: {}", path.display(), err))?;

            if file_name == std::ffi::OsStr::new(".git") {
                if let Some(repo_dir) = path.parent() {
                    if let Some(repo_root) = detect_git_repo_root(repo_dir)? {
                        let normalized = canonicalize_or_clone(&repo_root);
                        if normalized.starts_with(scope_root) || scope_root.starts_with(&normalized) {
                            repo_roots.push(normalized);
                        }
                    }
                }
                continue;
            }

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }

    Ok(repo_roots)
}

fn canonicalize_or_clone(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn detect_git_repo_root(cwd: &Path) -> Result<Option<PathBuf>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to execute git: {}", err))?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "git returned non-utf8 output for repo root".to_string())?;
    let root = stdout.trim();
    if root.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(root)))
}

fn collect_git_repo_state(repo_root: &Path, include_untracked: bool) -> Result<GitRepoState, String> {
    let head = run_git_capture_optional(repo_root, &["rev-parse", "HEAD"])?;
    let status = run_git_capture(repo_root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    let status_porcelain = split_nonempty_lines(&status);
    let diff_binary = run_git_capture(repo_root, &["diff", "--binary"])?;
    let untracked_inventory = if include_untracked {
        let files = run_git_capture(repo_root, &["ls-files", "--others", "--exclude-standard"])?;
        Some(split_nonempty_lines(&files))
    } else {
        None
    };
    let hashes = build_git_repo_state_hashes(
        head.as_deref(),
        &status_porcelain,
        &diff_binary,
        untracked_inventory.as_deref(),
    );

    Ok(GitRepoState {
        head,
        status_porcelain: status_porcelain.clone(),
        diff_binary,
        untracked_inventory,
        hashes,
    })
}

fn build_git_repo_state_hashes(
    head: Option<&str>,
    status_porcelain: &[String],
    diff_binary: &str,
    untracked_inventory: Option<&[String]>,
) -> GitRepoStateHashes {
    let head_sha256 = head.map(sha256_hex);
    let status_text = status_porcelain.join("\n");
    let status_sha256 = sha256_hex(&status_text);
    let diff_binary_sha256 = sha256_hex(diff_binary);
    let untracked_inventory_sha256 =
        untracked_inventory.map(|entries| sha256_hex(&entries.join("\n")));
    let state_sha256 = sha256_hex(
        &json!({
            "head": head,
            "status_porcelain": status_porcelain,
            "diff_binary_sha256": diff_binary_sha256,
            "untracked_inventory": untracked_inventory,
        })
        .to_string(),
    );

    GitRepoStateHashes {
        head_sha256,
        status_sha256,
        diff_binary_sha256,
        untracked_inventory_sha256,
        state_sha256,
    }
}

fn build_git_state_comparison(before: Option<&GitRepoState>, after: Option<&GitRepoState>) -> Option<GitStateComparison> {
    let before = before?;
    let after = after?;

    Some(GitStateComparison {
        before_state_sha256: Some(before.hashes.state_sha256.clone()),
        after_state_sha256: Some(after.hashes.state_sha256.clone()),
        head_changed: before.head != after.head,
        status_changed: before.hashes.status_sha256 != after.hashes.status_sha256,
        diff_changed: before.hashes.diff_binary_sha256 != after.hashes.diff_binary_sha256,
        untracked_changed: match (
            before.hashes.untracked_inventory_sha256.as_ref(),
            after.hashes.untracked_inventory_sha256.as_ref(),
        ) {
            (Some(left), Some(right)) => Some(left != right),
            (None, None) => None,
            _ => Some(true),
        },
        overall_changed: before.hashes.state_sha256 != after.hashes.state_sha256,
    })
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn run_git_capture(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute git {}: {}", args.join(" "), err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            repo_root.display(),
            stderr.trim()
        ));
    }

    String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-utf8 output", args.join(" ")))
}

fn run_git_capture_optional(repo_root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute git {}: {}", args.join(" "), err))?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-utf8 output", args.join(" ")))?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

fn split_nonempty_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

pub(crate) fn summarize_status_lines(lines: &[String]) -> GitDiffSummary {
    let mut summary = GitDiffSummary::default();

    for line in lines {
        let status = line.get(0..2).unwrap_or("");
        if status == "??" {
            summary.untracked += 1;
            continue;
        }

        for code in status.chars() {
            match code {
                'A' => summary.added += 1,
                'M' => summary.modified += 1,
                'D' => summary.deleted += 1,
                'R' => summary.renamed += 1,
                'C' => summary.copied += 1,
                'U' => summary.unmerged += 1,
                ' ' => {}
                _ => summary.other += 1,
            }
        }
    }

    summary.changed = !lines.is_empty();
    summary
}

fn unix_timestamp_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, PolicyFile, resolve_policy};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const TEST_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";

    #[derive(Clone)]
    struct TestTlsMaterial {
        cert: PathBuf,
        key: PathBuf,
        ca: PathBuf,
    }

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn build_cli() -> Cli {
        Cli {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            inject_keychain: Vec::new(),
            trusted_secret: Vec::new(),
            trusted_secret_exec: Vec::new(),
            trusted_secret_fd_env: Vec::new(),
            list_keychain: false,
            list_prefix: None,
            print_policy: false,
            git_snapshot: false,
            git_snapshot_dir: None,
            git_snapshot_untracked: false,
            watch_policy: false,
            slim_channel: None,
            slim_destination: None,
            slim_timeout: None,
            slim_payload_type: None,
            slim_allow_empty: false,
            session_name: None,
            record_ref: None,
            subcommand: None,
            run_command: vec!["echo".to_string(), "ok".to_string()],
        }
    }

    fn generate_test_tls_dir(base_dir: &Path) -> PathBuf {
        let tls_dir = base_dir.join("shadi-slim-mtls");
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("tools")
            .join("generate_slim_mtls_certs.sh");
        let output = Command::new("bash")
            .arg(&script)
            .arg(&tls_dir)
            .output()
            .expect("run SLIM cert generator");

        assert!(
            output.status.success(),
            "failed to generate SLIM test certs: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        tls_dir
    }

    fn test_client_tls_material(base_dir: &Path, agent_id: &str) -> TestTlsMaterial {
        TestTlsMaterial {
            cert: base_dir.join(format!("client-{agent_id}.crt")),
            key: base_dir.join(format!("client-{agent_id}.key")),
            ca: base_dir.join("ca.crt"),
        }
    }

    fn test_server_tls_material(base_dir: &Path) -> TestTlsMaterial {
        TestTlsMaterial {
            cert: base_dir.join("server.crt"),
            key: base_dir.join("server.key"),
            ca: base_dir.join("ca.crt"),
        }
    }

    fn build_test_client_config(endpoint: &str, tls: &TestTlsMaterial) -> slim_bindings::ClientConfig {
        let mut config = slim_bindings::ClientConfig::default();
        config.endpoint = format!("https://{endpoint}");
        config.tls = slim_bindings::TlsClientConfig {
            insecure: false,
            insecure_skip_verify: false,
            source: slim_bindings::TlsSource::File {
                cert: tls.cert.display().to_string(),
                key: tls.key.display().to_string(),
            },
            ca_source: slim_bindings::CaSource::File {
                path: tls.ca.display().to_string(),
            },
            include_system_ca_certs_pool: true,
            tls_version: "tls1.3".to_string(),
        };
        config
    }

    fn build_test_server_config(endpoint: &str, tls: &TestTlsMaterial) -> slim_bindings::ServerConfig {
        let mut config = slim_bindings::ServerConfig::default();
        config.endpoint = endpoint.to_string();
        config.tls = slim_bindings::TlsServerConfig {
            insecure: false,
            source: slim_bindings::TlsSource::File {
                cert: tls.cert.display().to_string(),
                key: tls.key.display().to_string(),
            },
            client_ca: slim_bindings::CaSource::File {
                path: tls.ca.display().to_string(),
            },
            include_system_ca_certs_pool: Some(true),
            tls_version: Some("tls1.3".to_string()),
            reload_client_ca_file: Some(false),
        };
        config
    }

    fn reserve_test_endpoint() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let endpoint = listener.local_addr().expect("local addr").to_string();
        drop(listener);
        endpoint
    }

    fn format_slim_error(err: slim_bindings::SlimError) -> String {
        err.to_string()
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_child_or_interrupt_kills_process_when_terminate_flag_is_set() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let mut child = SandboxedChild::from_std(child);
        let terminate_requested = Arc::new(AtomicBool::new(false));
        let signal_flag = Arc::clone(&terminate_requested);

        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            signal_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let outcome = wait_for_child_or_interrupt(&mut child, None, Some(&terminate_requested), None)
            .expect("wait for terminated child");
        match outcome {
            ChildWaitOutcome::Terminated(status) => assert!(!status.success()),
            other => panic!("expected Terminated, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_child_or_interrupt_kills_process_when_interrupt_flag_is_set() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let mut child = SandboxedChild::from_std(child);
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal_flag = Arc::clone(&interrupted);

        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            signal_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let outcome = wait_for_child_or_interrupt(&mut child, Some(&interrupted), None, None)
            .expect("wait for interrupted child");
        match outcome {
            ChildWaitOutcome::Terminated(status) => assert!(!status.success()),
            other => panic!("expected Terminated, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_child_or_interrupt_returns_restart_requested_when_restart_flag_is_set() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let mut child = SandboxedChild::from_std(child);
        let restart_requested = Arc::new(AtomicBool::new(false));
        let signal_flag = Arc::clone(&restart_requested);

        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            signal_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let outcome = wait_for_child_or_interrupt(&mut child, None, None, Some(&restart_requested))
            .expect("wait for restart");
        assert!(matches!(outcome, ChildWaitOutcome::RestartRequested));
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_child_or_interrupt_returns_exited_when_child_exits_normally() {
        let child = Command::new("/usr/bin/true")
            .spawn()
            .expect("spawn true");
        let mut child = SandboxedChild::from_std(child);

        let outcome = wait_for_child_or_interrupt(&mut child, None, None, None)
            .expect("wait for exit");
        match outcome {
            ChildWaitOutcome::Exited(status) => assert!(status.success()),
            other => panic!("expected Exited, got {:?}", other),
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_child_terminate_takes_priority_over_restart() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let mut child = SandboxedChild::from_std(child);
        let terminate = Arc::new(AtomicBool::new(false));
        let restart = Arc::new(AtomicBool::new(false));
        let t = Arc::clone(&terminate);
        let r = Arc::clone(&restart);

        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            // Set both; terminate should win because it's checked first.
            t.store(true, std::sync::atomic::Ordering::SeqCst);
            r.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let outcome = wait_for_child_or_interrupt(&mut child, None, Some(&terminate), Some(&restart))
            .expect("wait");
        assert!(matches!(outcome, ChildWaitOutcome::Terminated(_)));
    }

    #[test]
    fn prepare_sandbox_launch_returns_policy_with_base_net_allow() {
        let cli = build_cli();
        let file_policy = PolicyFile::default();
        let base_policy = SandboxPolicy::new()
            .allow_network_destination("1.1.1.1:80");
        let dir = temp_dir();

        let (_command, _pending, runtime_policy, _bridge) =
            prepare_sandbox_launch(&cli, &file_policy, dir.path(), &base_policy, None)
                .expect("prepare launch");

        assert_eq!(runtime_policy.net_allow(), &["1.1.1.1:80".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_sandbox_launch_with_proxy_injects_all_proxy_vars() {
        let mut cli = build_cli();
        cli.run_command = vec!["/usr/bin/env".to_string()];
        let file_policy = PolicyFile::default();
        let base_policy = SandboxPolicy::new();
        let dir = temp_dir();
        let proxy = NetProxy::start(NetAllowlist::new(vec![])).expect("start proxy");
        let expected_url = proxy.proxy_url();

        let (mut command, _, _, _) =
            prepare_sandbox_launch(&cli, &file_policy, dir.path(), &base_policy, Some(&proxy))
                .expect("prepare launch");

        let output = command.output().expect("run env");
        let env_output = String::from_utf8_lossy(&output.stdout);
        assert!(env_output.contains(&format!("ALL_PROXY={expected_url}")), "ALL_PROXY should be set");
        assert!(env_output.contains(&format!("HTTPS_PROXY={expected_url}")), "HTTPS_PROXY should be set");
        assert!(env_output.contains(&format!("HTTP_PROXY={expected_url}")), "HTTP_PROXY should be set");
        assert!(env_output.contains(&format!("https_proxy={expected_url}")), "https_proxy should be set");
        assert!(env_output.contains(&format!("http_proxy={expected_url}")), "http_proxy should be set");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_sandbox_launch_env_remove_strips_inherited_vars() {
        // env_remove must strip env vars inherited from the parent process.
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("SHADI_TEST_SENTINEL_9f3a", "sentinel-value");

        let mut cli = build_cli();
        cli.run_command = vec!["/usr/bin/env".to_string()];
        let file_policy = PolicyFile {
            env_remove: vec!["SHADI_TEST_SENTINEL_9f3a".to_string()],
            ..PolicyFile::default()
        };
        let base_policy = SandboxPolicy::new();
        let dir = temp_dir();

        let (mut command, _, _, _) =
            prepare_sandbox_launch(&cli, &file_policy, dir.path(), &base_policy, None)
                .expect("prepare launch");

        let output = command.output().expect("run env");
        std::env::remove_var("SHADI_TEST_SENTINEL_9f3a");
        let env_output = String::from_utf8_lossy(&output.stdout);
        assert!(
            !env_output.contains("SHADI_TEST_SENTINEL_9f3a"),
            "env_remove should strip the sentinel var from the child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_sandbox_launch_env_remove_strips_proxy_vars_while_keeping_all_proxy() {
        // Core use-case: copilot-cli.json removes HTTPS_PROXY/HTTP_PROXY to avoid
        // crashing Node.js SEA runtimes that don't support socks5h:// in those
        // vars, while keeping ALL_PROXY for SOCKS5 enforcement.
        let mut cli = build_cli();
        cli.run_command = vec!["/usr/bin/env".to_string()];
        let file_policy = PolicyFile {
            env_remove: vec![
                "HTTPS_PROXY".to_string(),
                "HTTP_PROXY".to_string(),
                "https_proxy".to_string(),
                "http_proxy".to_string(),
            ],
            ..PolicyFile::default()
        };
        let base_policy = SandboxPolicy::new();
        let dir = temp_dir();
        let proxy = NetProxy::start(NetAllowlist::new(vec![])).expect("start proxy");
        let expected_url = proxy.proxy_url();

        let (mut command, _, _, _) =
            prepare_sandbox_launch(&cli, &file_policy, dir.path(), &base_policy, Some(&proxy))
                .expect("prepare launch");

        let output = command.output().expect("run env");
        let env_output = String::from_utf8_lossy(&output.stdout);
        assert!(env_output.contains(&format!("ALL_PROXY={expected_url}")), "ALL_PROXY must remain for SOCKS5 enforcement");
        assert!(env_output.contains(&format!("all_proxy={expected_url}")), "all_proxy must remain");
        assert!(!env_output.contains("HTTPS_PROXY="), "HTTPS_PROXY must be stripped");
        assert!(!env_output.contains("HTTP_PROXY="), "HTTP_PROXY must be stripped");
        assert!(!env_output.contains("https_proxy="), "https_proxy must be stripped");
        assert!(!env_output.contains("http_proxy="), "http_proxy must be stripped");
    }

    #[test]
    fn given_slim_channel_when_resolving_internal_bridge_then_group_join_is_selected() {
        let mut cli = build_cli();
        cli.slim_channel = Some("agntcy/shadi/secops-room".to_string());
        cli.slim_timeout = Some(0);
        cli.slim_payload_type = Some("text/plain".to_string());
        cli.slim_allow_empty = true;

        let bridge = resolve_internal_slim_bridge_args(&cli)
            .expect("resolve bridge")
            .expect("bridge args");

        match bridge.bootstrap {
            NativeSlimBootstrap::GroupJoin { channel, timeout } => {
                assert_eq!(channel, "agntcy/shadi/secops-room");
                assert_eq!(timeout, None);
            }
            other => panic!("unexpected bootstrap: {:?}", other),
        }
        assert_eq!(bridge.payload_type.as_deref(), Some("text/plain"));
        assert!(bridge.allow_empty);
    }

    #[test]
    fn given_slim_destination_when_resolving_internal_bridge_then_point_to_point_is_selected() {
        let mut cli = build_cli();
        cli.slim_destination = Some("agntcy/shadi/secops-a".to_string());
        cli.slim_payload_type = Some("application/json".to_string());

        let bridge = resolve_internal_slim_bridge_args(&cli)
            .expect("resolve bridge")
            .expect("bridge args");

        match bridge.bootstrap {
            NativeSlimBootstrap::PointToPoint { destination } => {
                assert_eq!(destination, "agntcy/shadi/secops-a");
            }
            other => panic!("unexpected bootstrap: {:?}", other),
        }
        assert_eq!(bridge.payload_type.as_deref(), Some("application/json"));
        assert!(!bridge.allow_empty);
    }

    #[test]
    fn given_slim_timeout_without_channel_when_resolving_internal_bridge_then_it_is_rejected() {
        let mut cli = build_cli();
        cli.slim_timeout = Some(5);

        let err = resolve_internal_slim_bridge_args(&cli).expect_err("timeout rejected");
        assert!(err.contains("--slim-timeout requires --slim-channel"));
    }

    #[test]
    fn given_slim_payload_without_target_when_resolving_internal_bridge_then_it_is_rejected() {
        let mut cli = build_cli();
        cli.slim_payload_type = Some("text/plain".to_string());

        let err = resolve_internal_slim_bridge_args(&cli).expect_err("payload rejected");

        assert!(err.contains("--slim-payload-type requires --slim-channel or --slim-destination"));
    }

    #[test]
    fn given_slim_allow_empty_without_target_when_resolving_internal_bridge_then_it_is_rejected() {
        let mut cli = build_cli();
        cli.slim_allow_empty = true;

        let err = resolve_internal_slim_bridge_args(&cli).expect_err("allow-empty rejected");

        assert!(err.contains("--slim-allow-empty requires --slim-channel or --slim-destination"));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_sandbox_launch_with_internal_slim_bridge_pipes_child_stdio() {
        let mut cli = build_cli();
        cli.run_command = vec!["/bin/cat".to_string()];
        cli.slim_destination = Some("agntcy/shadi/secops-a".to_string());
        let file_policy = PolicyFile::default();
        let base_policy = SandboxPolicy::new();
        let dir = temp_dir();

        let (mut command, _pending, _runtime_policy, bridge) =
            prepare_sandbox_launch(&cli, &file_policy, dir.path(), &base_policy, None)
                .expect("prepare launch");
        let mut child = command.spawn().expect("spawn cat");

        assert!(bridge.is_some());
        assert!(child.stdin.take().is_some(), "internal bridge requires piped stdin");
        assert!(child.stdout.take().is_some(), "internal bridge requires piped stdout");

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn run_sandboxed_command_returns_error_when_internal_slim_bridge_cannot_start() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let cwd_root = temp_dir();
        let cwd = cwd_root.path().canonicalize().expect("canonical cwd");
        let tmp_root = temp_dir();
        let previous_tmp_dir = std::env::var_os("SHADI_TMP_DIR");
        let previous_endpoint = std::env::var_os("SLIM_ENDPOINT");
        let previous_secret = std::env::var_os("SLIM_SHARED_SECRET");
        let previous_cert = std::env::var_os("SLIM_TLS_CERT");
        let previous_key = std::env::var_os("SLIM_TLS_KEY");
        let previous_ca = std::env::var_os("SLIM_TLS_CA");

        std::env::set_var("SHADI_TMP_DIR", tmp_root.path());
        std::env::set_var("SLIM_ENDPOINT", "127.0.0.1:65535");
        std::env::set_var("SLIM_SHARED_SECRET", "my_shared_secret_for_testing_purposes_only");
        std::env::remove_var("SLIM_TLS_CERT");
        std::env::remove_var("SLIM_TLS_KEY");
        std::env::remove_var("SLIM_TLS_CA");

        let mut cli = build_cli();
        cli.run_command = vec!["/bin/cat".to_string()];
        cli.allow.push(PathBuf::from("/bin"));
        cli.slim_destination = Some("agntcy/shadi/secops-a".to_string());

        let file_policy = PolicyFile::default();
        let resolved = resolve_policy(&cli, &file_policy).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &file_policy, &cwd);

        match previous_tmp_dir {
            Some(value) => std::env::set_var("SHADI_TMP_DIR", value),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }
        match previous_endpoint {
            Some(value) => std::env::set_var("SLIM_ENDPOINT", value),
            None => std::env::remove_var("SLIM_ENDPOINT"),
        }
        match previous_secret {
            Some(value) => std::env::set_var("SLIM_SHARED_SECRET", value),
            None => std::env::remove_var("SLIM_SHARED_SECRET"),
        }
        match previous_cert {
            Some(value) => std::env::set_var("SLIM_TLS_CERT", value),
            None => std::env::remove_var("SLIM_TLS_CERT"),
        }
        match previous_key {
            Some(value) => std::env::set_var("SLIM_TLS_KEY", value),
            None => std::env::remove_var("SLIM_TLS_KEY"),
        }
        match previous_ca {
            Some(value) => std::env::set_var("SLIM_TLS_CA", value),
            None => std::env::remove_var("SLIM_TLS_CA"),
        }

        assert_eq!(exit, ExitCode::from(1));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn run_sandboxed_command_with_internal_slim_bridge_forwards_child_stdout() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let cwd_root = temp_dir();
        let cwd = cwd_root.path().canonicalize().expect("canonical cwd");
        let tls_root = temp_dir();
        let tls_dir = generate_test_tls_dir(tls_root.path());
        let endpoint = reserve_test_endpoint();
        let server_tls = test_server_tls_material(&tls_dir);
        let participant_tls = test_client_tls_material(&tls_dir, "secops-a");
        let previous_tmp_dir = std::env::var_os("SHADI_TMP_DIR");
        let previous_endpoint = std::env::var_os("SLIM_ENDPOINT");
        let previous_secret = std::env::var_os("SLIM_SHARED_SECRET");
        let previous_agent_id = std::env::var_os("SHADI_AGENT_ID");
        let previous_cert = std::env::var_os("SLIM_TLS_CERT");
        let previous_key = std::env::var_os("SLIM_TLS_KEY");
        let previous_ca = std::env::var_os("SLIM_TLS_CA");

        let node_service = slim_bindings::Service::new(format!(
            "sandbox-snapshot-test-node-{}",
            std::process::id()
        ));
        node_service
            .run_server(build_test_server_config(&endpoint, &server_tls))
            .expect("start local SLIM node");
        std::thread::sleep(std::time::Duration::from_millis(250));

        let (ready_tx, ready_rx) = mpsc::channel();
        let endpoint_for_participant = endpoint.clone();
        let participant_handle = std::thread::spawn(move || -> Result<Vec<u8>, String> {
            let participant_service = slim_bindings::Service::new(format!(
                "sandbox-snapshot-test-participant-{}",
                std::process::id()
            ));
            let participant_name = slim_bindings::Name::from_string(
                "agntcy/shadi/secops-a".to_string(),
            )
            .map_err(format_slim_error)?;
            let connection_id = participant_service
                .connect(build_test_client_config(&endpoint_for_participant, &participant_tls))
                .map_err(format_slim_error)?;
            let participant_app = participant_service
                .create_app_with_secret(Arc::new(participant_name.clone()), TEST_SHARED_SECRET.to_string())
                .map_err(format_slim_error)?;

            participant_app
                .subscribe(Arc::new(participant_name), Some(connection_id))
                .map_err(format_slim_error)?;
            std::thread::sleep(std::time::Duration::from_millis(200));
            ready_tx.send(()).map_err(|err| err.to_string())?;

            let session = participant_app
                .listen_for_session(Some(std::time::Duration::from_secs(20)))
                .map_err(format_slim_error)?;
            let payload = session
                .get_message(Some(std::time::Duration::from_secs(20)))
                .map_err(format_slim_error)?
                .payload;

            let _ = participant_app.delete_session_and_wait(session);
            participant_service
                .disconnect(connection_id)
                .map_err(format_slim_error)?;
            participant_service.shutdown().map_err(format_slim_error)?;
            Ok(payload)
        });

        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("participant ready");

        std::env::set_var("SHADI_TMP_DIR", tls_root.path());
        std::env::set_var("SLIM_ENDPOINT", &endpoint);
        std::env::set_var("SLIM_SHARED_SECRET", TEST_SHARED_SECRET);
        std::env::set_var("SHADI_AGENT_ID", "avatar");
        std::env::remove_var("SLIM_TLS_CERT");
        std::env::remove_var("SLIM_TLS_KEY");
        std::env::remove_var("SLIM_TLS_CA");

        let mut cli = build_cli();
        cli.run_command = vec!["/bin/echo".to_string(), "hello".to_string()];
        cli.allow.push(PathBuf::from("/bin"));
        cli.slim_destination = Some("agntcy/shadi/secops-a".to_string());

        let file_policy = PolicyFile::default();
        let resolved = resolve_policy(&cli, &file_policy).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &file_policy, &cwd);

        match previous_tmp_dir {
            Some(value) => std::env::set_var("SHADI_TMP_DIR", value),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }
        match previous_endpoint {
            Some(value) => std::env::set_var("SLIM_ENDPOINT", value),
            None => std::env::remove_var("SLIM_ENDPOINT"),
        }
        match previous_secret {
            Some(value) => std::env::set_var("SLIM_SHARED_SECRET", value),
            None => std::env::remove_var("SLIM_SHARED_SECRET"),
        }
        match previous_agent_id {
            Some(value) => std::env::set_var("SHADI_AGENT_ID", value),
            None => std::env::remove_var("SHADI_AGENT_ID"),
        }
        match previous_cert {
            Some(value) => std::env::set_var("SLIM_TLS_CERT", value),
            None => std::env::remove_var("SLIM_TLS_CERT"),
        }
        match previous_key {
            Some(value) => std::env::set_var("SLIM_TLS_KEY", value),
            None => std::env::remove_var("SLIM_TLS_KEY"),
        }
        match previous_ca {
            Some(value) => std::env::set_var("SLIM_TLS_CA", value),
            None => std::env::remove_var("SLIM_TLS_CA"),
        }

        let payload = participant_handle
            .join()
            .expect("participant thread panicked")
            .expect("participant payload");

        node_service
            .stop_server(endpoint.clone())
            .expect("stop node server");
        node_service.shutdown().expect("shutdown node service");

        assert_eq!(exit, ExitCode::from(0));
        assert_eq!(payload, b"hello".to_vec());
    }

    fn run_git(cwd: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(args)
            .output()
            .expect("run git");
        if !output.status.success() {
            panic!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn init_git_repo() -> TempDir {
        let dir = temp_dir();
        run_git(dir.path(), &["init"]);
        run_git(dir.path(), &["config", "user.name", "SHADI Tests"]);
        run_git(dir.path(), &["config", "user.email", "shadi-tests@example.com"]);
        run_git(dir.path(), &["config", "commit.gpgsign", "false"]);
        dir
    }

    fn seed_git_repo(repo_path: &Path) {
        let tracked = repo_path.join("tracked.txt");
        std::fs::write(&tracked, "initial\n").expect("write tracked file");
        run_git(repo_path, &["add", "tracked.txt"]);
        run_git(repo_path, &["commit", "-m", "initial"]);
    }

    fn init_nested_git_repo(parent: &Path, name: &str) -> PathBuf {
        let repo_path = parent.join(name);
        std::fs::create_dir_all(&repo_path).expect("create nested repo dir");
        run_git(&repo_path, &["init"]);
        run_git(&repo_path, &["config", "user.name", "SHADI Tests"]);
        run_git(&repo_path, &["config", "user.email", "shadi-tests@example.com"]);
        run_git(&repo_path, &["config", "commit.gpgsign", "false"]);
        repo_path
    }

    fn sample_git_repo_state(untracked_inventory: Option<Vec<String>>) -> GitRepoState {
        let head = Some("head-sha".to_string());
        let status_porcelain = vec![" M tracked.txt".to_string()];
        let diff_binary = "diff --git a/tracked.txt b/tracked.txt".to_string();
        let hashes = build_git_repo_state_hashes(
            head.as_deref(),
            &status_porcelain,
            &diff_binary,
            untracked_inventory.as_deref(),
        );

        GitRepoState {
            head,
            status_porcelain,
            diff_binary,
            untracked_inventory,
            hashes,
        }
    }

    #[test]
    fn git_snapshot_record_sync_primary_repository_fields_clears_without_repositories() {
        let mut record = GitSnapshotRecord {
            detected: true,
            changed_repositories: 1,
            any_repo_changed: true,
            repo_root: Some("root".to_string()),
            include_untracked_inventory: false,
            before: Some(sample_git_repo_state(None)),
            after: Some(sample_git_repo_state(Some(vec!["scratch.txt".to_string()]))),
            diff_summary: Some(GitDiffSummary {
                changed: true,
                ..GitDiffSummary::default()
            }),
            comparison: Some(GitStateComparison {
                before_state_sha256: Some("a".repeat(64)),
                after_state_sha256: Some("b".repeat(64)),
                head_changed: true,
                status_changed: true,
                diff_changed: true,
                untracked_changed: Some(true),
                overall_changed: true,
            }),
            capture_error: Some("stale".to_string()),
            repositories: Vec::new(),
        };

        record.sync_primary_repository_fields();

        assert!(record.repo_root.is_none());
        assert!(record.before.is_none());
        assert!(record.after.is_none());
        assert!(record.diff_summary.is_none());
        assert!(record.comparison.is_none());
        assert!(record.capture_error.is_none());
    }

    #[test]
    fn default_git_snapshot_dir_falls_back_without_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let previous = std::env::var_os("SHADI_TMP_DIR");
        std::env::remove_var("SHADI_TMP_DIR");

        let path = default_git_snapshot_dir();

        match previous {
            Some(value) => std::env::set_var("SHADI_TMP_DIR", value),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }

        assert_eq!(path, PathBuf::from("./.tmp").join("git-snapshots"));
    }

    #[test]
    fn build_snapshot_artifact_id_uses_command_fallback_when_name_is_empty() {
        let artifact_id = build_snapshot_artifact_id(&["!!!".to_string()], 42);
        assert!(artifact_id.ends_with("-command"));
    }

    #[test]
    fn capture_git_snapshot_reports_no_repo_outside_git() {
        let dir = temp_dir();
        let record = capture_git_snapshot(dir.path(), true);

        assert!(!record.detected);
        assert_eq!(record.changed_repositories, 0);
        assert!(!record.any_repo_changed);
        assert!(record.repo_root.is_none());
        assert!(record.before.is_none());
        assert!(record.after.is_none());
        assert!(record.diff_summary.is_none());
        assert!(record.comparison.is_none());
        assert!(record.capture_error.is_none());
        assert!(record.repositories.is_empty());
        assert!(record.include_untracked_inventory);
    }

    #[test]
    fn capture_git_repository_snapshot_records_missing_repo_error() {
        let dir = temp_dir();
        let missing_repo = dir.path().join("missing-repo");

        let repository = capture_git_repository_snapshot(dir.path(), &missing_repo, false);

        assert_eq!(repository.repo_root, missing_repo.display().to_string());
        assert!(repository.before.is_none());
        assert!(repository.after.is_none());
        assert!(repository.diff_summary.is_none());
        assert!(repository.comparison.is_none());
        assert!(repository.capture_error.as_deref().unwrap_or_default().contains("git status"));
    }

    #[test]
    fn repo_relative_path_handles_parent_and_unrelated_roots() {
        let dir = temp_dir();
        let cwd = dir.path().join("workspace").join("repo");
        let unrelated = dir.path().join("external-repo");
        std::fs::create_dir_all(&cwd).expect("create cwd");
        std::fs::create_dir_all(&unrelated).expect("create unrelated dir");

        assert_eq!(repo_relative_path(&cwd, dir.path()), ".");
        assert_eq!(repo_relative_path(&cwd, &unrelated), unrelated.display().to_string());
    }

    #[test]
    fn canonicalize_or_clone_returns_missing_path_unchanged() {
        let dir = temp_dir();
        let missing = dir.path().join("does-not-exist");
        assert_eq!(canonicalize_or_clone(&missing), missing);
    }

    #[test]
    fn detect_git_repo_root_returns_none_outside_git() {
        let dir = temp_dir();
        assert!(detect_git_repo_root(dir.path()).expect("detect git root").is_none());
    }

    #[test]
    fn run_git_capture_reports_git_failures() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        let err = run_git_capture(&repo_path, &["definitely-not-a-real-git-subcommand"]).unwrap_err();
        assert!(err.contains("git definitely-not-a-real-git-subcommand failed"));
    }

    #[test]
    fn run_git_capture_optional_returns_none_on_git_failures() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        let output = run_git_capture_optional(&repo_path, &["show-ref", "--verify", "refs/heads/does-not-exist"])
            .expect("optional git output");
        assert!(output.is_none());
    }

    #[test]
    fn build_git_state_comparison_marks_untracked_presence_change() {
        let before = sample_git_repo_state(None);
        let after = sample_git_repo_state(Some(vec!["scratch.txt".to_string()]));

        let comparison = build_git_state_comparison(Some(&before), Some(&after)).expect("comparison");
        assert_eq!(comparison.untracked_changed, Some(true));
    }

    #[test]
    fn git_snapshot_session_records_after_capture_error_when_nested_repo_disappears() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let nested_repo = init_nested_git_repo(&repo_path, "nested-missing-after-start");
        std::fs::write(nested_repo.join("nested.txt"), "initial\n").expect("write nested file");
        run_git(&nested_repo, &["add", "nested.txt"]);
        run_git(&nested_repo, &["commit", "-m", "initial"]);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        cli.run_command = vec!["portable-test".to_string()];
        cli.git_snapshot = true;
        cli.git_snapshot_dir = Some(snapshot_dir);

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let mut session = GitSnapshotSession::start(&cli, &resolved, &repo_path).expect("start snapshot");

        std::fs::remove_dir_all(&nested_repo).expect("remove nested repo");

        let artifact_path = session.finish(Some(0), None).expect("finish snapshot");
        let payload = std::fs::read_to_string(&artifact_path).expect("read artifact");
        let artifact: Value = serde_json::from_str(&payload).expect("parse artifact");

        let repositories = artifact["git"]["repositories"]
            .as_array()
            .expect("repository array");
        let nested = repositories
            .iter()
            .find(|repository| repository["relative_path"] == "nested-missing-after-start")
            .expect("nested repository entry");
        assert!(nested["capture_error"].as_str().expect("capture error").contains("git status"));
    }

    #[test]
    fn git_snapshot_session_reports_run_dir_creation_failure() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        cli.run_command = vec!["portable-test".to_string()];
        cli.git_snapshot = true;
        cli.git_snapshot_dir = Some(snapshot_dir.clone());

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let mut session = GitSnapshotSession::start(&cli, &resolved, &repo_path).expect("start snapshot");

        let run_dir = snapshot_dir.join("runs").join(&session.artifact.artifact_id);
        std::fs::create_dir_all(run_dir.parent().expect("runs parent")).expect("create runs parent");
        std::fs::write(&run_dir, "occupied\n").expect("block run dir with file");

        let err = session.finish(Some(0), None).unwrap_err();
        assert!(err.contains("failed to create"));
    }

    #[test]
    fn git_snapshot_session_reports_snapshot_write_failure() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        cli.run_command = vec!["portable-test".to_string()];
        cli.git_snapshot = true;
        cli.git_snapshot_dir = Some(snapshot_dir.clone());

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let mut session = GitSnapshotSession::start(&cli, &resolved, &repo_path).expect("start snapshot");

        let run_dir = snapshot_dir.join("runs").join(&session.artifact.artifact_id);
        std::fs::create_dir_all(&run_dir).expect("create run dir");
        std::fs::create_dir(run_dir.join("snapshot.json")).expect("block snapshot file with dir");

        let err = session.finish(Some(0), None).unwrap_err();
        assert!(err.contains("failed to write"));
    }

    #[test]
    fn git_snapshot_session_reports_latest_write_failure() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        cli.run_command = vec!["portable-test".to_string()];
        cli.git_snapshot = true;
        cli.git_snapshot_dir = Some(snapshot_dir.clone());

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let mut session = GitSnapshotSession::start(&cli, &resolved, &repo_path).expect("start snapshot");

        std::fs::create_dir_all(&snapshot_dir).expect("create snapshot dir");
        std::fs::create_dir(snapshot_dir.join("latest.json")).expect("block latest file with dir");

        let err = session.finish(Some(0), None).unwrap_err();
        assert!(err.contains("failed to write"));
    }

    /// Exercises the three new lines added by the dir-integration PR:
    /// `if let Some(record_ref) = cli.record_ref.as_deref() { eprintln!(...) }`
    /// inside the `watch_policy` → control-socket success path.
    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn run_sandboxed_command_prints_record_ref_with_watch_policy() {
        let cwd_root = temp_dir();
        let cwd = cwd_root.path().canonicalize().expect("canonical cwd");

        let mut cli = build_cli();
        cli.watch_policy = true;
        cli.record_ref = Some("test/agent:v1.0@bafkreitest".to_string());
        cli.run_command = vec!["/usr/bin/true".to_string()];
        cli.allow.push(std::path::PathBuf::from("/usr/bin"));
        // Unique session name to avoid socket-path collision across parallel tests.
        cli.session_name = Some(format!("shadi-test-recref-{}", std::process::id()));

        let file_policy = PolicyFile::default();
        let resolved = resolve_policy(&cli, &file_policy).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &file_policy, &cwd);

        assert_eq!(exit, ExitCode::from(0));
    }

    /// Exercises the `else` branch of `if let Some(name) = cli.session_name` (line 232),
    /// which prints the control socket path when no session name is provided.
    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn run_sandboxed_command_prints_control_socket_path_without_session_name() {
        let cwd_root = temp_dir();
        let cwd = cwd_root.path().canonicalize().expect("canonical cwd");

        let mut cli = build_cli();
        cli.watch_policy = true;
        // session_name left as None → triggers the else branch (prints socket path)
        cli.run_command = vec!["/usr/bin/true".to_string()];
        cli.allow.push(std::path::PathBuf::from("/usr/bin"));

        let file_policy = PolicyFile::default();
        let resolved = resolve_policy(&cli, &file_policy).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &file_policy, &cwd);

        assert_eq!(exit, ExitCode::from(0));
    }
}

