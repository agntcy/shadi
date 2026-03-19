use super::*;

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

    let mut command = Command::new(cmd_name);
    if cli.run_command.len() > 1 {
        command.args(&cli.run_command[1..]);
    }
    command.current_dir(cwd);
    #[cfg(test)]
    scrub_test_secret_backend_env(&mut command);

    let secret_config = match resolve_launch_secret_config(&command, cli, file_policy) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to resolve launch secret policy: {}", err);
            return ExitCode::from(2);
        }
    };

    let mut pending_trusted_secrets = match PendingTrustedSecretDelivery::new(
        &mut command,
        &secret_config.trusted_secret,
        &secret_config.trusted_secret_exec,
        &secret_config.trusted_secret_fd_env,
        &secret_config.process_secret_policy,
    ) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("failed to configure trusted secret delivery: {}", err);
            return ExitCode::from(2);
        }
    };

    let mut runtime_policy = resolved.policy.clone();
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

    if let Err(err) = inject_keychain_secrets(&mut command, &secret_config.inject_keychain) {
        eprintln!("failed to inject keychain secrets: {}", err);
        return ExitCode::from(2);
    }

    let mut snapshot = GitSnapshotSession::start(cli, resolved, cwd);
    let snapshot_enabled = snapshot.is_some();

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

    match spawn_sandboxed(&mut command, &runtime_policy) {
        Ok(mut child) => {
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

            let exit = match child.wait() {
            Ok(status) => {
                let exit_code = status.code().unwrap_or(1);
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
                ExitCode::from(status.code().unwrap_or(1) as u8)
            }
            Err(err) => {
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
                ExitCode::from(1)
            }
            };

            exit
        }
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
            ExitCode::from(1)
        }
    }
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
