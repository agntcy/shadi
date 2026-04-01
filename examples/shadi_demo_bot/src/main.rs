use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use agent_secrets::{
    AgentSecretAccess, AgentVerifier, SecretBytes, SecretError, SecretPolicy, SecretResult,
    SecretStore, SessionContext,
};
use agent_transport_slim::{NativeSlimBootstrap, NativeSlimSession, SecureAgentChannel};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use shadi_memory::SqlCipherStore;
use shadi_sandbox::{spawn_sandboxed, SandboxError, SandboxPolicy};
use slim_bindings::{
    CaSource, ClientConfig, Name, ServerConfig, Service, TlsClientConfig, TlsServerConfig,
    TlsSource,
};

const DEFAULT_TICK_SECONDS: u64 = 3;
const DEFAULT_MEMORY_KEY: &str = "shadi-demo-memory-key";
const DEFAULT_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";
const DEFAULT_BOT_AGENT_ID: &str = "avatar";
const DEFAULT_PEER_AGENT_ID: &str = "secops-a";

#[derive(Parser)]
#[command(name = "shadi-demo-bot", about = "Rust demo bot and helpers for SHADI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    FeatureBot(FeatureBotArgs),
    ShellTicker(ShellTickerArgs),
    SandboxProbe(SandboxProbeArgs),
    SlimEchoPeer(SlimEchoPeerArgs),
}

#[derive(Args, Clone)]
struct FeatureBotArgs {
    #[arg(long, env = "SHADI_TMP_DIR")]
    shadi_tmp_dir: Option<PathBuf>,

    #[arg(long, env = "SHADI_DEMO_MEMORY_DB")]
    memory_db: Option<PathBuf>,

    #[arg(long, env = "SHADI_DEMO_MEMORY_KEY", default_value = DEFAULT_MEMORY_KEY)]
    memory_key: String,

    #[arg(long, env = "SLIM_ENDPOINT")]
    slim_endpoint: Option<String>,

    #[arg(long, default_value = DEFAULT_BOT_AGENT_ID)]
    slim_bot_agent_id: String,

    #[arg(long, default_value = DEFAULT_PEER_AGENT_ID)]
    slim_peer_agent_id: String,

    #[arg(long)]
    slim_destination: Option<String>,

    #[arg(long, default_value = DEFAULT_SHARED_SECRET)]
        slim_shared_secret: String,

    #[arg(long, default_value_t = 20)]
    slim_timeout_seconds: u64,

    #[arg(long, default_value_t = false)]
    no_slim: bool,
}

impl Default for FeatureBotArgs {
    fn default() -> Self {
        Self {
            shadi_tmp_dir: None,
            memory_db: None,
            memory_key: DEFAULT_MEMORY_KEY.to_string(),
            slim_endpoint: None,
            slim_bot_agent_id: DEFAULT_BOT_AGENT_ID.to_string(),
            slim_peer_agent_id: DEFAULT_PEER_AGENT_ID.to_string(),
            slim_destination: None,
            slim_shared_secret: DEFAULT_SHARED_SECRET.to_string(),
            slim_timeout_seconds: 20,
            no_slim: false,
        }
    }
}

#[derive(Args)]
struct ShellTickerArgs {
    #[arg(long, env = "DEMO_TICK", default_value_t = DEFAULT_TICK_SECONDS)]
    tick_seconds: u64,
}

#[derive(Args)]
struct SandboxProbeArgs {
    #[arg(long)]
    allowed_read: PathBuf,

    #[arg(long)]
    allowed_write: PathBuf,

    #[arg(long)]
    blocked_read: PathBuf,

    #[arg(long)]
    network_host: String,

    #[arg(long)]
    network_port: u16,
}

#[derive(Args)]
struct SlimEchoPeerArgs {
    #[arg(long, env = "SHADI_TMP_DIR")]
    shadi_tmp_dir: Option<PathBuf>,

    #[arg(long)]
    endpoint: String,

    #[arg(long, default_value = DEFAULT_PEER_AGENT_ID)]
    agent_id: String,

    #[arg(long, default_value = DEFAULT_SHARED_SECRET)]
    shared_secret: String,

    #[arg(long, default_value_t = 20)]
    listen_timeout_seconds: u64,

    #[arg(long)]
    ready_file: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    start_local_node: bool,
}

#[derive(Default)]
struct InMemorySecretStore {
    entries: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecretStore for InMemorySecretStore {
    fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
        let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
        guard.insert(key.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
        let value = guard.get(key).ok_or(SecretError::InvalidInput)?.clone();
        Ok(SecretBytes::new(value))
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
        guard.remove(key);
        Ok(())
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
        Ok(guard.keys().cloned().collect())
    }
}

struct VerifiedSessionVerifier;

impl AgentVerifier for VerifiedSessionVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        AgentSecretAccess::require_verified(session)
    }
}

struct ScopedEnvVar {
    name: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnvVar {
    fn set(name: &'static str, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }

    fn unset(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::remove_var(name);
        Self { name, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DemoStatus {
    Pass,
    Fail,
    Skip,
}

impl DemoStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

struct DemoCheck {
    name: String,
    status: DemoStatus,
    detail: String,
}

#[derive(Default)]
struct DemoReport {
    checks: Vec<DemoCheck>,
}

impl DemoReport {
    fn push(&mut self, status: DemoStatus, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(DemoCheck {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }

    fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| matches!(check.status, DemoStatus::Fail))
    }

    fn print(&self) {
        println!("[shadi-demo-bot] feature report");
        for check in &self.checks {
            println!(
                "[{}] {}: {}",
                check.status.label(),
                check.name,
                check.detail
            );
        }

        let passed = self
            .checks
            .iter()
            .filter(|check| matches!(check.status, DemoStatus::Pass))
            .count();
        let skipped = self
            .checks
            .iter()
            .filter(|check| matches!(check.status, DemoStatus::Skip))
            .count();
        let failed = self
            .checks
            .iter()
            .filter(|check| matches!(check.status, DemoStatus::Fail))
            .count();

        println!(
            "[shadi-demo-bot] summary: {} passed, {} skipped, {} failed",
            passed, skipped, failed
        );
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProbeAttempt {
    success: bool,
    detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxProbeResult {
    allowed_read: ProbeAttempt,
    allowed_write: ProbeAttempt,
    blocked_read: ProbeAttempt,
    network_connect: ProbeAttempt,
}

#[derive(Clone)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Commands::FeatureBot(args)) => run_feature_bot(args),
        Some(Commands::ShellTicker(args)) => run_shell_ticker(args),
        Some(Commands::SandboxProbe(args)) => run_sandbox_probe(args),
        Some(Commands::SlimEchoPeer(args)) => run_slim_echo_peer(args),
        None => run_feature_bot(FeatureBotArgs::default()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {}", err);
            ExitCode::from(1)
        }
    }
}

fn run_feature_bot(args: FeatureBotArgs) -> Result<(), String> {
    let repo_root = repo_root()?;
    let tmp_dir = resolve_tmp_dir(args.shadi_tmp_dir.as_deref(), &repo_root)?;
    let memory_db = args
        .memory_db
        .unwrap_or_else(|| tmp_dir.join("shadi-demo-memory.db"));
    let current_exe = std::env::current_exe()
        .map_err(|err| format!("failed to locate current executable: {}", err))?;
    let slim_endpoint = match args.slim_endpoint {
        Some(endpoint) => endpoint,
        None => reserve_local_endpoint()?,
    };
    let slim_destination = args
        .slim_destination
        .unwrap_or_else(|| canonical_name(&args.slim_peer_agent_id));

    let mut report = DemoReport::default();
    run_secret_checks(&mut report);
    run_memory_checks(&mut report, &memory_db, &args.memory_key);
    run_sandbox_checks(&mut report, &current_exe, &repo_root, &tmp_dir);
    run_slim_checks(
        &mut report,
        &current_exe,
        &tmp_dir,
        &slim_endpoint,
        &args.slim_bot_agent_id,
        &args.slim_peer_agent_id,
        &slim_destination,
        &args.slim_shared_secret,
        args.slim_timeout_seconds,
        args.no_slim,
    );

    report.print();
    if report.has_failures() {
        return Err("one or more SHADI feature checks failed".to_string());
    }
    Ok(())
}

fn run_secret_checks(report: &mut DemoReport) {
    let store = InMemorySecretStore::default();
    let verifier = VerifiedSessionVerifier;
    let access = AgentSecretAccess::new(&store, &verifier);

    let unverified = SessionContext::new("demo-bot", "unverified-session");
    match access.put_for_session(
        &unverified,
        "demo/api-token",
        b"demo-token",
        SecretPolicy::default(),
    ) {
        Err(SecretError::NotAuthorized) => report.push(
            DemoStatus::Pass,
            "session-gated secrets",
            "unverified session was rejected before secret access",
        ),
        Err(err) => report.push(
            DemoStatus::Fail,
            "session-gated secrets",
            format!("unexpected verifier error: {}", err),
        ),
        Ok(()) => report.push(
            DemoStatus::Fail,
            "session-gated secrets",
            "unverified session unexpectedly wrote a secret",
        ),
    }

    let mut verified = SessionContext::new("demo-bot", "verified-session");
    verified.verified = true;

    let outcome = (|| -> Result<String, String> {
        access
            .put_for_session(
                &verified,
                "demo/api-token",
                b"demo-token",
                SecretPolicy {
                    allow_export: false,
                    max_uses: Some(1),
                    ttl_seconds: Some(60),
                },
            )
            .map_err(secret_err_to_string)?;

        let secret = access
            .get_for_session(&verified, "demo/api-token")
            .map_err(secret_err_to_string)?;
        let value = secret.expose(|bytes| String::from_utf8_lossy(bytes).to_string());

        let mut keys = store.list_keys().map_err(secret_err_to_string)?;
        keys.sort();

        access
            .delete_for_session(&verified, "demo/api-token")
            .map_err(secret_err_to_string)?;
        let remaining = store.list_keys().map_err(secret_err_to_string)?;

        if value != "demo-token" {
            return Err(format!("unexpected secret payload: {}", value));
        }
        if keys != vec!["demo/api-token".to_string()] {
            return Err(format!("unexpected key listing: {:?}", keys));
        }
        if !remaining.is_empty() {
            return Err(format!("secret delete left keys behind: {:?}", remaining));
        }

        Ok("verified session stored, read, listed, and deleted a demo secret".to_string())
    })();

    match outcome {
        Ok(detail) => report.push(DemoStatus::Pass, "secret store round-trip", detail),
        Err(err) => report.push(DemoStatus::Fail, "secret store round-trip", err),
    }
}

fn run_memory_checks(report: &mut DemoReport, memory_db: &Path, memory_key: &str) {
    let outcome = (|| -> Result<String, String> {
        if let Some(parent) = memory_db.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {}", parent.display(), err))?;
        }
        if memory_db.exists() {
            fs::remove_file(memory_db)
                .map_err(|err| format!("failed to reset {}: {}", memory_db.display(), err))?;
        }

        let store = SqlCipherStore::open(memory_db, memory_key)
            .map_err(|err| format!("failed to open SQLCipher store: {}", err))?;
        store
            .put("demo-bot", "status", "all systems nominal")
            .map_err(|err| format!("put failed: {}", err))?;

        let latest = store
            .get_latest("demo-bot", "status")
            .map_err(|err| format!("get_latest failed: {}", err))?
            .ok_or_else(|| "memory entry was not found after put".to_string())?;
        let search = store
            .search(Some("demo-bot"), "systems", 10)
            .map_err(|err| format!("search failed: {}", err))?;
        let list = store
            .list(Some("demo-bot"), 10)
            .map_err(|err| format!("list failed: {}", err))?;
        let deleted = store
            .delete("demo-bot", "status")
            .map_err(|err| format!("delete failed: {}", err))?;

        if latest.payload != "all systems nominal" {
            return Err(format!("unexpected latest payload: {}", latest.payload));
        }
        if search.len() != 1 || search[0].entry_key != "status" {
            return Err(format!("unexpected search results: {:?}", search));
        }
        if list.is_empty() || list[0].entry_key != "status" {
            return Err(format!("unexpected list results: {:?}", list));
        }
        if deleted != 1 {
            return Err(format!("unexpected delete count: {}", deleted));
        }

        Ok(format!(
            "opened {}, wrote one encrypted entry, queried it, and deleted it",
            memory_db.display()
        ))
    })();

    match outcome {
        Ok(detail) => report.push(DemoStatus::Pass, "encrypted memory", detail),
        Err(err) => report.push(DemoStatus::Fail, "encrypted memory", err),
    }
}

fn run_sandbox_checks(
    report: &mut DemoReport,
    current_exe: &Path,
    repo_root: &Path,
    tmp_dir: &Path,
) {
    let allowed_read = repo_root.join("README.md");
    let allowed_write = tmp_dir.join("sandbox-probe-output.txt");
    let blocked_read = blocked_probe_path();
    let _ = fs::remove_file(&allowed_write);

    let outcome = (|| -> Result<SandboxProbeResult, String> {
        let mut command = Command::new(current_exe);
        command
            .arg("sandbox-probe")
            .arg("--allowed-read")
            .arg(&allowed_read)
            .arg("--allowed-write")
            .arg(&allowed_write)
            .arg("--blocked-read")
            .arg(&blocked_read)
            .arg("--network-host")
            .arg("1.1.1.1")
            .arg("--network-port")
            .arg("80")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let policy = demo_sandbox_policy(repo_root, tmp_dir);
        let mut child = match spawn_sandboxed(&mut command, &policy) {
            Ok(child) => child,
            Err(SandboxError::NotSupported) => {
                return Err("sandboxing is not supported on this platform".to_string())
            }
            Err(err) => return Err(format!("failed to spawn sandbox probe: {}", err)),
        };

        let stdout = read_optional_stream(child.take_stdout())?;
        let stderr = read_optional_stream(child.take_stderr())?;
        let status = child
            .wait()
            .map_err(|err| format!("failed to wait for sandbox probe: {}", err))?;

        if !status.success() {
            return Err(format!(
                "sandbox probe exited with {} and stderr: {}",
                status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }

        serde_json::from_str(stdout.trim()).map_err(|err| {
            format!(
                "failed to parse sandbox probe output: {} (stdout: {} stderr: {})",
                err,
                stdout.trim(),
                stderr.trim()
            )
        })
    })();

    match outcome {
        Ok(result) => {
            let allowed_detail = format!(
                "read={} write={} ({})",
                result.allowed_read.success,
                result.allowed_write.success,
                result.allowed_write.detail
            );
            if result.allowed_read.success && result.allowed_write.success {
                report.push(DemoStatus::Pass, "sandbox allowed paths", allowed_detail);
            } else {
                report.push(DemoStatus::Fail, "sandbox allowed paths", allowed_detail);
            }

            if result.blocked_read.success {
                report.push(
                    DemoStatus::Fail,
                    "sandbox blocked read",
                    format!("blocked path unexpectedly succeeded: {}", result.blocked_read.detail),
                );
            } else {
                report.push(
                    DemoStatus::Pass,
                    "sandbox blocked read",
                    result.blocked_read.detail,
                );
            }

            if result.network_connect.success {
                report.push(
                    DemoStatus::Fail,
                    "sandbox blocked network",
                    format!("network connect unexpectedly succeeded: {}", result.network_connect.detail),
                );
            } else {
                report.push(
                    DemoStatus::Pass,
                    "sandbox blocked network",
                    result.network_connect.detail,
                );
            }
        }
        Err(err) if err.contains("not supported") => {
            report.push(DemoStatus::Skip, "sandbox probe", err);
        }
        Err(err) => {
            report.push(DemoStatus::Fail, "sandbox probe", err);
        }
    }
}

fn run_slim_checks(
    report: &mut DemoReport,
    current_exe: &Path,
    tmp_dir: &Path,
    slim_endpoint: &str,
    bot_agent_id: &str,
    peer_agent_id: &str,
    destination: &str,
    shared_secret: &str,
    timeout_seconds: u64,
    no_slim: bool,
) {
    if no_slim {
        report.push(
            DemoStatus::Skip,
            "SLIM messaging",
            "skipped by --no-slim",
        );
        return;
    }

    #[cfg(windows)]
    {
        let _ = (current_exe, tmp_dir, slim_endpoint, bot_agent_id, peer_agent_id, destination, shared_secret, timeout_seconds);
        report.push(
            DemoStatus::Skip,
            "SLIM messaging",
            "local SLIM demo is currently wired for Unix/macOS assets",
        );
        return;
    }

    #[cfg(not(windows))]
    {
        let outcome = (|| -> Result<String, String> {
            ensure_slim_tls_assets(tmp_dir)?;

            let ready_file = tmp_dir.join("shadi-demo-slim-peer.ready");
            let _ = fs::remove_file(&ready_file);

            let peer = Command::new(current_exe)
                .arg("slim-echo-peer")
                .arg("--shadi-tmp-dir")
                .arg(tmp_dir)
                .arg("--endpoint")
                .arg(slim_endpoint)
                .arg("--agent-id")
                .arg(peer_agent_id)
                .arg("--shared-secret")
                .arg(shared_secret)
                .arg("--listen-timeout-seconds")
                .arg(timeout_seconds.to_string())
                .arg("--ready-file")
                .arg(&ready_file)
                .arg("--start-local-node")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|err| format!("failed to spawn SLIM peer: {}", err))?;

            wait_for_file(&ready_file, Duration::from_secs(10))?;

            let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", tmp_dir.as_os_str());
            let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", slim_endpoint);
            let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", shared_secret);
            let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", bot_agent_id);
            let _local_name = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
            let _secret_key = ScopedEnvVar::unset("SHADI_SLIM_SHARED_SECRET_KEY");
            let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
            let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
            let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

            let session = NativeSlimSession::from_env(NativeSlimBootstrap::PointToPoint {
                destination: destination.to_string(),
            })
            .map_err(|err| format!("failed to open native SLIM session: {}", err))?;

            let store = InMemorySecretStore::default();
            let verifier = VerifiedSessionVerifier;
            let channel = SecureAgentChannel::new(&session, &verifier, &store);
            let mut ctx = SessionContext::new(bot_agent_id, "slim-feature-session");
            ctx.verified = true;

            let outbound = format!("demo slim ping from {}", bot_agent_id);
            channel
                .send(&ctx, outbound.as_bytes())
                .map_err(secret_err_to_string)?;
            let reply = session
                .receive_bytes(Some(Duration::from_secs(timeout_seconds)))
                .map_err(|err| format!("failed to receive SLIM reply: {}", err))?;
            let reply_text = String::from_utf8_lossy(&reply).to_string();

            let output = wait_for_child_output(peer, Duration::from_secs(timeout_seconds + 5))?;
            if !output.status.success() {
                return Err(format!(
                    "SLIM peer exited with {} stdout={} stderr={}",
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stdout).trim(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }

            if !reply_text.contains(&outbound) {
                return Err(format!("unexpected SLIM reply: {}", reply_text));
            }

            Ok(format!(
                "sent {:?} to {} via {} and received {:?}",
                outbound,
                destination,
                session.local_name(),
                reply_text
            ))
        })();

        match outcome {
            Ok(detail) => report.push(DemoStatus::Pass, "SLIM messaging", detail),
            Err(err) => report.push(DemoStatus::Fail, "SLIM messaging", err),
        }
    }
}

fn run_shell_ticker(args: ShellTickerArgs) -> Result<(), String> {
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_handlers(&shutdown)?;

    println!("[demo-agent] starting - press Ctrl-C to stop");
    println!("[demo-agent] pid={}", std::process::id());
    println!(
        "[demo-agent] cwd={}",
        std::env::current_dir()
            .map_err(|err| format!("failed to read cwd: {}", err))?
            .display()
    );
    println!("[demo-agent] tick every {}s", args.tick_seconds);
    println!();

    let mut tick = 0_u64;
    while !shutdown.load(Ordering::SeqCst) {
        tick += 1;
        println!(
            "[demo-agent] tick {:>4}  {}",
            tick,
            clock_time_string()
        );
        let sleep_until = Instant::now() + Duration::from_secs(args.tick_seconds);
        while Instant::now() < sleep_until {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    println!();
    println!("[demo-agent] shutting down");
    Ok(())
}

fn run_sandbox_probe(args: SandboxProbeArgs) -> Result<(), String> {
    let result = SandboxProbeResult {
        allowed_read: attempt_allowed_read(&args.allowed_read),
        allowed_write: attempt_allowed_write(&args.allowed_write),
        blocked_read: attempt_blocked_read(&args.blocked_read),
        network_connect: attempt_network_connect(&args.network_host, args.network_port),
    };

    let output = serde_json::to_string(&result)
        .map_err(|err| format!("failed to serialize sandbox probe output: {}", err))?;
    println!("{}", output);
    Ok(())
}

fn run_slim_echo_peer(args: SlimEchoPeerArgs) -> Result<(), String> {
    let repo_root = repo_root()?;
    let tmp_dir = resolve_tmp_dir(args.shadi_tmp_dir.as_deref(), &repo_root)?;
    let tls_dir = ensure_slim_tls_assets(&tmp_dir)?;
    let peer_name = canonical_name(&args.agent_id);

    let server_tls = server_tls_material(&tls_dir);
    let client_tls = client_tls_material(&tls_dir, &args.agent_id)?;

    let node_service = if args.start_local_node {
        let service = Service::new(format!("shadi-demo-node-{}", std::process::id()));
        service
            .run_server(build_server_config(&args.endpoint, &server_tls))
            .map_err(format_slim_error)?;
        thread::sleep(Duration::from_millis(300));
        Some(service)
    } else {
        None
    };

    let service = Service::new(format!("shadi-demo-peer-{}", std::process::id()));
    let connection_id = service
        .connect(build_client_config(&args.endpoint, &client_tls))
        .map_err(format_slim_error)?;
    let peer_name_ref = Arc::new(parse_name(&peer_name)?);
    let app = service
        .create_app_with_secret(peer_name_ref.clone(), args.shared_secret.clone())
        .map_err(format_slim_error)?;
    app.subscribe(peer_name_ref.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    if let Some(ready_file) = &args.ready_file {
        fs::write(ready_file, b"ready")
            .map_err(|err| format!("failed to write {}: {}", ready_file.display(), err))?;
    }

    println!("[slim-peer] ready as {} on {}", peer_name, args.endpoint);
    let session = app
        .listen_for_session(Some(Duration::from_secs(args.listen_timeout_seconds)))
        .map_err(format_slim_error)?;
    let message = session
        .get_message(Some(Duration::from_secs(args.listen_timeout_seconds)))
        .map_err(format_slim_error)?;
    let payload_text = String::from_utf8_lossy(&message.payload).to_string();
    let reply = format!("echo:{}:{}", peer_name, payload_text).into_bytes();
    session
        .publish_and_wait(reply, Some("text/plain".to_string()), Some(HashMap::new()))
        .map_err(format_slim_error)?;
    let _ = app.delete_session_and_wait(session);
    let _ = app.unsubscribe(peer_name_ref, Some(connection_id));
    let _ = service.disconnect(connection_id);
    let _ = service.shutdown();

    if let Some(service) = node_service {
        let _ = service.stop_server(args.endpoint.clone());
        let _ = service.shutdown();
    }

    Ok(())
}

fn resolve_tmp_dir(candidate: Option<&Path>, repo_root: &Path) -> Result<PathBuf, String> {
    let path = candidate
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join(".tmp"));
    fs::create_dir_all(&path)
        .map_err(|err| format!("failed to create {}: {}", path.display(), err))?;
    path.canonicalize()
        .map_err(|err| format!("failed to canonicalize {}: {}", path.display(), err))
}

fn repo_root() -> Result<PathBuf, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    path.canonicalize()
        .map_err(|err| format!("failed to resolve repository root: {}", err))
}

fn blocked_probe_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/private/etc/hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

fn demo_sandbox_policy(repo_root: &Path, tmp_dir: &Path) -> SandboxPolicy {
    let mut policy = SandboxPolicy::new()
        .allow_read_path(repo_root)
        .allow_read_path(tmp_dir)
        .allow_write_path(tmp_dir)
        .block_network(true);

    for path in default_system_read_paths() {
        policy = policy.allow_read_path(path);
    }

    if cfg!(target_os = "macos") {
        policy = policy.use_minimal_platform_profile();
    }

    policy
}

fn default_system_read_paths() -> Vec<&'static str> {
    let mut paths = vec!["/usr/bin", "/usr/lib", "/bin"];
    if cfg!(target_os = "macos") {
        paths.extend(["/usr/local", "/Library", "/private/etc/ssl"]);
    }
    if cfg!(target_os = "linux") {
        paths.extend(["/lib", "/lib64", "/etc/ssl"]);
    }
    paths
}

fn attempt_allowed_read(path: &Path) -> ProbeAttempt {
    match fs::read_to_string(path) {
        Ok(content) => ProbeAttempt {
            success: true,
            detail: format!("read {} bytes from {}", content.len(), path.display()),
        },
        Err(err) => ProbeAttempt {
            success: false,
            detail: format!("failed to read {}: {}", path.display(), err),
        },
    }
}

fn attempt_allowed_write(path: &Path) -> ProbeAttempt {
    match fs::write(path, b"sandbox write ok\n") {
        Ok(()) => ProbeAttempt {
            success: true,
            detail: format!("wrote {}", path.display()),
        },
        Err(err) => ProbeAttempt {
            success: false,
            detail: format!("failed to write {}: {}", path.display(), err),
        },
    }
}

fn attempt_blocked_read(path: &Path) -> ProbeAttempt {
    match fs::read_to_string(path) {
        Ok(content) => ProbeAttempt {
            success: true,
            detail: format!("unexpectedly read {} bytes from {}", content.len(), path.display()),
        },
        Err(err) => ProbeAttempt {
            success: false,
            detail: format!("blocked reading {}: {}", path.display(), err),
        },
    }
}

fn attempt_network_connect(host: &str, port: u16) -> ProbeAttempt {
    let address = format!("{}:{}", host, port);
    match address.to_socket_addrs() {
        Ok(mut addresses) => match addresses.next() {
            Some(target) => match TcpStream::connect_timeout(&target, Duration::from_secs(2)) {
                Ok(_) => ProbeAttempt {
                    success: true,
                    detail: format!("connected to {}", target),
                },
                Err(err) => ProbeAttempt {
                    success: false,
                    detail: format!("blocked connect to {}: {}", target, err),
                },
            },
            None => ProbeAttempt {
                success: false,
                detail: format!("no socket addresses resolved for {}", address),
            },
        },
        Err(err) => ProbeAttempt {
            success: false,
            detail: format!("failed to resolve {}: {}", address, err),
        },
    }
}

fn reserve_local_endpoint() -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to reserve local port: {}", err))?;
    let endpoint = listener
        .local_addr()
        .map_err(|err| format!("failed to inspect local port: {}", err))?
        .to_string();
    drop(listener);
    Ok(endpoint)
}

fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while !path.exists() {
        if start.elapsed() > timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn wait_for_child_output(mut child: Child, timeout: Duration) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|err| format!("failed to collect child output: {}", err));
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    return Err(format!(
                        "timed out after {}s waiting for child process",
                        timeout.as_secs()
                    ));
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(format!("failed to poll child process: {}", err)),
        }
    }
}

fn read_optional_stream<T>(stream: Option<T>) -> Result<String, String>
where
    T: Read,
{
    let Some(mut stream) = stream else {
        return Ok(String::new());
    };

    let mut output = String::new();
    stream
        .read_to_string(&mut output)
        .map_err(|err| format!("failed to read child output: {}", err))?;
    Ok(output)
}

#[cfg(unix)]
fn install_shutdown_handlers(shutdown: &Arc<AtomicBool>) -> Result<(), String> {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    for signal in [SIGINT, SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(shutdown))
            .map_err(|err| format!("failed to install signal handler for {}: {}", signal, err))?;
    }
    Ok(())
}

#[cfg(windows)]
fn install_shutdown_handlers(shutdown: &Arc<AtomicBool>) -> Result<(), String> {
    let flag = Arc::clone(shutdown);
    ctrlc::set_handler(move || {
        flag.store(true, Ordering::SeqCst);
    })
    .map_err(|err| format!("failed to install Ctrl-C handler: {}", err))
}

fn clock_time_string() -> String {
    let output = Command::new("date")
        .arg("+%H:%M:%S")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());

    output.unwrap_or_else(|| "00:00:00".to_string())
}

fn canonical_name(agent_id: &str) -> String {
    format!("agntcy/shadi/{}", agent_id)
}

fn parse_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|err| format!("invalid SLIM name {}: {}", raw, err))
}

fn secret_err_to_string(err: SecretError) -> String {
    err.to_string()
}

fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

fn ensure_slim_tls_assets(tmp_dir: &Path) -> Result<PathBuf, String> {
    let tls_dir = tmp_dir.join("shadi-slim-mtls");
    let required = [
        tls_dir.join("server.crt"),
        tls_dir.join("server.key"),
        tls_dir.join("ca.crt"),
        tls_dir.join(format!("client-{}.crt", DEFAULT_BOT_AGENT_ID)),
        tls_dir.join(format!("client-{}.key", DEFAULT_BOT_AGENT_ID)),
        tls_dir.join(format!("client-{}.crt", DEFAULT_PEER_AGENT_ID)),
        tls_dir.join(format!("client-{}.key", DEFAULT_PEER_AGENT_ID)),
    ];

    if required.iter().all(|path| path.is_file()) {
        return Ok(tls_dir);
    }

    #[cfg(windows)]
    {
        return Err(format!(
            "missing SLIM TLS assets under {} and the generator script is only wired for Unix/macOS",
            tls_dir.display()
        ));
    }

    #[cfg(not(windows))]
    {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("tools")
            .join("generate_slim_mtls_certs.sh");
        let output = Command::new("bash")
            .arg(&script)
            .arg(&tls_dir)
            .output()
            .map_err(|err| format!("failed to run {}: {}", script.display(), err))?;

        if !output.status.success() {
            return Err(format!(
                "failed to generate SLIM TLS assets: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(tls_dir)
    }
}

fn client_tls_material(base_dir: &Path, agent_id: &str) -> Result<TlsMaterial, String> {
    let cert = base_dir.join(format!("client-{}.crt", agent_id));
    let key = base_dir.join(format!("client-{}.key", agent_id));
    if !cert.is_file() || !key.is_file() {
        return Err(format!(
            "missing client TLS material for {} under {}",
            agent_id,
            base_dir.display()
        ));
    }

    Ok(TlsMaterial {
        cert,
        key,
        ca: base_dir.join("ca.crt"),
    })
}

fn server_tls_material(base_dir: &Path) -> TlsMaterial {
    TlsMaterial {
        cert: base_dir.join("server.crt"),
        key: base_dir.join("server.key"),
        ca: base_dir.join("ca.crt"),
    }
}

fn build_client_config(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.endpoint = format!("https://{}", endpoint);
    config.tls = TlsClientConfig {
        insecure: false,
        insecure_skip_verify: false,
        source: TlsSource::File {
            cert: tls.cert.display().to_string(),
            key: tls.key.display().to_string(),
        },
        ca_source: CaSource::File {
            path: tls.ca.display().to_string(),
        },
        include_system_ca_certs_pool: false,
        tls_version: "tls1.3".to_string(),
    };
    config
}

fn build_server_config(endpoint: &str, tls: &TlsMaterial) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.endpoint = endpoint.to_string();
    config.tls = TlsServerConfig {
        insecure: false,
        source: TlsSource::File {
            cert: tls.cert.display().to_string(),
            key: tls.key.display().to_string(),
        },
        client_ca: CaSource::File {
            path: tls.ca.display().to_string(),
        },
        include_system_ca_certs_pool: Some(false),
        tls_version: Some("tls1.3".to_string()),
        reload_client_ca_file: Some(false),
    };
    config
}