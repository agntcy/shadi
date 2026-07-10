use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use a2a::*;
use a2a_client::A2AClient;
use a2a_server::{
    AgentExecutor, DefaultRequestHandler, InMemoryTaskStore, RequestHandler,
    ServiceParams as A2AServiceParams,
};
use agent_secrets::{
    AgentSecretAccess, AgentVerifier, SecretBytes, SecretError, SecretPolicy, SecretResult,
    SecretStore, SessionContext,
};
#[cfg(not(windows))]
use agent_transport_slim::{NativeSlimBootstrap, NativeSlimSession, SecureAgentChannel};
use async_trait::async_trait;
use clap::{Args, Parser, Subcommand};
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use shadi_a2a::{A2AChannelBuilder, SlimRpcHandler};
use shadi_memory::SqlCipherStore;
use shadi_sandbox::{spawn_sandboxed, SandboxError, SandboxPolicy};
use slim_bindings::{
    CaSource, ClientConfig, Name, Server, ServerConfig, Service, TlsClientConfig,
    TlsServerConfig, TlsSource,
};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::Notify;

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
    SlimNode(SlimNodeArgs),
    SlimEchoPeer(SlimEchoPeerArgs),
    A2AEchoPeer(A2AEchoPeerArgs),
    A2ASend(A2ASendArgs),
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

    #[arg(long, hide = true)]
    ready_file: Option<PathBuf>,
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
    result_file: Option<PathBuf>,

    #[arg(long)]
    network_host: String,

    #[arg(long)]
    network_port: u16,
}

#[derive(Args)]
struct SlimNodeArgs {
    #[arg(long, env = "SHADI_TMP_DIR")]
    shadi_tmp_dir: Option<PathBuf>,

    #[arg(long)]
    endpoint: String,

    #[arg(long, default_value_t = 21600)]
    runtime_seconds: u64,

    #[arg(long)]
    ready_file: Option<PathBuf>,
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

    #[arg(long, default_value_t = 1)]
    expected_messages: usize,

    #[arg(long)]
    ready_file: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    start_local_node: bool,
}

#[derive(Args)]
struct A2AEchoPeerArgs {
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

    #[arg(long, default_value_t = 1)]
    expected_requests: usize,

    #[arg(long)]
    ready_file: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    start_local_node: bool,
}

#[derive(Args, Clone)]
struct A2ASendArgs {
    #[arg(long, env = "SHADI_TMP_DIR")]
    shadi_tmp_dir: Option<PathBuf>,

    #[arg(long)]
    endpoint: String,

    #[arg(long, default_value = DEFAULT_BOT_AGENT_ID)]
    agent_id: String,

    #[arg(long, default_value = DEFAULT_PEER_AGENT_ID)]
    peer_agent_id: String,

    #[arg(long)]
    destination: Option<String>,

    #[arg(long, default_value = DEFAULT_SHARED_SECRET)]
    shared_secret: String,

    #[arg(long, default_value = "hello from SHADI A2A")]
    message: String,

    #[arg(long, default_value_t = false)]
    stream: bool,

    #[arg(long, default_value_t = 20)]
    timeout_seconds: u64,
}

#[derive(Default)]
struct InMemorySecretStore {
    entries: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecretStore for InMemorySecretStore {
    fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| SecretError::StorageFailure)?;
        guard.insert(key.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| SecretError::StorageFailure)?;
        let value = guard.get(key).ok_or(SecretError::InvalidInput)?.clone();
        Ok(SecretBytes::new(value))
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| SecretError::StorageFailure)?;
        guard.remove(key);
        Ok(())
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| SecretError::StorageFailure)?;
        Ok(guard.keys().cloned().collect())
    }
}

struct VerifiedSessionVerifier;

impl AgentVerifier for VerifiedSessionVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        AgentSecretAccess::require_verified(session)
    }
}

struct DemoA2AExecutor {
    agent_name: String,
}

#[async_trait]
impl AgentExecutor for DemoA2AExecutor {
    fn execute(&self, ctx: a2a_server::ExecutorContext) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let input = ctx
            .message
            .as_ref()
            .map(readable_message_text)
            .unwrap_or_else(|| "(no request message)".to_string());
        let response = Message {
            message_id: new_message_id(),
            context_id: Some(ctx.context_id.clone()),
            task_id: Some(ctx.task_id.clone()),
            role: Role::Agent,
            parts: vec![Part::text(format!("echo:{}:{}", self.agent_name, input))],
            metadata: None,
            extensions: None,
            reference_task_ids: None,
        };
        let history = ctx.message.clone().map(|message| vec![message]);

        Box::pin(futures::stream::iter(vec![
            Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            })),
            Ok(StreamResponse::Task(Task {
                id: ctx.task_id,
                context_id: ctx.context_id,
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: Some(response),
                    timestamp: None,
                },
                artifacts: None,
                history,
                metadata: None,
            })),
        ]))
    }

    fn cancel(&self, ctx: a2a_server::ExecutorContext) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        Box::pin(futures::stream::once(async move {
            Ok(StreamResponse::Task(Task {
                id: ctx.task_id,
                context_id: ctx.context_id,
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            }))
        }))
    }
}

struct DemoA2AHandler {
    inner: DefaultRequestHandler,
    card: AgentCard,
    request_seen: Arc<Notify>,
    request_count: Arc<AtomicUsize>,
}

impl DemoA2AHandler {
    fn new(
        agent_name: String,
        target: String,
        request_seen: Arc<Notify>,
        request_count: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner: DefaultRequestHandler::new(
                DemoA2AExecutor {
                    agent_name: agent_name.clone(),
                },
                InMemoryTaskStore::new(),
            ),
            card: demo_a2a_agent_card(&agent_name, &target),
            request_seen,
            request_count,
        }
    }
}

#[async_trait]
impl RequestHandler for DemoA2AHandler {
    async fn send_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        let result = self.inner.send_message(params, req).await;
        if result.is_ok() {
            self.request_count.fetch_add(1, Ordering::SeqCst);
            self.request_seen.notify_waiters();
        }
        result
    }

    async fn send_streaming_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        let result = self.inner.send_streaming_message(params, req).await;
        if result.is_ok() {
            self.request_count.fetch_add(1, Ordering::SeqCst);
            self.request_seen.notify_waiters();
        }
        result
    }

    async fn get_task(
        &self,
        params: &A2AServiceParams,
        req: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        self.inner.get_task(params, req).await
    }

    async fn list_tasks(
        &self,
        params: &A2AServiceParams,
        req: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        self.inner.list_tasks(params, req).await
    }

    async fn cancel_task(
        &self,
        params: &A2AServiceParams,
        req: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        self.inner.cancel_task(params, req).await
    }

    async fn subscribe_to_task(
        &self,
        params: &A2AServiceParams,
        req: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.inner.subscribe_to_task(params, req).await
    }

    async fn create_push_config(
        &self,
        params: &A2AServiceParams,
        req: CreateTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.inner.create_push_config(params, req).await
    }

    async fn get_push_config(
        &self,
        params: &A2AServiceParams,
        req: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.inner.get_push_config(params, req).await
    }

    async fn list_push_configs(
        &self,
        params: &A2AServiceParams,
        req: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        self.inner.list_push_configs(params, req).await
    }

    async fn delete_push_config(
        &self,
        params: &A2AServiceParams,
        req: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        self.inner.delete_push_config(params, req).await
    }

    async fn get_extended_agent_card(
        &self,
        _params: &A2AServiceParams,
        _req: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        Ok(self.card.clone())
    }
}

#[cfg(any(test, not(windows)))]
struct ScopedEnvVar {
    name: &'static str,
    previous: Option<OsString>,
}

#[cfg(any(test, not(windows)))]
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

#[cfg(any(test, not(windows)))]
impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

pub fn main_entry() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Commands::FeatureBot(args)) => run_feature_bot(args),
        Some(Commands::ShellTicker(args)) => run_shell_ticker(args),
        Some(Commands::SandboxProbe(args)) => run_sandbox_probe(args),
        Some(Commands::SlimNode(args)) => run_slim_node(args),
        Some(Commands::SlimEchoPeer(args)) => run_slim_echo_peer(args),
        Some(Commands::A2AEchoPeer(args)) => run_a2a_echo_peer(args),
        Some(Commands::A2ASend(args)) => run_a2a_send(args),
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
    if sandbox_checks_should_run_last() {
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
        run_a2a_checks(
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
        run_sandbox_checks(&mut report, &current_exe, &repo_root, &tmp_dir);
    } else {
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
        run_a2a_checks(
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
    }

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
    record_unverified_secret_access(
        report,
        access.put_for_session(
            &unverified,
            "demo/api-token",
            b"demo-token",
            SecretPolicy::default(),
        ),
    );

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

        validate_secret_roundtrip(&value, &keys, &remaining)
    })();

    record_secret_roundtrip_outcome(report, outcome);
}

fn record_unverified_secret_access(report: &mut DemoReport, outcome: SecretResult<()>) {
    match outcome {
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
}

fn validate_secret_roundtrip(
    value: &str,
    keys: &[String],
    remaining: &[String],
) -> Result<String, String> {
    if value != "demo-token" {
        return Err(format!("unexpected secret payload: {}", value));
    }

    let expected_key = ["demo/api-token".to_string()];
    if keys != expected_key {
        return Err(format!("unexpected key listing: {:?}", keys));
    }

    if !remaining.is_empty() {
        return Err(format!("secret delete left keys behind: {:?}", remaining));
    }

    Ok("verified session stored, read, listed, and deleted a demo secret".to_string())
}

fn record_secret_roundtrip_outcome(report: &mut DemoReport, outcome: Result<String, String>) {
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

        validate_memory_roundtrip(
            memory_db,
            &latest.payload,
            search.len(),
            search.first().map(|entry| entry.entry_key.as_str()),
            list.first().map(|entry| entry.entry_key.as_str()),
            deleted,
        )
    })();

    record_memory_outcome(report, outcome);
}

fn validate_memory_roundtrip(
    memory_db: &Path,
    latest_payload: &str,
    search_len: usize,
    search_key: Option<&str>,
    list_key: Option<&str>,
    deleted: usize,
) -> Result<String, String> {
    if latest_payload != "all systems nominal" {
        return Err(format!("unexpected latest payload: {}", latest_payload));
    }
    if search_len != 1 || search_key != Some("status") {
        return Err(format!(
            "unexpected search results: len={} key={:?}",
            search_len, search_key
        ));
    }
    if list_key != Some("status") {
        return Err(format!("unexpected list results: key={:?}", list_key));
    }
    if deleted != 1 {
        return Err(format!("unexpected delete count: {}", deleted));
    }

    Ok(format!(
        "opened {}, wrote one encrypted entry, queried it, and deleted it",
        memory_db.display()
    ))
}

fn record_memory_outcome(report: &mut DemoReport, outcome: Result<String, String>) {
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
    let blocked_read = blocked_probe_path(repo_root);
    let result_file = tmp_dir.join("sandbox-probe-result.json");
    let _ = fs::remove_file(&allowed_write);
    let _ = fs::remove_file(&result_file);

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
            .arg("--result-file")
            .arg(&result_file)
            .arg("--network-host")
            .arg("1.1.1.1")
            .arg("--network-port")
            .arg("80")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let policy = demo_sandbox_policy(repo_root, tmp_dir, &allowed_read);
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
            let result = read_sandbox_probe_output(&result_file, &stdout).unwrap_or_default();
            return Err(format!(
                "sandbox probe exited with {} stdout={} stderr={}",
                status.code().unwrap_or(-1),
                result.trim(),
                stderr.trim()
            ));
        }

        let result = read_sandbox_probe_output(&result_file, &stdout)?;

        serde_json::from_str(result.trim()).map_err(|err| {
            format!(
                "failed to parse sandbox probe output: {} (stdout: {} stderr: {})",
                err,
                result.trim(),
                stderr.trim()
            )
        })
    })();

    record_sandbox_outcome(report, outcome);
}

fn record_sandbox_outcome(report: &mut DemoReport, outcome: Result<SandboxProbeResult, String>) {
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
                    format!(
                        "blocked path unexpectedly succeeded: {}",
                        result.blocked_read.detail
                    ),
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
                    format!(
                        "network connect unexpectedly succeeded: {}",
                        result.network_connect.detail
                    ),
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
        report.push(DemoStatus::Skip, "SLIM messaging", "skipped by --no-slim");
        return;
    }

    #[cfg(windows)]
    {
        let _ = (
            current_exe,
            tmp_dir,
            slim_endpoint,
            bot_agent_id,
            peer_agent_id,
            destination,
            shared_secret,
            timeout_seconds,
        );
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

fn run_a2a_checks(
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
        report.push(DemoStatus::Skip, "A2A over SLIMRPC", "skipped by --no-slim");
        return;
    }

    #[cfg(windows)]
    {
        let _ = (
            current_exe,
            tmp_dir,
            slim_endpoint,
            bot_agent_id,
            peer_agent_id,
            destination,
            shared_secret,
            timeout_seconds,
        );
        report.push(
            DemoStatus::Skip,
            "A2A over SLIMRPC",
            "local A2A demo is currently wired for Unix/macOS assets",
        );
        return;
    }

    #[cfg(not(windows))]
    {
        let outcome = (|| -> Result<String, String> {
            let task_detail = run_a2a_exchange(
                current_exe,
                tmp_dir,
                slim_endpoint,
                bot_agent_id,
                peer_agent_id,
                destination,
                shared_secret,
                &format!("demo a2a ping from {}", bot_agent_id),
                false,
                timeout_seconds,
            )?;
            let stream_detail = run_a2a_exchange(
                current_exe,
                tmp_dir,
                slim_endpoint,
                bot_agent_id,
                peer_agent_id,
                destination,
                shared_secret,
                &format!("demo a2a stream ping from {}", bot_agent_id),
                true,
                timeout_seconds,
            )?;

            Ok(format!("{}; {}", task_detail, stream_detail))
        })();

        match outcome {
            Ok(detail) => report.push(DemoStatus::Pass, "A2A over SLIMRPC", detail),
            Err(err) => report.push(DemoStatus::Fail, "A2A over SLIMRPC", err),
        }
    }
}

#[cfg(not(windows))]
fn run_a2a_exchange(
    current_exe: &Path,
    tmp_dir: &Path,
    slim_endpoint: &str,
    bot_agent_id: &str,
    peer_agent_id: &str,
    destination: &str,
    shared_secret: &str,
    message: &str,
    stream: bool,
    timeout_seconds: u64,
) -> Result<String, String> {
    ensure_slim_tls_assets(tmp_dir)?;

    let ready_file = tmp_dir.join(if stream {
        "shadi-demo-a2a-peer-stream.ready"
    } else {
        "shadi-demo-a2a-peer-task.ready"
    });
    let _ = fs::remove_file(&ready_file);

    let peer = Command::new(current_exe)
        .arg("a2a-echo-peer")
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
        .map_err(|err| format!("failed to spawn A2A peer: {}", err))?;

    wait_for_file(&ready_file, Duration::from_secs(10))?;

    let detail = run_a2a_send_once(&A2ASendArgs {
                shadi_tmp_dir: Some(tmp_dir.to_path_buf()),
                endpoint: slim_endpoint.to_string(),
                agent_id: bot_agent_id.to_string(),
                peer_agent_id: peer_agent_id.to_string(),
                destination: Some(destination.to_string()),
                shared_secret: shared_secret.to_string(),
                message: message.to_string(),
                stream,
                timeout_seconds,
            })?;

    let output = wait_for_child_output(peer, Duration::from_secs(timeout_seconds + 5))?;
    if !output.status.success() {
        return Err(format!(
            "A2A peer exited with {} stdout={} stderr={}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(detail)
}

fn run_shell_ticker(args: ShellTickerArgs) -> Result<(), String> {
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_handlers(&shutdown)?;

    maybe_write_ready_file(args.ready_file.as_deref())?;

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
        println!("[demo-agent] tick {:>4}  {}", tick, clock_time_string());
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

    if let Some(result_file) = &args.result_file {
        if let Some(parent) = result_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {}", parent.display(), err))?;
        }
        fs::write(result_file, output.as_bytes())
            .map_err(|err| format!("failed to write {}: {}", result_file.display(), err))?;
    }

    println!("{}", output);
    Ok(())
}

fn run_slim_node(args: SlimNodeArgs) -> Result<(), String> {
    let repo_root = repo_root()?;
    let tmp_dir = resolve_tmp_dir(args.shadi_tmp_dir.as_deref(), &repo_root)?;
    let tls_dir = ensure_slim_tls_assets(&tmp_dir)?;
    let server_tls = server_tls_material(&tls_dir);

    let service = Service::new(format!("shadi-demo-node-{}", std::process::id()));
    service
        .run_server(build_server_config(&args.endpoint, &server_tls))
        .map_err(format_slim_error)?;

    if let Some(ready_file) = &args.ready_file {
        fs::write(ready_file, b"ready")
            .map_err(|err| format!("failed to write {}: {}", ready_file.display(), err))?;
    }

    println!("[slim-node] ready on {}", args.endpoint);
    thread::sleep(Duration::from_secs(args.runtime_seconds));

    let _ = service.stop_server(args.endpoint.clone());
    let _ = service.shutdown();
    Ok(())
}

fn run_slim_echo_peer(args: SlimEchoPeerArgs) -> Result<(), String> {
    if args.expected_messages == 0 {
        return Err("expected_messages must be at least 1".to_string());
    }

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
    let idle_grace_seconds = std::env::var("SHADI_LIVE_PEER_IDLE_GRACE_SECONDS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);
    let mut observed_messages = 0usize;
    loop {
        let listen_timeout = if observed_messages < args.expected_messages {
            Duration::from_secs(args.listen_timeout_seconds)
        } else {
            Duration::from_secs(idle_grace_seconds)
        };

        let session = match app.listen_for_session(Some(listen_timeout)) {
            Ok(session) => session,
            Err(_err) if observed_messages >= args.expected_messages => break,
            Err(err) => return Err(format_slim_error(err)),
        };
        let message = session
            .get_message(Some(Duration::from_secs(args.listen_timeout_seconds)))
            .map_err(format_slim_error)?;
        let payload_text = String::from_utf8_lossy(&message.payload).to_string();
        let reply = format!("echo:{}:{}", peer_name, payload_text).into_bytes();
        session
            .publish_and_wait(reply, Some("text/plain".to_string()), Some(HashMap::new()))
            .map_err(format_slim_error)?;
        let _ = app.delete_session_and_wait(session);
        observed_messages = observed_messages.saturating_add(1);
    }
    let _ = app.unsubscribe(peer_name_ref, Some(connection_id));
    let _ = service.disconnect(connection_id);
    let _ = service.shutdown();

    if let Some(service) = node_service {
        let _ = service.stop_server(args.endpoint.clone());
        let _ = service.shutdown();
    }

    Ok(())
}

fn run_a2a_echo_peer(args: A2AEchoPeerArgs) -> Result<(), String> {
    if args.expected_requests == 0 {
        return Err("expected_requests must be at least 1".to_string());
    }

    let repo_root = repo_root()?;
    let tmp_dir = resolve_tmp_dir(args.shadi_tmp_dir.as_deref(), &repo_root)?;
    let tls_dir = ensure_slim_tls_assets(&tmp_dir)?;
    let peer_name = canonical_name(&args.agent_id);

    let server_tls = server_tls_material(&tls_dir);
    let client_tls = client_tls_material(&tls_dir, &args.agent_id)?;

    let node_service = if args.start_local_node {
        let service = Service::new(format!("shadi-demo-a2a-node-{}", std::process::id()));
        service
            .run_server(build_server_config(&args.endpoint, &server_tls))
            .map_err(format_slim_error)?;
        thread::sleep(Duration::from_millis(300));
        Some(service)
    } else {
        None
    };

    let service = Service::new(format!("shadi-demo-a2a-peer-{}", std::process::id()));
    let connection_id = service
        .connect(build_client_config(&args.endpoint, &client_tls))
        .map_err(format_slim_error)?;
    let peer_name_ref = Arc::new(parse_name(&peer_name)?);
    let app = service
        .create_app_with_secret(peer_name_ref.clone(), args.shared_secret.clone())
        .map_err(format_slim_error)?;
    app.subscribe(peer_name_ref.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    let server = Arc::new(Server::new(&app, app.name().clone()));
    let request_seen = Arc::new(Notify::new());
    let request_count = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(DemoA2AHandler::new(
        peer_name.clone(),
        format!("slimrpc://{}", peer_name),
        request_seen.clone(),
        request_count.clone(),
    ));
    SlimRpcHandler::new(handler).register(&server);

    let ready_file = args.ready_file.clone();
    let endpoint = args.endpoint.clone();
    let wait_seconds = args.listen_timeout_seconds;
    let idle_grace_seconds = std::env::var("SHADI_LIVE_PEER_IDLE_GRACE_SECONDS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);
    let expected_requests = args.expected_requests;
    let peer_label = peer_name.clone();
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to create tokio runtime: {}", err))?;

    let serve_result = runtime.block_on(async move {
        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .serve_async()
                    .await
                    .map_err(|err| format!("A2A SLIMRPC server failed: {}", err))
            })
        };

        tokio::time::sleep(Duration::from_millis(300)).await;
        if let Some(ready_file) = &ready_file {
            fs::write(ready_file, b"ready")
                .map_err(|err| format!("failed to write {}: {}", ready_file.display(), err))?;
        }

        println!("[a2a-peer] ready as {} on {}", peer_label, endpoint);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_seconds);
        while tokio::time::Instant::now() < deadline {
            let observed = request_count.load(Ordering::SeqCst);
            if observed >= expected_requests {
                let idle = tokio::time::timeout(
                    Duration::from_secs(idle_grace_seconds),
                    request_seen.notified(),
                )
                .await;
                if idle.is_err() {
                    break;
                }
                continue;
            }

            let now = tokio::time::Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            let notified = tokio::time::timeout(remaining, request_seen.notified()).await;
            if notified.is_err() {
                break;
            }
        }

        let observed = request_count.load(Ordering::SeqCst);

        if observed >= expected_requests {
            // Allow in-flight response streams to flush before stopping the server.
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        server.shutdown_async().await;
        let server_status = server_task
            .await
            .map_err(|err| format!("failed to join A2A SLIMRPC server task: {}", err))?;
        server_status?;

        if observed == 0 {
            return Err(format!(
                "timed out waiting for A2A requests after {}s (observed {}, expected {})",
                wait_seconds, observed, expected_requests
            ));
        }

        Ok::<(), String>(())
    });

    let _ = app.unsubscribe(peer_name_ref, Some(connection_id));
    let _ = service.disconnect(connection_id);
    let _ = service.shutdown();

    if let Some(service) = node_service {
        let _ = service.stop_server(args.endpoint.clone());
        let _ = service.shutdown();
    }

    serve_result
}

fn run_a2a_send(args: A2ASendArgs) -> Result<(), String> {
    let detail = run_a2a_send_once(&args)?;
    println!("{}", detail);
    Ok(())
}

fn run_a2a_send_once(args: &A2ASendArgs) -> Result<String, String> {
    let repo_root = repo_root()?;
    let tmp_dir = resolve_tmp_dir(args.shadi_tmp_dir.as_deref(), &repo_root)?;
    let tls_dir = ensure_slim_tls_assets(&tmp_dir)?;
    let client_tls = client_tls_material(&tls_dir, &args.agent_id)?;
    let local_name = canonical_name(&args.agent_id);
    let destination = args
        .destination
        .clone()
        .unwrap_or_else(|| canonical_name(&args.peer_agent_id));

    let service = Service::new(format!("shadi-demo-a2a-client-{}", std::process::id()));
    let connection_id = service
        .connect(build_client_config(&args.endpoint, &client_tls))
        .map_err(format_slim_error)?;
    let local_name_ref = Arc::new(parse_name(&local_name)?);
    let remote_name_ref = Arc::new(parse_name(&destination)?);
    let app = service
        .create_app_with_secret(local_name_ref.clone(), args.shared_secret.clone())
        .map_err(format_slim_error)?;
    app.subscribe(local_name_ref.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    let mut session = SessionContext::new(&args.agent_id, "a2a-demo-session");
    session.verified = true;
    let verifier: Arc<dyn AgentVerifier> = Arc::new(VerifiedSessionVerifier);
    let channel = A2AChannelBuilder::new(app.clone(), remote_name_ref, verifier, session)
        .connection_id(connection_id)
        .build();
    let client = A2AClient::new(Box::new(channel));
    let request = SendMessageRequest {
        message: Message::new(Role::User, vec![Part::text(args.message.clone())]),
        configuration: None,
        metadata: None,
        tenant: None,
    };

    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to create tokio runtime: {}", err))?;
    let response_detail = runtime
        .block_on(async {
            if args.stream {
                use futures::StreamExt;

                let stream = client.send_streaming_message(&request).await?;
                let events = stream.collect::<Vec<_>>().await;
                client.destroy().await?;
                Ok::<String, A2AError>(describe_a2a_stream(&events))
            } else {
                let response = client.send_message(&request).await?;
                client.destroy().await?;
                Ok::<String, A2AError>(describe_a2a_response(&response))
            }
        })
        .map_err(|err| format!("failed to send A2A message: {}", err))?;

    let _ = app.unsubscribe(local_name_ref, Some(connection_id));
    let _ = service.disconnect(connection_id);
    let _ = service.shutdown();

    Ok(format!(
        "sent {:?} to {} via {} and received {}",
        args.message,
        destination,
        local_name,
        response_detail
    ))
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
    let canonical = path
        .canonicalize()
        .map_err(|err| format!("failed to resolve repository root: {}", err))?;
    // On Windows, Path::canonicalize produces a \\?\ extended-length prefix.
    // AppContainer security evaluation on newer Windows builds does not honour
    // DACL grants made on the plain path when the child reads via the \\?\
    // variant, so we strip the prefix here to keep the grant path and the
    // read path consistent.
    #[cfg(windows)]
    {
        let s = canonical.to_string_lossy();
        if let Some(stripped) = s.strip_prefix("\\\\?\\") {
            return Ok(PathBuf::from(stripped));
        }
    }
    Ok(canonical)
}

fn blocked_probe_path(repo_root: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/private/etc/hosts")
    } else if cfg!(target_os = "linux") {
        PathBuf::from("/proc/version")
    } else if cfg!(target_os = "windows") {
        repo_root.join("Cargo.toml")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

fn demo_sandbox_policy(repo_root: &Path, tmp_dir: &Path, allowed_read: &Path) -> SandboxPolicy {
    let mut policy = SandboxPolicy::new()
        .allow_read_path(repo_root)
        .allow_read_path(tmp_dir)
        .allow_write_path(tmp_dir)
        .block_network(true);

    if cfg!(target_os = "windows") {
        policy = policy.allow_read_path(allowed_read);
    }

    if let Some(profile_dir) = llvm_profile_output_dir() {
        policy = policy.allow_write_path(profile_dir);
    }

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
    paths.retain(|path| Path::new(path).exists());
    paths
}

fn sandbox_checks_should_run_last() -> bool {
    cfg!(target_os = "linux") && llvm_profile_output_dir().is_some()
}

fn llvm_profile_output_dir() -> Option<PathBuf> {
    let profile = std::env::var_os("LLVM_PROFILE_FILE")?;
    let path = PathBuf::from(profile);
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }

    if parent.is_absolute() {
        Some(parent.to_path_buf())
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(parent))
    }
}

fn read_sandbox_probe_output(result_file: &Path, stdout: &str) -> Result<String, String> {
    if let Ok(output) = fs::read_to_string(result_file) {
        if !output.trim().is_empty() {
            return Ok(output);
        }
    }

    if !stdout.trim().is_empty() {
        return Ok(stdout.to_string());
    }

    Err(format!(
        "sandbox probe produced no output in {} or stdout",
        result_file.display()
    ))
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
            detail: format!(
                "unexpectedly read {} bytes from {}",
                content.len(),
                path.display()
            ),
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

#[cfg(any(test, not(windows)))]
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

#[cfg(any(test, not(windows)))]
fn wait_for_child_output(
    mut child: Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
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

fn maybe_write_ready_file(path: Option<&Path>) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create ready file parent: {}", err))?;
    }

    fs::write(path, b"ready").map_err(|err| format!("failed to write ready file: {}", err))
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

fn readable_message_text(message: &Message) -> String {
    let text = message
        .parts
        .iter()
        .filter_map(Part::as_text)
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        "(no text parts)".to_string()
    } else {
        text
    }
}

fn describe_a2a_response(response: &SendMessageResponse) -> String {
    match response {
        SendMessageResponse::Message(message) => {
            format!("message {:?}", readable_message_text(message))
        }
        SendMessageResponse::Task(task) => {
            let detail = task
                .status
                .message
                .as_ref()
                .map(readable_message_text)
                .unwrap_or_else(|| format!("state {:?}", task.status.state));
            format!("task {} ({})", task.id, detail)
        }
    }
}

fn describe_a2a_stream(events: &[Result<StreamResponse, A2AError>]) -> String {
    let mut descriptions = Vec::new();
    for event in events {
        match event {
            Ok(StreamResponse::StatusUpdate(update)) => descriptions.push(format!(
                "status {:?}",
                update.status.state
            )),
            Ok(StreamResponse::Task(task)) => descriptions.push(format!(
                "task {} ({})",
                task.id,
                task.status
                    .message
                    .as_ref()
                    .map(readable_message_text)
                    .unwrap_or_else(|| format!("state {:?}", task.status.state))
            )),
            Ok(StreamResponse::Message(message)) => {
                descriptions.push(format!("message {:?}", readable_message_text(message)))
            }
            Ok(StreamResponse::ArtifactUpdate(update)) => {
                descriptions.push(format!("artifact {}", update.task_id))
            }
            Err(error) => descriptions.push(format!("error {}", error)),
        }
    }
    format!("stream [{}]", descriptions.join(", "))
}

fn demo_a2a_agent_card(agent_name: &str, target: &str) -> AgentCard {
    AgentCard {
        name: format!("SHADI Demo A2A Peer ({})", agent_name),
        description: "Demo SHADI agent exposing A2A over SLIMRPC".to_string(),
        version: VERSION.to_string(),
        supported_interfaces: vec![AgentInterface::new(
            target.to_string(),
            TRANSPORT_PROTOCOL_SLIMRPC,
        )],
        capabilities: AgentCapabilities {
            streaming: Some(true),
            push_notifications: Some(false),
            extensions: None,
            extended_agent_card: Some(true),
        },
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["text/plain".to_string()],
        skills: Vec::new(),
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: None,
        security_requirements: None,
        signatures: None,
    }
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
        generate_client_tls_material(base_dir, agent_id)?;
    }

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

fn generate_client_tls_material(base_dir: &Path, agent_id: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = (base_dir, agent_id);
        return Err("cannot generate dynamic SLIM client TLS material on Windows".to_string());
    }

    #[cfg(not(windows))]
    {
        let cert = base_dir.join(format!("client-{}.crt", agent_id));
        let key = base_dir.join(format!("client-{}.key", agent_id));
        let csr = base_dir.join(format!("client-{}.csr", agent_id));
        let ca_crt = base_dir.join("ca.crt");
        let ca_key = base_dir.join("ca.key");
        let client_ext = base_dir.join("client.ext");
        if !client_ext.is_file() {
            fs::write(
                &client_ext,
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n",
            )
            .map_err(|err| format!("failed to write {}: {}", client_ext.display(), err))?;
        }

        let req = Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str()
                    .ok_or_else(|| format!("invalid path {}", key.display()))?,
                "-out",
                csr.to_str()
                    .ok_or_else(|| format!("invalid path {}", csr.display()))?,
                "-subj",
                &format!("/CN={}", agent_id),
            ])
            .output()
            .map_err(|err| format!("failed to run openssl req: {}", err))?;
        if !req.status.success() {
            return Err(format!(
                "failed to generate client key/csr for {}: {}{}",
                agent_id,
                String::from_utf8_lossy(&req.stdout),
                String::from_utf8_lossy(&req.stderr)
            ));
        }

        let sign = Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                csr.to_str()
                    .ok_or_else(|| format!("invalid path {}", csr.display()))?,
                "-CA",
                ca_crt
                    .to_str()
                    .ok_or_else(|| format!("invalid path {}", ca_crt.display()))?,
                "-CAkey",
                ca_key
                    .to_str()
                    .ok_or_else(|| format!("invalid path {}", ca_key.display()))?,
                "-CAcreateserial",
                "-out",
                cert.to_str()
                    .ok_or_else(|| format!("invalid path {}", cert.display()))?,
                "-days",
                "365",
                "-extfile",
                client_ext
                    .to_str()
                    .ok_or_else(|| format!("invalid path {}", client_ext.display()))?,
            ])
            .output()
            .map_err(|err| format!("failed to run openssl x509: {}", err))?;
        if !sign.status.success() {
            return Err(format!(
                "failed to sign client cert for {}: {}{}",
                agent_id,
                String::from_utf8_lossy(&sign.stdout),
                String::from_utf8_lossy(&sign.stderr)
            ));
        }

        let _ = fs::remove_file(csr);
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use futures::StreamExt;
    use std::io::{Cursor, Error, ErrorKind};

    fn demo_send_request(text: &str) -> SendMessageRequest {
        SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text(text)]),
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }

    fn demo_executor_context(message: Option<Message>) -> a2a_server::ExecutorContext {
        a2a_server::ExecutorContext {
            message,
            task_id: "task-1".to_string(),
            stored_task: None,
            context_id: "context-1".to_string(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::new(ErrorKind::Other, "boom"))
        }
    }

    #[cfg(unix)]
    fn success_command() -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg("printf ok");
        command
    }

    #[cfg(windows)]
    fn success_command() -> Command {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("echo ok");
        command
    }

    #[cfg(unix)]
    fn sleep_command() -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 1");
        command
    }

    #[cfg(windows)]
    fn sleep_command() -> Command {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("ping 127.0.0.1 -n 3 >NUL");
        command
    }

    fn create_tls_assets(root: &Path) -> PathBuf {
        let tls_dir = root.join("shadi-slim-mtls");
        fs::create_dir_all(&tls_dir).expect("create tls dir");
        for relative in [
            "server.crt",
            "server.key",
            "ca.crt",
            "client-avatar.crt",
            "client-avatar.key",
            "client-secops-a.crt",
            "client-secops-a.key",
        ] {
            fs::write(tls_dir.join(relative), b"fixture").expect("write tls fixture");
        }
        tls_dir
    }

    #[test]
    fn maybe_write_ready_file_accepts_none() {
        assert!(maybe_write_ready_file(None).is_ok());
    }

    #[test]
    fn maybe_write_ready_file_writes_nested_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ready_file = dir.path().join("nested").join("shell-ticker.ready");

        maybe_write_ready_file(Some(ready_file.as_path())).expect("write ready file");

        assert_eq!(fs::read(&ready_file).expect("read ready file"), b"ready");
    }

    #[test]
    fn maybe_write_ready_file_reports_write_error_without_parent() {
        let err = maybe_write_ready_file(Some(Path::new(""))).expect_err("empty path should fail");
        assert!(err.contains("failed to write ready file"), "{err}");
    }

    #[test]
    fn feature_bot_args_default_matches_expected_values() {
        let args = FeatureBotArgs::default();
        assert_eq!(args.memory_key, DEFAULT_MEMORY_KEY);
        assert_eq!(args.slim_bot_agent_id, DEFAULT_BOT_AGENT_ID);
        assert_eq!(args.slim_peer_agent_id, DEFAULT_PEER_AGENT_ID);
        assert_eq!(args.slim_shared_secret, DEFAULT_SHARED_SECRET);
        assert_eq!(args.slim_timeout_seconds, 20);
        assert!(!args.no_slim);
    }

    #[test]
    fn demo_report_tracks_failures_and_prints_summary() {
        let mut report = DemoReport::default();
        report.push(DemoStatus::Pass, "secrets", "ok");
        report.push(DemoStatus::Skip, "slim", "skipped");
        report.push(DemoStatus::Fail, "sandbox", "blocked");

        assert!(report.has_failures());
        assert_eq!(DemoStatus::Pass.label(), "PASS");
        assert_eq!(DemoStatus::Skip.label(), "SKIP");
        report.print();
    }

    #[test]
    fn scoped_env_var_restores_previous_value() {
        std::env::set_var("SHADI_DEMO_TEST_ENV", "before");
        {
            let _scoped = ScopedEnvVar::set("SHADI_DEMO_TEST_ENV", "after");
            assert_eq!(std::env::var("SHADI_DEMO_TEST_ENV").unwrap(), "after");
        }
        assert_eq!(std::env::var("SHADI_DEMO_TEST_ENV").unwrap(), "before");

        {
            let _scoped = ScopedEnvVar::unset("SHADI_DEMO_TEST_ENV");
            assert!(std::env::var("SHADI_DEMO_TEST_ENV").is_err());
        }
        assert_eq!(std::env::var("SHADI_DEMO_TEST_ENV").unwrap(), "before");
        std::env::remove_var("SHADI_DEMO_TEST_ENV");
    }

    #[test]
    fn run_secret_checks_reports_passing_checks() {
        let mut report = DemoReport::default();
        run_secret_checks(&mut report);

        assert_eq!(report.checks.len(), 2);
        assert!(report
            .checks
            .iter()
            .all(|check| check.status == DemoStatus::Pass));
        assert!(!report.has_failures());
    }

    #[test]
    fn unverified_secret_access_records_expected_statuses() {
        let mut report = DemoReport::default();
        record_unverified_secret_access(&mut report, Err(SecretError::NotAuthorized));
        assert_eq!(report.checks[0].status, DemoStatus::Pass);

        let mut report = DemoReport::default();
        record_unverified_secret_access(&mut report, Err(SecretError::StorageFailure));
        assert_eq!(report.checks[0].status, DemoStatus::Fail);
        assert!(report.checks[0]
            .detail
            .contains("unexpected verifier error"));

        let mut report = DemoReport::default();
        record_unverified_secret_access(&mut report, Ok(()));
        assert_eq!(report.checks[0].status, DemoStatus::Fail);
        assert!(report.checks[0].detail.contains("unexpectedly wrote"));
    }

    #[test]
    fn secret_roundtrip_validation_rejects_bad_values() {
        let expected_keys = ["demo/api-token".to_string()];
        let empty: [String; 0] = [];

        assert!(validate_secret_roundtrip("demo-token", &expected_keys, &empty).is_ok());
        assert!(validate_secret_roundtrip("wrong", &expected_keys, &empty)
            .expect_err("wrong payload should fail")
            .contains("unexpected secret payload"));
        assert!(
            validate_secret_roundtrip("demo-token", &["wrong".to_string()], &empty)
                .expect_err("wrong key should fail")
                .contains("unexpected key listing")
        );
        assert!(
            validate_secret_roundtrip("demo-token", &expected_keys, &["leftover".to_string()],)
                .expect_err("leftover keys should fail")
                .contains("secret delete left keys behind")
        );
    }

    #[test]
    fn outcome_recorders_capture_failures() {
        let mut report = DemoReport::default();
        record_secret_roundtrip_outcome(&mut report, Err("boom".to_string()));
        assert_eq!(report.checks[0].status, DemoStatus::Fail);
        assert_eq!(report.checks[0].detail, "boom");

        let mut report = DemoReport::default();
        record_memory_outcome(&mut report, Err("nope".to_string()));
        assert_eq!(report.checks[0].status, DemoStatus::Fail);
        assert_eq!(report.checks[0].detail, "nope");
    }

    #[test]
    fn run_memory_checks_reports_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut report = DemoReport::default();
        run_memory_checks(&mut report, &dir.path().join("memory.db"), "memory-key");

        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].status, DemoStatus::Pass);
        assert!(report.checks[0].detail.contains("opened"));
    }

    #[test]
    fn memory_roundtrip_validation_rejects_bad_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let memory_db = dir.path().join("memory.db");

        assert!(validate_memory_roundtrip(
            &memory_db,
            "all systems nominal",
            1,
            Some("status"),
            Some("status"),
            1,
        )
        .is_ok());
        assert!(validate_memory_roundtrip(
            &memory_db,
            "wrong",
            1,
            Some("status"),
            Some("status"),
            1
        )
        .expect_err("wrong payload should fail")
        .contains("unexpected latest payload"));
        assert!(validate_memory_roundtrip(
            &memory_db,
            "all systems nominal",
            2,
            Some("status"),
            Some("status"),
            1
        )
        .expect_err("wrong search len should fail")
        .contains("unexpected search results"));
        assert!(validate_memory_roundtrip(
            &memory_db,
            "all systems nominal",
            1,
            Some("status"),
            None,
            1
        )
        .expect_err("missing list key should fail")
        .contains("unexpected list results"));
        assert!(validate_memory_roundtrip(
            &memory_db,
            "all systems nominal",
            1,
            Some("status"),
            Some("status"),
            0
        )
        .expect_err("wrong delete count should fail")
        .contains("unexpected delete count"));
    }

    #[test]
    fn run_slim_checks_can_be_skipped_without_runtime_setup() {
        let mut report = DemoReport::default();
        run_slim_checks(
            &mut report,
            Path::new("unused"),
            Path::new("unused"),
            "127.0.0.1:12345",
            DEFAULT_BOT_AGENT_ID,
            DEFAULT_PEER_AGENT_ID,
            &canonical_name(DEFAULT_PEER_AGENT_ID),
            DEFAULT_SHARED_SECRET,
            1,
            true,
        );

        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].status, DemoStatus::Skip);
        assert!(report.checks[0].detail.contains("--no-slim"));
    }

    #[test]
    fn run_a2a_checks_can_be_skipped_without_runtime_setup() {
        let mut report = DemoReport::default();
        run_a2a_checks(
            &mut report,
            Path::new("unused"),
            Path::new("unused"),
            "127.0.0.1:12345",
            DEFAULT_BOT_AGENT_ID,
            DEFAULT_PEER_AGENT_ID,
            &canonical_name(DEFAULT_PEER_AGENT_ID),
            DEFAULT_SHARED_SECRET,
            1,
            true,
        );

        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].status, DemoStatus::Skip);
        assert!(report.checks[0].detail.contains("--no-slim"));
    }

    #[cfg(not(windows))]
    #[test]
    fn run_a2a_checks_record_failure_when_peer_binary_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        create_tls_assets(dir.path());
        let missing_binary = dir.path().join("missing-a2a-peer");
        let mut report = DemoReport::default();

        run_a2a_checks(
            &mut report,
            &missing_binary,
            dir.path(),
            "127.0.0.1:12345",
            DEFAULT_BOT_AGENT_ID,
            DEFAULT_PEER_AGENT_ID,
            &canonical_name(DEFAULT_PEER_AGENT_ID),
            DEFAULT_SHARED_SECRET,
            1,
            false,
        );

        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].status, DemoStatus::Fail);
        assert!(report.checks[0].detail.contains("failed to spawn A2A peer"));
    }

    #[test]
    fn cli_parses_a2a_commands_with_expected_defaults_and_flags() {
        let echo_peer = Cli::try_parse_from([
            "shadi-demo-bot",
            "a2a-echo-peer",
            "--endpoint",
            "127.0.0.1:4555",
            "--agent-id",
            "secops-a",
            "--listen-timeout-seconds",
            "9",
            "--start-local-node",
        ])
        .expect("parse a2a-echo-peer args");

        match echo_peer.command {
            Some(Commands::A2AEchoPeer(args)) => {
                assert_eq!(args.endpoint, "127.0.0.1:4555");
                assert_eq!(args.agent_id, "secops-a");
                assert_eq!(args.listen_timeout_seconds, 9);
                assert!(args.start_local_node);
            }
            _ => panic!("unexpected parsed command"),
        }

        let send = Cli::try_parse_from([
            "shadi-demo-bot",
            "a2a-send",
            "--endpoint",
            "127.0.0.1:4666",
            "--peer-agent-id",
            "secops-a",
            "--destination",
            "agntcy/shadi/secops-a",
            "--message",
            "hello from parser",
            "--stream",
            "--timeout-seconds",
            "11",
        ])
        .expect("parse a2a-send args");

        match send.command {
            Some(Commands::A2ASend(args)) => {
                assert_eq!(args.endpoint, "127.0.0.1:4666");
                assert_eq!(args.agent_id, DEFAULT_BOT_AGENT_ID);
                assert_eq!(args.peer_agent_id, "secops-a");
                assert_eq!(args.destination.as_deref(), Some("agntcy/shadi/secops-a"));
                assert_eq!(args.message, "hello from parser");
                assert!(args.stream);
                assert_eq!(args.timeout_seconds, 11);
            }
            _ => panic!("unexpected parsed command"),
        }
    }

    #[test]
    fn resolve_tmp_dir_supports_explicit_and_default_locations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let explicit = dir.path().join("explicit");
        let resolved = resolve_tmp_dir(Some(&explicit), dir.path()).expect("resolve explicit");
        assert_eq!(resolved, explicit.canonicalize().unwrap());

        let defaulted = resolve_tmp_dir(None, dir.path()).expect("resolve default");
        assert_eq!(defaulted, dir.path().join(".tmp").canonicalize().unwrap());
    }

    #[test]
    fn repo_root_and_static_paths_resolve() {
        let root = repo_root().expect("repo root");
        assert!(root.join("Cargo.toml").is_file());

        let blocked = blocked_probe_path(&root);
        #[cfg(target_os = "macos")]
        assert_eq!(blocked, PathBuf::from("/private/etc/hosts"));
        #[cfg(target_os = "linux")]
        assert_eq!(blocked, PathBuf::from("/proc/version"));
        #[cfg(target_os = "windows")]
        assert_eq!(blocked, root.join("Cargo.toml"));
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        assert_eq!(blocked, PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn llvm_profile_output_dir_reads_parent_directory_from_env() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let profile = temp_dir.path().join("demo-%p.profraw");
        let _profile = ScopedEnvVar::set("LLVM_PROFILE_FILE", profile.as_os_str());

        assert_eq!(
            llvm_profile_output_dir(),
            Some(temp_dir.path().to_path_buf())
        );
    }

    #[test]
    fn default_system_read_paths_include_expected_entries() {
        let paths = default_system_read_paths();

        for path in &paths {
            assert!(Path::new(path).exists(), "missing system read path: {path}");
        }

        #[cfg(not(target_os = "windows"))]
        {
            assert!(paths.contains(&"/usr/bin"));
            assert!(paths.contains(&"/usr/lib"));
            assert!(paths.contains(&"/bin"));
        }

        #[cfg(target_os = "windows")]
        assert!(paths.is_empty());

        #[cfg(target_os = "macos")]
        assert!(paths.contains(&"/Library"));

        #[cfg(target_os = "linux")]
        assert!(paths.contains(&"/etc/ssl"));
    }

    #[test]
    fn probe_file_helpers_cover_success_and_failure_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let readable = dir.path().join("readable.txt");
        let writable = dir.path().join("written.txt");
        let missing = dir.path().join("missing.txt");
        fs::write(&readable, "hello world").expect("write readable");

        let allowed = attempt_allowed_read(&readable);
        assert!(allowed.success);
        assert!(allowed.detail.contains("read 11 bytes"));

        let allowed_error = attempt_allowed_read(&missing);
        assert!(!allowed_error.success);

        let write = attempt_allowed_write(&writable);
        assert!(write.success);
        assert_eq!(fs::read(&writable).unwrap(), b"sandbox write ok\n");

        let blocked_success = attempt_blocked_read(&readable);
        assert!(blocked_success.success);
        assert!(blocked_success.detail.contains("unexpectedly read"));

        let blocked_error = attempt_blocked_read(&missing);
        assert!(!blocked_error.success);
        assert!(blocked_error.detail.contains("blocked reading"));
    }

    #[test]
    fn attempt_allowed_write_reports_failure_for_missing_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unwritable = dir.path().join("missing-parent").join("written.txt");

        let attempt = attempt_allowed_write(&unwritable);
        assert!(!attempt.success);
        assert!(attempt.detail.contains("failed to write"));
    }

    #[test]
    fn attempt_network_connect_covers_success_and_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("listener addr").port();

        let success = attempt_network_connect("127.0.0.1", port);
        assert!(success.success);
        assert!(success.detail.contains("connected to"));

        drop(listener);
        thread::sleep(Duration::from_millis(50));

        let refused = attempt_network_connect("127.0.0.1", port);
        assert!(!refused.success);
        assert!(refused.detail.contains("blocked connect to"));

        let unresolved = attempt_network_connect("nonexistent.invalid.example", 80);
        assert!(!unresolved.success);
        assert!(unresolved.detail.contains("failed to resolve"));
    }

    #[test]
    fn reserve_endpoint_and_wait_for_file_cover_success_and_timeout() {
        let endpoint = reserve_local_endpoint().expect("reserve endpoint");
        assert!(endpoint.parse::<std::net::SocketAddr>().is_ok());

        let dir = tempfile::tempdir().expect("tempdir");
        let ready = dir.path().join("ready.txt");
        let writer = ready.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::write(writer, b"ready").expect("write ready file");
        });
        wait_for_file(&ready, Duration::from_secs(1)).expect("wait for ready file");

        let err = wait_for_file(&dir.path().join("missing.txt"), Duration::from_millis(10))
            .expect_err("missing file should time out");
        assert!(err.contains("timed out waiting"));
    }

    #[test]
    fn wait_for_child_output_covers_success_and_timeout() {
        let mut success = success_command();
        success.stdout(Stdio::piped()).stderr(Stdio::piped());
        let output = wait_for_child_output(
            success.spawn().expect("spawn success"),
            Duration::from_secs(1),
        )
        .expect("collect child output");
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("ok"));

        let mut sleeper = sleep_command();
        sleeper.stdout(Stdio::piped()).stderr(Stdio::piped());
        let err = wait_for_child_output(
            sleeper.spawn().expect("spawn sleeper"),
            Duration::from_millis(50),
        )
        .expect_err("sleeping child should time out");
        assert!(err.contains("timed out after"));
    }

    #[test]
    fn optional_stream_reader_covers_none_success_and_error() {
        let none_output = read_optional_stream::<Cursor<Vec<u8>>>(None).expect("none stream");
        assert!(none_output.is_empty());

        let some_output =
            read_optional_stream(Some(Cursor::new(b"demo".to_vec()))).expect("cursor output");
        assert_eq!(some_output, "demo");

        let err =
            read_optional_stream(Some(FailingReader)).expect_err("failing reader should error");
        assert!(err.contains("failed to read child output"));
    }

    #[test]
    fn formatting_and_name_helpers_return_expected_values() {
        let timestamp = clock_time_string();
        assert_eq!(timestamp.len(), 8);
        assert_eq!(&timestamp[2..3], ":");
        assert_eq!(&timestamp[5..6], ":");

        assert_eq!(canonical_name("bot"), "agntcy/shadi/bot");
        assert!(parse_name(&canonical_name("bot")).is_ok());
        assert!(parse_name("").is_err());

        assert_eq!(
            secret_err_to_string(SecretError::InvalidInput),
            "invalid input"
        );

        let response = SendMessageResponse::Task(Task {
            id: "task-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(Message::new(Role::Agent, vec![Part::text("done")])),
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        });
        assert!(describe_a2a_response(&response).contains("task task-1 (done)"));

        let stream = vec![
            Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: "task-1".to_string(),
                context_id: "ctx-1".to_string(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            })),
            Ok(StreamResponse::Task(Task {
                id: "task-1".to_string(),
                context_id: "ctx-1".to_string(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: Some(Message::new(Role::Agent, vec![Part::text("done")])),
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })),
        ];
        let stream_detail = describe_a2a_stream(&stream);
        assert!(stream_detail.contains("status Working"));
        assert!(stream_detail.contains("task task-1 (done)"));
    }

    #[test]
    fn demo_a2a_helpers_cover_executor_handler_and_card_paths() {
        let empty_message = Message::new(Role::User, vec![]);
        assert_eq!(readable_message_text(&empty_message), "(no text parts)");

        let card = demo_a2a_agent_card(
            "agntcy/shadi/secops-a",
            "slimrpc://agntcy/shadi/secops-a",
        );
        assert_eq!(card.name, "SHADI Demo A2A Peer (agntcy/shadi/secops-a)");
        assert_eq!(card.supported_interfaces.len(), 1);
        assert_eq!(
            card.supported_interfaces[0].protocol_binding,
            TRANSPORT_PROTOCOL_SLIMRPC
        );

        let executor = DemoA2AExecutor {
            agent_name: "agntcy/shadi/secops-a".to_string(),
        };
        let events = futures::executor::block_on(async {
            executor
                .execute(demo_executor_context(Some(Message::new(
                    Role::User,
                    vec![Part::text("hello demo executor")],
                ))))
                .collect::<Vec<_>>()
                .await
        });
        assert_eq!(events.len(), 2);
        match &events[0] {
            Ok(StreamResponse::StatusUpdate(update)) => {
                assert_eq!(update.status.state, TaskState::Working);
            }
            other => panic!("unexpected first executor event: {other:?}"),
        }
        match &events[1] {
            Ok(StreamResponse::Task(task)) => {
                assert_eq!(task.id, "task-1");
                assert_eq!(
                    readable_message_text(task.status.message.as_ref().expect("task message")),
                    "echo:agntcy/shadi/secops-a:hello demo executor"
                );
                assert_eq!(task.history.as_ref().expect("history").len(), 1);
            }
            other => panic!("unexpected second executor event: {other:?}"),
        }

        let cancel_events = futures::executor::block_on(async {
            executor
                .cancel(demo_executor_context(None))
                .collect::<Vec<_>>()
                .await
        });
        match &cancel_events[0] {
            Ok(StreamResponse::Task(task)) => {
                assert_eq!(task.status.state, TaskState::Canceled);
            }
            other => panic!("unexpected cancel event: {other:?}"),
        }

        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let request_seen = Arc::new(Notify::new());
            let handler = DemoA2AHandler::new(
                "agntcy/shadi/secops-a".to_string(),
                "slimrpc://agntcy/shadi/secops-a".to_string(),
                request_seen.clone(),
            );
            let params: A2AServiceParams = HashMap::new();

            let send_wait = request_seen.notified();
            let response = handler
                .send_message(&params, demo_send_request("hello demo handler"))
                .await
                .expect("send message through handler");
            tokio::time::timeout(Duration::from_secs(1), send_wait)
                .await
                .expect("send_message should notify waiters");

            let task = match response {
                SendMessageResponse::Task(task) => task,
                other => panic!("unexpected send_message response: {other:?}"),
            };

            let send_stream_wait = request_seen.notified();
            let stream_events = handler
                .send_streaming_message(&params, demo_send_request("hello demo stream"))
                .await
                .expect("send streaming message")
                .collect::<Vec<_>>()
                .await;
            tokio::time::timeout(Duration::from_secs(1), send_stream_wait)
                .await
                .expect("send_streaming_message should notify waiters");
            assert_eq!(stream_events.len(), 2);

            let fetched = handler
                .get_task(
                    &params,
                    GetTaskRequest {
                        id: task.id.clone(),
                        history_length: Some(1),
                        tenant: None,
                    },
                )
                .await
                .expect("get task");
            assert_eq!(fetched.id, task.id);

            let listed = handler
                .list_tasks(
                    &params,
                    ListTasksRequest {
                        context_id: Some(task.context_id.clone()),
                        status: None,
                        page_size: Some(10),
                        page_token: None,
                        history_length: Some(1),
                        status_timestamp_after: None,
                        include_artifacts: Some(false),
                        tenant: None,
                    },
                )
                .await
                .expect("list tasks");
            assert!(listed.tasks.iter().any(|entry| entry.id == task.id));

            let push_config_err = handler
                .create_push_config(
                    &params,
                    CreateTaskPushNotificationConfigRequest {
                        task_id: task.id.clone(),
                        config: PushNotificationConfig {
                            url: "https://example.invalid/hook".to_string(),
                            id: Some("cfg-1".to_string()),
                            token: None,
                            authentication: None,
                        },
                        tenant: None,
                    },
                )
                .await
                .expect_err("push config should not be supported");
            assert!(push_config_err.message.contains("not supported"));

            let fetched_push_err = handler
                .get_push_config(
                    &params,
                    GetTaskPushNotificationConfigRequest {
                        task_id: task.id.clone(),
                        id: "cfg-1".to_string(),
                        tenant: None,
                    },
                )
                .await
                .expect_err("get push config should not be supported");
            assert!(fetched_push_err.message.contains("not supported"));

            let listed_push_err = handler
                .list_push_configs(
                    &params,
                    ListTaskPushNotificationConfigsRequest {
                        task_id: task.id.clone(),
                        page_size: Some(10),
                        page_token: None,
                        tenant: None,
                    },
                )
                .await
                .expect_err("list push configs should not be supported");
            assert!(listed_push_err.message.contains("not supported"));

            let delete_push_err = handler
                .delete_push_config(
                    &params,
                    DeleteTaskPushNotificationConfigRequest {
                        task_id: task.id.clone(),
                        id: "cfg-1".to_string(),
                        tenant: None,
                    },
                )
                .await
                .expect_err("delete push config should not be supported");
            assert!(delete_push_err.message.contains("not supported"));

            let card = handler
                .get_extended_agent_card(&params, GetExtendedAgentCardRequest { tenant: None })
                .await
                .expect("extended agent card");
            assert_eq!(card.supported_interfaces[0].url, "slimrpc://agntcy/shadi/secops-a");
        });
    }

    #[test]
    fn slim_tls_helpers_use_existing_assets_and_embed_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tls_dir = create_tls_assets(dir.path());

        let ensured = ensure_slim_tls_assets(dir.path()).expect("ensure tls assets");
        assert_eq!(ensured, tls_dir);

        let client = client_tls_material(&tls_dir, DEFAULT_BOT_AGENT_ID).expect("client tls");
        assert_eq!(client.cert, tls_dir.join("client-avatar.crt"));
        assert_eq!(client.key, tls_dir.join("client-avatar.key"));
        assert_eq!(client.ca, tls_dir.join("ca.crt"));

        let missing = client_tls_material(dir.path(), DEFAULT_BOT_AGENT_ID)
            .expect_err("missing client tls should error");
        assert!(missing.contains("missing client TLS material"));

        let server = server_tls_material(&tls_dir);
        assert_eq!(server.cert, tls_dir.join("server.crt"));
        assert_eq!(server.key, tls_dir.join("server.key"));
        assert_eq!(server.ca, tls_dir.join("ca.crt"));

        let client_config = build_client_config("127.0.0.1:4444", &client);
        assert_eq!(client_config.endpoint, "https://127.0.0.1:4444");
        match client_config.tls.source {
            TlsSource::File { cert, key } => {
                assert_eq!(
                    cert,
                    tls_dir.join("client-avatar.crt").display().to_string()
                );
                assert_eq!(key, tls_dir.join("client-avatar.key").display().to_string());
            }
            other => panic!("unexpected client tls source: {other:?}"),
        }
        match client_config.tls.ca_source {
            CaSource::File { path } => {
                assert_eq!(path, tls_dir.join("ca.crt").display().to_string());
            }
            other => panic!("unexpected client ca source: {other:?}"),
        }

        let server_config = build_server_config("127.0.0.1:4444", &server);
        assert_eq!(server_config.endpoint, "127.0.0.1:4444");
        match server_config.tls.source {
            TlsSource::File { cert, key } => {
                assert_eq!(cert, tls_dir.join("server.crt").display().to_string());
                assert_eq!(key, tls_dir.join("server.key").display().to_string());
            }
            other => panic!("unexpected server tls source: {other:?}"),
        }
        match server_config.tls.client_ca {
            CaSource::File { path } => {
                assert_eq!(path, tls_dir.join("ca.crt").display().to_string());
            }
            other => panic!("unexpected server client ca: {other:?}"),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn ensure_slim_tls_assets_generates_missing_assets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tls_dir = ensure_slim_tls_assets(dir.path()).expect("generate tls assets");

        for relative in [
            "server.crt",
            "server.key",
            "ca.crt",
            "client-avatar.crt",
            "client-avatar.key",
            "client-secops-a.crt",
            "client-secops-a.key",
        ] {
            assert!(tls_dir.join(relative).is_file(), "missing {relative}");
        }
    }

    #[test]
    fn sandbox_outcome_records_pass_fail_and_skip_paths() {
        let mut report = DemoReport::default();
        record_sandbox_outcome(
            &mut report,
            Ok(SandboxProbeResult {
                allowed_read: ProbeAttempt {
                    success: true,
                    detail: "read ok".to_string(),
                },
                allowed_write: ProbeAttempt {
                    success: true,
                    detail: "write ok".to_string(),
                },
                blocked_read: ProbeAttempt {
                    success: false,
                    detail: "blocked".to_string(),
                },
                network_connect: ProbeAttempt {
                    success: false,
                    detail: "blocked".to_string(),
                },
            }),
        );
        assert!(report
            .checks
            .iter()
            .all(|check| check.status == DemoStatus::Pass));

        let mut report = DemoReport::default();
        record_sandbox_outcome(
            &mut report,
            Ok(SandboxProbeResult {
                allowed_read: ProbeAttempt {
                    success: false,
                    detail: "denied".to_string(),
                },
                allowed_write: ProbeAttempt {
                    success: true,
                    detail: "write ok".to_string(),
                },
                blocked_read: ProbeAttempt {
                    success: true,
                    detail: "unexpected".to_string(),
                },
                network_connect: ProbeAttempt {
                    success: true,
                    detail: "unexpected".to_string(),
                },
            }),
        );
        assert!(report
            .checks
            .iter()
            .all(|check| check.status == DemoStatus::Fail));

        let mut report = DemoReport::default();
        record_sandbox_outcome(
            &mut report,
            Err("sandboxing is not supported on this platform".to_string()),
        );
        assert_eq!(report.checks[0].status, DemoStatus::Skip);

        let mut report = DemoReport::default();
        record_sandbox_outcome(&mut report, Err("boom".to_string()));
        assert_eq!(report.checks[0].status, DemoStatus::Fail);
        assert_eq!(report.checks[0].detail, "boom");
    }

    #[test]
    fn run_sandbox_probe_serializes_results() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowed_read = dir.path().join("allowed.txt");
        let allowed_write = dir.path().join("allowed-write.txt");
        let blocked_read = dir.path().join("blocked.txt");
        let result_file = dir.path().join("probe-result.json");
        fs::write(&allowed_read, "hello").expect("write allowed read");
        fs::write(&blocked_read, "secret").expect("write blocked read");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let args = SandboxProbeArgs {
            allowed_read,
            allowed_write: allowed_write.clone(),
            blocked_read,
            result_file: Some(result_file.clone()),
            network_host: "127.0.0.1".to_string(),
            network_port: listener.local_addr().expect("listener addr").port(),
        };

        run_sandbox_probe(args).expect("sandbox probe run");
        assert!(allowed_write.exists());
        assert!(result_file.exists());
    }
}
