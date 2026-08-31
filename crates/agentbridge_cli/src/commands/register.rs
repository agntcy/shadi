use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use a2a::event::StreamResponse;
use a2a::*;
use a2a_server::{
    AgentExecutor, DefaultRequestHandler, InMemoryTaskStore, RequestHandler,
    ServiceParams as A2AServiceParams,
};
use agentbridge::{
    adapters::{
        claude_code::ClaudeCodeAdapter,
        codex::CodexAdapter,
        copilot::CopilotAdapter,
        generic_stdio::GenericStdioAdapter,
    },
    dir_registry::DirError,
    CliAdapter,
};
use async_trait::async_trait;
use futures::stream::BoxStream;
use shadi_a2a::SlimRpcHandler;
use slim_bindings::{
    CaSource, ClientConfig, Name, Service, TlsClientConfig, TlsSource,
};
use slim_rpc::Server;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::Notify;

/// Agent Directory server + auth to publish this adapter's `AgentCard` to.
pub struct DirPublishOptions<'a> {
    pub server: &'a str,
    pub gh_token: Option<&'a str>,
}

/// Start a registered adapter server for a named tool.
///
/// When `slim_endpoint` is provided the adapter is also exposed as an A2A
/// service over SLIMRPC, reachable at `agntcy/shadi/<tool>-a2a`. When
/// `dir_publish` is provided, the adapter's real `AgentCard` — with its SLIM
/// endpoint and DID, if a SLIM listener is running — is published to the
/// Agent Directory before the adapter starts serving.
pub fn run(
    tool: &str,
    command: Option<&str>,
    args: &[String],
    agent_id: Option<&str>,
    slim_endpoint: Option<&str>,
    dir_publish: Option<DirPublishOptions>,
) -> anyhow::Result<()> {
    let id = agent_id.unwrap_or(tool);
    match tool {
        "generic-stdio" => {
            let command = command.ok_or_else(|| {
                anyhow::anyhow!("--command is required for tool type 'generic-stdio'")
            })?;
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let adapter = Arc::new(GenericStdioAdapter::spawn(id, command, &args_ref)?);
            println!("Registered adapter '{}' (agent id: {})", tool, adapter.agent_id().0);
            if let Some(endpoint) = slim_endpoint {
                println!("Starting SLIM A2A listener on {endpoint} as agntcy/shadi/{id}-a2a ...");
                run_slim_listener(id, adapter, endpoint, dir_publish.as_ref())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            } else {
                if let Some(opts) = dir_publish.as_ref() {
                    publish_card_to_dir(id, None, best_effort_did(id).as_deref(), opts)?;
                }
                println!("Adapter is running. Press Ctrl-C to stop.");
                std::thread::park();
            }
        }
        "claude-code" => {
            let work_dir = command
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = Arc::new(ClaudeCodeAdapter::new(id, &work_dir));
            println!(
                "Registered Claude Code adapter (agent id: {}, dir: {})",
                adapter.agent_id().0,
                work_dir.display()
            );
            if let Some(endpoint) = slim_endpoint {
                println!("Starting SLIM A2A listener on {endpoint} as agntcy/shadi/{id}-a2a ...");
                run_slim_listener(id, adapter, endpoint, dir_publish.as_ref())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            } else {
                if let Some(opts) = dir_publish.as_ref() {
                    publish_card_to_dir(id, None, best_effort_did(id).as_deref(), opts)?;
                }
                println!("Adapter ready. Use 'agentbridge handoff' or 'agentbridge coordinate'.");
            }
        }
        "copilot" => {
            let work_dir = command
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = Arc::new(CopilotAdapter::new(id, work_dir));
            println!("Registered Copilot adapter (agent id: {})", adapter.agent_id().0);
            if let Some(endpoint) = slim_endpoint {
                println!("Starting SLIM A2A listener on {endpoint} as agntcy/shadi/{id}-a2a ...");
                run_slim_listener(id, adapter, endpoint, dir_publish.as_ref())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            } else {
                if let Some(opts) = dir_publish.as_ref() {
                    publish_card_to_dir(id, None, best_effort_did(id).as_deref(), opts)?;
                }
                println!("Adapter ready. Use 'agentbridge handoff' or 'agentbridge coordinate'.");
            }
        }
        "codex" => {
            let work_dir = command
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = Arc::new(CodexAdapter::new(id, work_dir));
            println!("Registered Codex adapter (agent id: {})", adapter.agent_id().0);
            if let Some(endpoint) = slim_endpoint {
                println!("Starting SLIM A2A listener on {endpoint} as agntcy/shadi/{id}-a2a ...");
                run_slim_listener(id, adapter, endpoint, dir_publish.as_ref())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            } else {
                if let Some(opts) = dir_publish.as_ref() {
                    publish_card_to_dir(id, None, best_effort_did(id).as_deref(), opts)?;
                }
                println!("Adapter ready. Use 'agentbridge handoff' or 'agentbridge coordinate'.");
            }
        }
        other => {
            anyhow::bail!(
                "Unknown tool type '{}'. Supported: generic-stdio, claude-code, copilot, codex.",
                other
            );
        }
    }
    Ok(())
}

/// Best-effort DID for `agent_id` when no SLIM listener is running to supply
/// one: `Some(did)` iff DID auth is actually configured in the environment,
/// `None` otherwise (the card is then published without an `authors` entry).
fn best_effort_did(agent_id: &str) -> Option<String> {
    match shadi_identity::did_auth_from_env(agent_id) {
        Some(Ok(shadi_identity::SlimAuth::Did { did, .. })) => Some(did),
        _ => None,
    }
}

// ─── SLIM A2A listener ────────────────────────────────────────────────────────

struct AgentBridgeExecutor {
    adapter: Arc<dyn CliAdapter>,
}

#[allow(dead_code)]
fn preview(s: &str, max: usize) -> String {
    let first_line = s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s);
    if first_line.len() > max {
        format!("{}…", &first_line[..max])
    } else {
        first_line.to_string()
    }
}

/// Print the full text of a recv/send body, one "│  " prefixed line at a
/// time — unlike `preview` (kept for anyone still calling it directly),
/// this never truncates. A single-line first-sentence preview was hiding
/// the rest of every multi-line reply (e.g. a full CONCORD certificate),
/// which is the whole point of watching this log.
fn print_full(s: &str) {
    if s.is_empty() {
        println!("│  (empty)");
        return;
    }
    for line in s.lines() {
        println!("│  {line}");
    }
}

#[async_trait]
impl AgentExecutor for AgentBridgeExecutor {
    fn execute(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let raw = ctx
            .message
            .as_ref()
            .map(extract_text)
            .unwrap_or_else(|| "(no prompt)".to_string());

        // Extract the body from the task envelope rendered by render_task_message().
        let prompt = raw
            .split_once("\nbody:\n")
            .map(|(_, body)| body)
            .unwrap_or(&raw)
            .to_string();

        let agent_id = self.adapter.agent_id().0.clone();
        println!(
            "\n┌─ A2A recv [{agent_id}] task {}",
            ctx.task_id
        );
        print_full(&prompt);
        println!("└─────────────────────────────────────────────────────────");

        let started = std::time::Instant::now();
        let response_text = match self.adapter.execute_prompt(&prompt) {
            Ok(text) => text,
            Err(e) => format!("agentbridge error: {e}"),
        };
        let elapsed_ms = started.elapsed().as_millis();

        println!(
            "\n┌─ A2A send [{agent_id}] ({} ms)",
            elapsed_ms
        );
        print_full(&response_text);
        println!("└─────────────────────────────────────────────────────────\n");

        let response = Message {
            message_id: new_message_id(),
            context_id: Some(ctx.context_id.clone()),
            task_id: Some(ctx.task_id.clone()),
            role: Role::Agent,
            parts: vec![Part::text(response_text)],
            metadata: None,
            extensions: None,
            reference_task_ids: None,
        };
        let history = ctx.message.clone().map(|m| vec![m]);

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

    fn cancel(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
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

struct AgentBridgeRequestHandler {
    inner: DefaultRequestHandler,
    ready: Arc<Notify>,
    agent_id: String,
    slim_endpoint: Option<String>,
}

impl AgentBridgeRequestHandler {
    fn new(
        adapter: Arc<dyn CliAdapter>,
        agent_id: &str,
        slim_endpoint: Option<&str>,
        ready: Arc<Notify>,
    ) -> Self {
        Self {
            inner: DefaultRequestHandler::new(
                AgentBridgeExecutor { adapter },
                InMemoryTaskStore::new(),
            ),
            ready,
            agent_id: agent_id.to_string(),
            slim_endpoint: slim_endpoint.map(str::to_string),
        }
    }
}

#[async_trait]
impl RequestHandler for AgentBridgeRequestHandler {
    async fn send_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        self.ready.notify_waiters();
        self.inner.send_message(params, req).await
    }

    async fn send_streaming_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.ready.notify_waiters();
        self.inner.send_streaming_message(params, req).await
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
        req: TaskPushNotificationConfig,
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
        Ok(build_agent_card(&self.agent_id, self.slim_endpoint.as_deref()))
    }
}

/// Build the real, connectable `AgentCard` for an agentbridge adapter.
///
/// Used both to answer local `get_extended_agent_card` A2A calls and as the
/// card published to the Agent Directory — one source of truth for what
/// this adapter's card looks like.
fn build_agent_card(agent_id: &str, slim_endpoint: Option<&str>) -> AgentCard {
    let supported_interfaces = match slim_endpoint {
        Some(endpoint) => vec![AgentInterface::new(
            format!("slim://{endpoint}/agntcy/shadi/{agent_id}-a2a"),
            TRANSPORT_PROTOCOL_SLIMRPC,
        )],
        None => Vec::new(),
    };

    AgentCard {
        name: agent_id.to_string(),
        description: format!(
            "agentbridge adapter for '{agent_id}'. Supports context handoff, \
             task delegation, and autonomous code coordination."
        ),
        version: env!("CARGO_PKG_VERSION").to_string(),
        supported_interfaces,
        capabilities: AgentCapabilities {
            streaming: Some(true),
            push_notifications: Some(false),
            extensions: None,
            extended_agent_card: Some(false),
        },
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["text/plain".to_string()],
        skills: default_skills(),
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: None,
        security_requirements: None,
        signatures: None,
    }
}

/// The standard agentbridge skill set: task delegation, agent coordination,
/// and generating output. Shared by every adapter's `AgentCard`. Each `id` is
/// a real OASF skill taxonomy class (confirmed against a live Directory's
/// schema validator) — arbitrary strings are rejected by `dirctl push`.
fn default_skills() -> Vec<AgentSkill> {
    [
        (
            "agent_orchestration/task_decomposition",
            "Breaks down and delegates coding tasks to other coding agents.",
        ),
        (
            "agent_orchestration/agent_coordination",
            "Coordinates and hands off task context between coding agents.",
        ),
        (
            "natural_language_processing/natural_language_generation/text_completion",
            "Generates code and text completions on request.",
        ),
    ]
    .into_iter()
    .map(|(id, description)| AgentSkill {
        id: id.to_string(),
        name: id.to_string(),
        description: description.to_string(),
        tags: Vec::new(),
        examples: None,
        input_modes: None,
        output_modes: None,
        security_requirements: None,
    })
    .collect()
}

/// Require that this process is running under a SHADI sandbox with network
/// blocked by default before it may expose a remote-reachable listener.
///
/// Seatbelt (macOS), Landlock (Linux), and AppContainer + Job Objects
/// (Windows) sandboxes are all kernel-enforced and inherited by descendant
/// processes, so wrapping `agentbridge register` in `shadictl`'s sandbox is
/// enough to constrain whatever CLI tool an adapter spawns to run a task —
/// no sandboxing code is needed in agentbridge itself. See
/// [`shadi_sandbox::sandbox_enforced_from_env`].
fn require_sandbox_enforced(agent_id: &str, endpoint: &str) -> Result<(), String> {
    if shadi_sandbox::sandbox_enforced_from_env() {
        return Ok(());
    }
    // Explicit, opt-in escape hatch — NOT the default. Added for a
    // loopback-only local demo where a corporate endpoint-security agent
    // was silently blackholing network traffic from Seatbelt-sandboxed
    // child processes (confirmed via SHADI_DEBUG_SANDBOX that the Seatbelt
    // policy itself was correctly wide-open; the interference was outside
    // shadi_sandbox entirely). Anyone relying on the sandbox guarantee
    // should not set this.
    if std::env::var_os("AGENTBRIDGE_ALLOW_UNSANDBOXED_REGISTER").is_some() {
        eprintln!(
            "⚠️  AGENTBRIDGE_ALLOW_UNSANDBOXED_REGISTER set — running WITHOUT a SHADI sandbox. \
             This listener's incoming A2A tasks will execute with no containment. Only use this \
             for a trusted, loopback-only mesh."
        );
        return Ok(());
    }
    Err(format!(
        "agentbridge register --slim-endpoint requires running under a SHADI sandbox with \
         network blocked by default — a remote-reachable listener must not execute tasks \
         unsandboxed. Launch as:\n\n  \
         shadictl --net-block --net-allow {endpoint} -- agentbridge register --tool {agent_id} \
         --slim-endpoint {endpoint} ...\n"
    ))
}

/// Start a SLIM A2A listener that forwards incoming tasks to `adapter`.
///
/// Listens indefinitely under `agntcy/shadi/<agent_id>-a2a` until Ctrl-C.
/// Coding-agent adapters authenticate via DID/keys only — see
/// [`shadi_identity::require_did_auth_from_env`].
fn run_slim_listener(
    agent_id: &str,
    adapter: Arc<dyn CliAdapter>,
    endpoint: &str,
    dir_publish: Option<&DirPublishOptions>,
) -> Result<(), String> {
    let agent_name = format!("agntcy/shadi/{agent_id}-a2a");

    require_sandbox_enforced(agent_id, endpoint)?;

    // Security posture: incoming A2A tasks are executed by the local CLI tool,
    // constrained by whatever SHADI sandbox policy wraps this process (required
    // above). Sandboxing bounds what a task CAN do; SLIM_MEMBER_DIDS still
    // decides WHO may send one — only expose this listener to trusted SLIM peers.
    eprintln!(
        "⚠️  Incoming A2A tasks on {agent_name} are executed by the local '{agent_id}' \
         CLI tool. Only expose this listener to trusted SLIM peers."
    );

    let tls = resolve_client_tls(Some(agent_id))?;

    let service = Service::new(format!("agentbridge-listener-{}-{}", agent_id, std::process::id()));
    let connection_id = service
        .connect(build_client_config(endpoint, &tls))
        .map_err(|e| format!("SLIM connect failed: {e:?}"))?;

    let name_ref = Arc::new(parse_name(&agent_name)?);
    let auth = shadi_identity::require_did_auth_from_env(agent_id)
        .map_err(|e| format!("SLIM auth error: {e}"))?;
    let app = shadi_identity::create_app(&service, name_ref.clone(), &auth)
        .map_err(|e| format!("SLIM create_app failed: {e:?}"))?;
    app.subscribe(name_ref.clone(), Some(connection_id))
        .map_err(|e| format!("SLIM subscribe failed: {e:?}"))?;

    if let Some(opts) = dir_publish {
        let did = match &auth {
            shadi_identity::SlimAuth::Did { did, .. } => Some(did.as_str()),
            shadi_identity::SlimAuth::SharedSecret(_) => None,
        };
        if let Err(e) = publish_card_to_dir(agent_id, Some(endpoint), did, opts) {
            eprintln!("[agentbridge] DIR publish failed: {e}");
        }
    }

    let server = Arc::new(Server::new_with_shared_rx_and_connection(
        app.inner(),
        app.name().as_slim_name(),
        None,
        app.notification_receiver(),
        Some(slim_bindings::get_runtime()),
    ));
    let ready = Arc::new(Notify::new());
    let handler = Arc::new(AgentBridgeRequestHandler::new(
        adapter,
        agent_id,
        Some(endpoint),
        ready,
    ));
    SlimRpcHandler::new(handler).register(server.as_ref());

    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    let result = runtime.block_on(async move {
        let srv = server.clone();
        let server_task = tokio::spawn(async move {
            srv.serve()
                .await
                .map_err(|e| format!("A2A SLIMRPC server error: {e}"))
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        println!("[agentbridge] ready — listening on {agent_name}");
        println!("[agentbridge] Press Ctrl-C to stop.");

        tokio::signal::ctrl_c()
            .await
            .map_err(|e| format!("ctrl_c error: {e}"))?;

        println!("\n[agentbridge] shutting down...");
        server.shutdown().await;
        let _ = server_task.await;
        Ok::<(), String>(())
    });

    let _ = app.unsubscribe(name_ref, Some(connection_id));
    let _ = service.disconnect(connection_id);
    let _ = service.shutdown();

    result
}

// ─── SLIM helper fns (mirrors shadi_mas::experiments internals) ───────────────

struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

fn resolve_client_tls(agent_id: Option<&str>) -> Result<TlsMaterial, String> {
    let cert_override = std::env::var_os("SLIM_TLS_CERT").map(PathBuf::from);
    let key_override = std::env::var_os("SLIM_TLS_KEY").map(PathBuf::from);
    let ca = std::env::var_os("SLIM_TLS_CA")
        .map(PathBuf::from)
        .unwrap_or_else(|| slim_tls_dir().join("ca.crt"));

    let (cert, key) = match (cert_override, key_override) {
        (Some(cert), Some(key)) => (cert, key),
        (Some(_), None) | (None, Some(_)) => {
            return Err("SLIM_TLS_CERT and SLIM_TLS_KEY must both be set".to_string());
        }
        (None, None) => {
            let base = slim_tls_dir();
            let candidates = if let Some(id) = agent_id {
                vec![
                    (base.join(format!("client-{id}.crt")), base.join(format!("client-{id}.key"))),
                    (base.join("client.crt"), base.join("client.key")),
                ]
            } else {
                vec![(base.join("client.crt"), base.join("client.key"))]
            };
            candidates
                .into_iter()
                .find(|(c, k)| c.is_file() && k.is_file())
                .ok_or_else(|| {
                    "no SLIM client certificate found; set SLIM_TLS_CERT and SLIM_TLS_KEY".to_string()
                })?
        }
    };

    Ok(TlsMaterial { cert, key, ca })
}

fn slim_tls_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp"))
        .join("shadi-slim-mtls")
}

fn build_client_config(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
    let endpoint_url = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    };
    let mut config = ClientConfig::default();
    config.endpoint = endpoint_url;
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

fn parse_name(name: &str) -> Result<Name, String> {
    Name::from_string(name.to_string()).map_err(|e| {
        format!("invalid SLIM name '{name}': {e} (expected org/namespace/agent)")
    })
}

fn extract_text(message: &Message) -> String {
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

// ─── DIR publish ──────────────────────────────────────────────────────────────

/// Publish `agent_id`'s real `AgentCard` — wrapped in DIR's `integration/a2a`
/// OASF module shape, with `did` (if known) as the record's `authors` entry —
/// to the Agent Directory.
fn publish_card_to_dir(
    agent_id: &str,
    slim_endpoint: Option<&str>,
    did: Option<&str>,
    opts: &DirPublishOptions,
) -> anyhow::Result<()> {
    let card = build_agent_card(agent_id, slim_endpoint);
    let card_json = serde_json::to_value(&card)?;
    let record = agentbridge::dir_registry::wrap_agent_card(&card_json, did);

    println!("Publishing AgentCard for '{agent_id}' to {}...", opts.server);
    match agentbridge::dir_registry::publish_record(&record, opts.server, opts.gh_token) {
        Ok(cid) => println!("Published. CID: {cid}"),
        Err(DirError::DirctlNotFound) => {
            println!("dirctl not found — skipping DIR publish.");
            println!("Install: brew tap agntcy/dir https://github.com/agntcy/dir/ && brew install dirctl");
        }
        Err(e) => anyhow::bail!("DIR publish failed: {e}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_sandbox_enforced_rejects_unsandboxed_and_permissive() {
        // These env vars are touched by no other test in this crate, so a single
        // sequential test needs no cross-test lock.
        std::env::remove_var(shadi_sandbox::SANDBOX_ACTIVE_ENV);
        std::env::remove_var(shadi_sandbox::SANDBOX_NET_BLOCKED_ENV);
        let err = require_sandbox_enforced("copilot", "127.0.0.1:47357")
            .expect_err("must reject when not running under any sandbox");
        assert!(err.contains("shadictl --net-block"));
        assert!(err.contains("--tool copilot"));
        assert!(err.contains("127.0.0.1:47357"));

        std::env::set_var(shadi_sandbox::SANDBOX_ACTIVE_ENV, "1");
        std::env::set_var(shadi_sandbox::SANDBOX_NET_BLOCKED_ENV, "0");
        assert!(
            require_sandbox_enforced("copilot", "127.0.0.1:47357").is_err(),
            "an active but network-permissive sandbox must still be rejected"
        );

        std::env::set_var(shadi_sandbox::SANDBOX_NET_BLOCKED_ENV, "1");
        assert!(require_sandbox_enforced("copilot", "127.0.0.1:47357").is_ok());

        std::env::remove_var(shadi_sandbox::SANDBOX_ACTIVE_ENV);
        std::env::remove_var(shadi_sandbox::SANDBOX_NET_BLOCKED_ENV);
    }

    #[test]
    fn preview_truncates_to_first_nonblank_line() {
        assert_eq!(preview("\n\nhello world", 5), "hello…");
        assert_eq!(preview("short", 20), "short");
    }

    #[test]
    fn extract_text_joins_parts_or_reports_empty() {
        let msg = Message::new(
            Role::User,
            vec![Part::text("a".to_string()), Part::text("b".to_string())],
        );
        assert_eq!(extract_text(&msg), "a b");
        let empty = Message::new(Role::User, vec![]);
        assert_eq!(extract_text(&empty), "(no text parts)");
    }

    #[test]
    fn parse_name_accepts_qualified_and_rejects_bare() {
        assert!(parse_name("agntcy/shadi/copilot-a2a").is_ok());
        assert!(parse_name("bare").is_err());
    }

    #[test]
    fn build_agent_card_sets_slim_interface_when_endpoint_given() {
        let card = build_agent_card("copilot", Some("127.0.0.1:47357"));
        assert_eq!(card.name, "copilot");
        assert_eq!(card.supported_interfaces.len(), 1);
        let iface = &card.supported_interfaces[0];
        assert_eq!(iface.protocol_binding, TRANSPORT_PROTOCOL_SLIMRPC);
        assert_eq!(iface.url, "slim://127.0.0.1:47357/agntcy/shadi/copilot-a2a");
    }

    #[test]
    fn build_agent_card_has_no_interfaces_without_endpoint() {
        let card = build_agent_card("copilot", None);
        assert!(card.supported_interfaces.is_empty());
    }

    #[test]
    fn build_agent_card_includes_default_skills() {
        let card = build_agent_card("codex", None);
        assert_eq!(card.skills.len(), 3);
        assert!(card.skills.iter().any(|s| s.id.contains("task_decomposition")));
        assert!(card.skills.iter().any(|s| s.id.contains("agent_coordination")));
        assert!(card.skills.iter().any(|s| s.id.contains("text_completion")));
    }

    #[test]
    fn slim_tls_dir_ends_with_mtls_subdir() {
        assert!(slim_tls_dir().ends_with("shadi-slim-mtls"));
    }

    #[test]
    fn build_client_config_prefixes_https_and_sets_tls() {
        let tls = TlsMaterial {
            cert: PathBuf::from("/c"),
            key: PathBuf::from("/k"),
            ca: PathBuf::from("/a"),
        };
        let cfg = build_client_config("node:1", &tls);
        assert_eq!(cfg.endpoint, "https://node:1");
        assert_eq!(cfg.tls.tls_version, "tls1.3");
        assert!(!cfg.tls.insecure);
        assert!(build_client_config("https://node:1", &tls)
            .endpoint
            .starts_with("https://"));
    }
}
