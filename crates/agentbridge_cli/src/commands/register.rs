use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use a2a::event::StreamResponse;
use a2a::*;
use a2a_grpc::GrpcHandler;
use a2a_pb::proto::a2a_service_server::A2aServiceServer;
use a2a_server::{
    DefaultRequestHandler, InMemoryTaskStore, RequestHandler,
    ServiceParams as A2AServiceParams,
};
use agentbridge::{
    adapters::{
        generic_stdio::GenericStdioAdapter,
        profile::{bundled_profile_ids, load_profile, ProfileAdapter},
    },
    dir_registry::DirError,
    local_registry::{LocalAdapterRecord, LocalAdapterRegistry},
    CliAdapter,
    executor::AgentBridgeExecutor,
};
use async_trait::async_trait;
use futures::stream::BoxStream;
use shadi_a2a::{A2ABinding, SlimRpcHandler};
use slim_bindings::{CaSource, ClientConfig, Name, Service, TlsClientConfig, TlsSource};
use slim_rpc::Server;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::Notify;
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server as TonicServer;

/// Agent Directory server + auth to publish this adapter's `AgentCard` to.
pub struct DirPublishOptions<'a> {
    pub server: &'a str,
    pub gh_token: Option<&'a str>,
}

/// Start a registered adapter server for a named tool.
///
/// When `slim_endpoint` is provided the adapter is also exposed as an A2A
/// service over SLIMRPC, reachable at `agntcy/shadi/<tool>-a2a`. When
/// `a2a_listen` is provided it is exposed on an official A2A unicast binding
/// (`grpc`, `jsonrpc`, or `http+json`) at that `host:port`. When `dir_publish`
/// is provided, the adapter's real `AgentCard` is published to the Agent
/// Directory before the adapter starts serving.
pub fn run(
    tool: &str,
    command: Option<&str>,
    args: &[String],
    slim_endpoint: Option<&str>,
    a2a_listen: Option<&str>,
    a2a_binding: A2ABinding,
    dir_publish: Option<DirPublishOptions>,
    verbose: bool,
) -> anyhow::Result<()> {
    // Coding CLIs are JSON profiles (`ProfileAdapter`). Native modules stay
    // for local handoff/coordinate; register no longer constructs them.
    if tool != "generic-stdio" {
        if let Some(profile) = load_profile(tool).map_err(|e| anyhow::anyhow!("{e}"))? {
            let work_dir = register_work_dir(command);
            let id = profile.id.clone();
            let adapter = Arc::new(ProfileAdapter::new(profile, work_dir.clone()));
            println!(
                "Registered {id} adapter from profile (agent id: {}, dir: {})",
                adapter.agent_id().0,
                work_dir.display()
            );
            return serve_registered(
                &id,
                adapter,
                slim_endpoint,
                a2a_listen,
                a2a_binding,
                dir_publish,
                verbose,
            );
        }
    }

    match tool {
        "generic-stdio" => {
            let command = command.ok_or_else(|| {
                anyhow::anyhow!("--command is required for tool type 'generic-stdio'")
            })?;
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let adapter = Arc::new(GenericStdioAdapter::spawn(tool, command, &args_ref)?);
            println!(
                "Registered adapter '{}' (agent id: {})",
                tool,
                adapter.agent_id().0
            );
            if slim_endpoint.is_some() || a2a_listen.is_some() {
                start_listeners(
                    tool,
                    adapter,
                    slim_endpoint,
                    a2a_listen,
                    a2a_binding,
                    dir_publish,
                    verbose,
                )?;
            } else {
                if let Some(opts) = dir_publish.as_ref() {
                    publish_card_to_dir(
                        tool,
                        None,
                        None,
                        A2ABinding::Grpc,
                        best_effort_did(tool).as_deref(),
                        opts,
                    )?;
                }
                println!("Adapter is running. Press Ctrl-C to stop.");
                std::thread::park();
            }
        }
        other => {
            anyhow::bail!(
                "Unknown tool type '{other}'. Bundled profiles: {}. Also: generic-stdio. \
                 Or drop {{name}}.json in AGENTBRIDGE_PROFILES_DIR.",
                bundled_profile_ids().join(", ")
            );
        }
    }
    Ok(())
}

fn register_work_dir(command: Option<&str>) -> PathBuf {
    command
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()))
}

fn serve_registered(
    tool: &str,
    adapter: Arc<dyn CliAdapter>,
    slim_endpoint: Option<&str>,
    a2a_listen: Option<&str>,
    a2a_binding: A2ABinding,
    dir_publish: Option<DirPublishOptions>,
    verbose: bool,
) -> anyhow::Result<()> {
    if slim_endpoint.is_none() && a2a_listen.is_none() {
        if let Some(opts) = dir_publish.as_ref() {
            publish_card_to_dir(
                tool,
                None,
                None,
                a2a_binding,
                best_effort_did(tool).as_deref(),
                opts,
            )?;
        }
        println!("Adapter ready. Use 'agentbridge handoff' or 'agentbridge coordinate'.");
        return Ok(());
    }
    start_listeners(
        tool,
        adapter,
        slim_endpoint,
        a2a_listen,
        a2a_binding,
        dir_publish,
        verbose,
    )
}

fn start_listeners(
    tool: &str,
    adapter: Arc<dyn CliAdapter>,
    slim_endpoint: Option<&str>,
    a2a_listen: Option<&str>,
    a2a_binding: A2ABinding,
    dir_publish: Option<DirPublishOptions>,
    verbose: bool,
) -> anyhow::Result<()> {
    if let Some(listen) = a2a_listen {
        println!(
            "Starting A2A {} listener on {listen} ...",
            a2a_binding.as_protocol_binding()
        );
        if slim_endpoint.is_some() {
            let http_adapter = Arc::clone(&adapter);
            let http_tool = tool.to_string();
            let http_listen = listen.to_string();
            std::thread::spawn(move || {
                if let Err(err) = run_unicast_listener(
                    &http_tool,
                    http_adapter,
                    &http_listen,
                    a2a_binding,
                    None,
                    false,
                    verbose,
                ) {
                    eprintln!("[agentbridge] {} listener: {err}", a2a_binding.as_protocol_binding());
                }
            });
        } else {
            run_unicast_listener(
                tool,
                adapter,
                listen,
                a2a_binding,
                dir_publish.as_ref(),
                true,
                verbose,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            return Ok(());
        }
    }
    if let Some(endpoint) = slim_endpoint {
        println!("Starting SLIM A2A listener on {endpoint} as agntcy/shadi/{tool}-a2a ...");
        run_slim_listener(
            tool,
            adapter,
            endpoint,
            a2a_listen,
            a2a_binding,
            dir_publish.as_ref(),
            verbose,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
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

struct AgentBridgeRequestHandler {
    inner: DefaultRequestHandler,
    ready: Arc<Notify>,
    agent_id: String,
    slim_endpoint: Option<String>,
    a2a_listen: Option<String>,
    a2a_binding: A2ABinding,
}

impl AgentBridgeRequestHandler {
    fn new(
        adapter: Arc<dyn CliAdapter>,
        agent_id: &str,
        agent_did: Option<&str>,
        slim_endpoint: Option<&str>,
        a2a_listen: Option<&str>,
        a2a_binding: A2ABinding,
        ready: Arc<Notify>,
        verbose: bool,
    ) -> Self {
        Self {
            inner: DefaultRequestHandler::new(
                AgentBridgeExecutor::new(
                    adapter,
                    agent_did.filter(|did| !did.is_empty()).map(str::to_string),
                    slim_endpoint.map(str::to_string),
                    verbose,
                ),
                InMemoryTaskStore::new(),
            ),
            ready,
            agent_id: agent_id.to_string(),
            slim_endpoint: slim_endpoint.map(str::to_string),
            a2a_listen: a2a_listen.map(str::to_string),
            a2a_binding,
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
        // Admission is the executor's job now: the handler creates the task
        // before calling it, so a message that fails the DID gate still leaves
        // a task the client can fetch and resume.
        self.inner.send_message(params, req).await
    }

    async fn send_streaming_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.ready.notify_waiters();
        // See send_message: the executor gates the message, so the task exists
        // in the store either way.
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
        Ok(build_agent_card(
            &self.agent_id,
            self.slim_endpoint.as_deref(),
            self.a2a_listen.as_deref(),
            self.a2a_binding,
        ))
    }
}

/// Build the real, connectable `AgentCard` for an agentbridge adapter.
///
/// Used both to answer local `get_extended_agent_card` A2A calls and as the
/// card published to the Agent Directory — one source of truth for what
/// this adapter's card looks like.
fn build_agent_card(
    agent_id: &str,
    slim_endpoint: Option<&str>,
    a2a_listen: Option<&str>,
    a2a_binding: A2ABinding,
) -> AgentCard {
    let mut supported_interfaces = Vec::new();
    if let Some(endpoint) = slim_endpoint {
        supported_interfaces.push(AgentInterface::new(
            format!("slim://{endpoint}/agntcy/shadi/{agent_id}-a2a"),
            TRANSPORT_PROTOCOL_SLIMRPC,
        ));
    }
    if let Some(listen) = a2a_listen {
        let url = if listen.contains("://") {
            listen.to_string()
        } else {
            format!("http://{listen}")
        };
        supported_interfaces.push(AgentInterface::new(
            url,
            a2a_binding.as_protocol_binding(),
        ));
    }

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
    Err(format!(
        "agentbridge register --slim-endpoint / --a2a-listen requires running under a SHADI sandbox with \
         network blocked by default — a remote-reachable listener must not execute tasks \
         unsandboxed. Launch as:\n\n  \
         shadictl --net-block --net-allow {endpoint} -- agentbridge register --tool {agent_id} \
         --slim-endpoint {endpoint} ...\n  \
         or: shadictl --net-block --net-allow {endpoint} -- agentbridge register --tool {agent_id} \
         --a2a-listen {endpoint} ...\n"
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
    a2a_listen: Option<&str>,
    a2a_binding: A2ABinding,
    dir_publish: Option<&DirPublishOptions>,
    verbose: bool,
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

    let service = Service::new(format!(
        "agentbridge-listener-{}-{}",
        agent_id,
        std::process::id()
    ));
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

    let did = match &auth {
        shadi_identity::SlimAuth::Did { did, .. } => did.clone(),
        shadi_identity::SlimAuth::SharedSecret(_) => String::new(),
    };
    let _local_lease = if did.is_empty() {
        None
    } else {
        match agentbridge::local_registry::LocalAdapterRegistry::from_env().publish(
            &agentbridge::local_registry::LocalAdapterRecord {
                name: agent_id.to_string(),
                did: did.clone(),
                slim_endpoint: endpoint.to_string(),
                a2a_url: a2a_listen
                    .map(advertised_a2a_url)
                    .unwrap_or_default(),
                a2a_binding,
                pid: std::process::id(),
            },
        ) {
            Ok(lease) => Some(lease),
            Err(err) => {
                eprintln!("[agentbridge] local registry: {err}");
                None
            }
        }
    };

    if let Some(opts) = dir_publish {
        let did = match &auth {
            shadi_identity::SlimAuth::Did { did, .. } => Some(did.as_str()),
            shadi_identity::SlimAuth::SharedSecret(_) => None,
        };
        if let Err(e) = publish_card_to_dir(agent_id, Some(endpoint), a2a_listen, a2a_binding, did, opts) {
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
    // Cloned before the move below so shutdown can still reach the adapter
    // to kill whatever child process its current message is running.
    let adapter_for_shutdown = Arc::clone(&adapter);
    let handler = Arc::new(AgentBridgeRequestHandler::new(
        adapter,
        agent_id,
        (!did.is_empty()).then_some(did.as_str()),
        Some(endpoint),
        a2a_listen,
        a2a_binding,
        ready,
        verbose,
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
        // Proactively kill whatever child process the adapter's current
        // message is running, if any. Without this, a `claude` call still
        // in flight when Ctrl-C arrives is left orphaned: the listener
        // itself exits promptly (see the spawn_blocking fix above), but
        // nothing ever tells the child to stop, so it just keeps running
        // on its own after the parent that owned it is gone.
        adapter_for_shutdown.kill_in_flight();
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
                    (
                        base.join(format!("client-{id}.crt")),
                        base.join(format!("client-{id}.key")),
                    ),
                    (base.join("client.crt"), base.join("client.key")),
                ]
            } else {
                vec![(base.join("client.crt"), base.join("client.key"))]
            };
            candidates
                .into_iter()
                .find(|(c, k)| c.is_file() && k.is_file())
                .ok_or_else(|| {
                    "no SLIM client certificate found; set SLIM_TLS_CERT and SLIM_TLS_KEY"
                        .to_string()
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

fn slim_client_endpoint(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    }
}

fn build_client_config(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
    let endpoint_url = slim_client_endpoint(endpoint);
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
    Name::from_string(name.to_string())
        .map_err(|e| format!("invalid SLIM name '{name}': {e} (expected org/namespace/agent)"))
}

/// A single-task stream in `state`, carrying `reason` as the agent's message.
///
/// Emitted as `StreamResponse::Task`, which the handler persists, so the task
/// the client is told about exists in the store — `AuthRequired` is
/// non-terminal in the protocol and has to be fetchable to be resumed.
fn a2a_tls_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("shadi-a2a-tls")
}

fn is_loopback_addr(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

fn advertised_a2a_url(listen: &str) -> String {
    if listen.contains("://") {
        return listen.to_string();
    }
    match listen.parse::<SocketAddr>() {
        Ok(addr) if is_loopback_addr(&addr) => format!("http://{addr}"),
        Ok(addr) => format!("https://{addr}"),
        Err(_) => format!("http://{listen}"),
    }
}

fn a2a_server_tls_paths(addr: &SocketAddr) -> Result<Option<(PathBuf, PathBuf)>, String> {
    if is_loopback_addr(addr) {
        return Ok(None);
    }
    let cert = std::env::var_os("A2A_TLS_CERT")
        .map(PathBuf::from)
        .unwrap_or_else(|| a2a_tls_dir().join("server.crt"));
    let key = std::env::var_os("A2A_TLS_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| a2a_tls_dir().join("server.key"));
    if !cert.is_file() || !key.is_file() {
        return Err(format!(
            "non-loopback --a2a-listen {addr} requires TLS 1.3. Set A2A_TLS_CERT and A2A_TLS_KEY \
             (PEM files), or place server.crt/server.key under $SHADI_TMP_DIR/shadi-a2a-tls. \
             Do not reuse SLIM_TLS_*. Loopback http://127.0.0.1 is allowed without certificates."
        ));
    }
    Ok(Some((cert, key)))
}

/// rustls + tonic-tls, not tonic `ServerTlsConfig`. Enabling tonic's native TLS
/// feature (`_tls-any`) makes SLIM `https://` clients fail under workspace tests.
fn grpc_server_tls_config(
    addr: &SocketAddr,
) -> Result<Option<Arc<a2a_grpc::rustls::ServerConfig>>, String> {
    let Some((cert, key)) = a2a_server_tls_paths(addr)? else {
        return Ok(None);
    };
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let cert_pem = fs::read(&cert).map_err(|e| format!("read A2A_TLS_CERT {}: {e}", cert.display()))?;
    let key_pem = fs::read(&key).map_err(|e| format!("read A2A_TLS_KEY {}: {e}", key.display()))?;
    // rustls-pki-types ≥ 1.9 `PemObject` replaces archived rustls-pemfile
    // (RUSTSEC-2025-0134). Certs stay on disk via A2A_TLS_CERT / A2A_TLS_KEY.
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse A2A_TLS_CERT {}: {e}", cert.display()))?;
    if certs.is_empty() {
        return Err(format!("A2A_TLS_CERT {} has no certificates", cert.display()));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| {
        if matches!(e, rustls_pki_types::pem::Error::NoItemsFound) {
            format!("A2A_TLS_KEY {} has no private key", key.display())
        } else {
            format!("parse A2A_TLS_KEY {}: {e}", key.display())
        }
    })?;
    let mut config = a2a_grpc::rustls::ServerConfig::builder_with_protocol_versions(&[
        &a2a_grpc::rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| format!("A2A gRPC TLS identity: {e}"))?;
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];
    Ok(Some(Arc::new(config)))
}

fn run_unicast_listener(
    agent_id: &str,
    adapter: Arc<dyn CliAdapter>,
    listen: &str,
    a2a_binding: A2ABinding,
    dir_publish: Option<&DirPublishOptions>,
    register_locally: bool,
    verbose: bool,
) -> Result<(), String> {
    require_sandbox_enforced(agent_id, listen)?;
    let addr: SocketAddr = listen.parse().map_err(|e| {
        format!("invalid --a2a-listen '{listen}' (expected host:port): {e}")
    })?;

    let auth = shadi_identity::require_did_auth_from_env(agent_id)
        .map_err(|e| format!("A2A {} auth error: {e}", a2a_binding.as_protocol_binding()))?;
    let did = match &auth {
        shadi_identity::SlimAuth::Did { did, .. } => did.clone(),
        shadi_identity::SlimAuth::SharedSecret(_) => {
            return Err(format!(
                "A2A {} listen requires an agent DID (SHADI_SLIM_AUTH=did); shared-secret node auth is not enough",
                a2a_binding.as_protocol_binding()
            ));
        }
    };

    let a2a_url = advertised_a2a_url(listen);

    eprintln!(
        "⚠️  Incoming A2A tasks on {a2a_url} ({}) are executed by the local '{agent_id}' CLI tool. \
         Only expose this listener to trusted peers. Agent identity is the DID proof on the message, not TLS.",
        a2a_binding.as_protocol_binding()
    );

    let _local_lease = if register_locally {
        match LocalAdapterRegistry::from_env().publish(&LocalAdapterRecord {
            name: agent_id.to_string(),
            did: did.clone(),
            slim_endpoint: String::new(),
            a2a_url: a2a_url.clone(),
            a2a_binding,
            pid: std::process::id(),
        }) {
            Ok(lease) => Some(lease),
            Err(err) => {
                eprintln!("[agentbridge] local registry: {err}");
                None
            }
        }
    } else {
        None
    };

    if let Some(opts) = dir_publish {
        if let Err(e) =
            publish_card_to_dir(agent_id, None, Some(listen), a2a_binding, Some(did.as_str()), opts)
        {
            eprintln!("[agentbridge] DIR publish failed: {e}");
        }
    }

    let ready = Arc::new(Notify::new());
    let adapter_for_shutdown = Arc::clone(&adapter);
    let handler = Arc::new(AgentBridgeRequestHandler::new(
        adapter,
        agent_id,
        Some(did.as_str()),
        None,
        Some(listen),
        a2a_binding,
        ready,
        verbose,
    ));

    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    runtime.block_on(async move {
        println!(
            "[agentbridge] ready — A2A {} on {a2a_url}",
            a2a_binding.as_protocol_binding()
        );
        println!("[agentbridge] Press Ctrl-C to stop.");
        match a2a_binding {
            A2ABinding::Slim => {
                Err("SLIM uses --slim-endpoint, not --a2a-listen".to_string())
            }
            A2ABinding::Grpc => {
                let grpc_service = A2aServiceServer::new(GrpcHandler::new(handler));
                match grpc_server_tls_config(&addr)? {
                    Some(tls) => {
                        let incoming = TcpIncoming::bind(addr)
                            .map_err(|e| format!("bind A2A gRPC {addr}: {e}"))?;
                        let incoming = tonic_tls::rustls::TlsIncoming::new(incoming, tls);
                        tokio::select! {
                            result = TonicServer::builder()
                                .add_service(grpc_service)
                                .serve_with_incoming(incoming) => {
                                result.map_err(|e| format!("A2A gRPC server error: {e}"))
                            }
                            _ = tokio::signal::ctrl_c() => {
                                println!("\n[agentbridge] shutting down...");
                                adapter_for_shutdown.kill_in_flight();
                                Ok(())
                            }
                        }
                    }
                    None => {
                        tokio::select! {
                            result = TonicServer::builder()
                                .add_service(grpc_service)
                                .serve(addr) => {
                                result.map_err(|e| format!("A2A gRPC server error: {e}"))
                            }
                            _ = tokio::signal::ctrl_c() => {
                                println!("\n[agentbridge] shutting down...");
                                adapter_for_shutdown.kill_in_flight();
                                Ok(())
                            }
                        }
                    }
                }
            }
            A2ABinding::Jsonrpc | A2ABinding::HttpJson => {
                let router = match a2a_binding {
                    A2ABinding::Jsonrpc => a2a_server::jsonrpc::jsonrpc_router(handler),
                    A2ABinding::HttpJson => a2a_server::rest::rest_router(handler),
                    A2ABinding::Grpc | A2ABinding::Slim => unreachable!(),
                };
                let router = with_agent_card(router, agent_id, listen, a2a_binding);
                tokio::select! {
                    result = serve_http_router(addr, router) => result,
                    _ = tokio::signal::ctrl_c() => {
                        println!("\n[agentbridge] shutting down...");
                        adapter_for_shutdown.kill_in_flight();
                        Ok(())
                    }
                }
            }
        }
    })
}

/// Serve the agent card at the well-known path alongside the RPC routes.
///
/// `get_extended_agent_card` answers the same card, but that is no help to a
/// client which has not yet learned what binding to speak: discovery by URL
/// goes through this path.
fn with_agent_card(
    router: axum::Router,
    agent_id: &str,
    listen: &str,
    a2a_binding: A2ABinding,
) -> axum::Router {
    let card = build_agent_card(agent_id, None, Some(listen), a2a_binding);
    router.merge(a2a_server::agent_card::agent_card_router(
        std::sync::Arc::new(a2a_server::StaticAgentCard::new(card)),
    ))
}

async fn serve_http_router(addr: SocketAddr, router: axum::Router) -> Result<(), String> {
    match a2a_server_tls_paths(&addr)? {
        None => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| format!("bind A2A HTTP {addr}: {e}"))?;
            axum::serve(listener, router)
                .await
                .map_err(|e| format!("A2A HTTP server error: {e}"))
        }
        Some((cert, key)) => {
            use a2a_server::tls::axum_server;
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| {
                    format!(
                        "A2A HTTP TLS from {} / {}: {e}",
                        cert.display(),
                        key.display()
                    )
                })?;
            axum_server::bind_rustls(addr, config)
                .serve(router.into_make_service())
                .await
                .map_err(|e| format!("A2A HTTPS server error: {e}"))
        }
    }
}

// ─── DIR publish ──────────────────────────────────────────────────────────────

/// Publish `agent_id`'s real `AgentCard` — wrapped in DIR's `integration/a2a`
/// OASF module shape, with `did` (if known) as the record's `authors` entry —
/// to the Agent Directory.
fn publish_card_to_dir(
    agent_id: &str,
    slim_endpoint: Option<&str>,
    a2a_listen: Option<&str>,
    a2a_binding: A2ABinding,
    did: Option<&str>,
    opts: &DirPublishOptions,
) -> anyhow::Result<()> {
    let card = build_agent_card(agent_id, slim_endpoint, a2a_listen, a2a_binding);
    let card_json = serde_json::to_value(&card)?;
    let record = agentbridge::dir_registry::wrap_agent_card(&card_json, did);

    println!(
        "Publishing AgentCard for '{agent_id}' to {}...",
        opts.server
    );
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
    fn unknown_tool_lists_profiles_and_generic_stdio() {
        let err = run("gemini", None, &[], None, None, A2ABinding::Grpc, None, false)
            .expect_err("no gemini profile");
        let msg = err.to_string();
        assert!(msg.contains("claude-code"));
        assert!(msg.contains("generic-stdio"));
        assert!(msg.contains("AGENTBRIDGE_PROFILES_DIR"));
    }

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

    fn sample_request(text: impl Into<String>) -> SendMessageRequest {
        SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text(text.into())]),
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }

    /// Minimal adapter: the parked and rejected paths never reach it.
    struct SilentAdapter(shadi_mas::AgentId);

    impl CliAdapter for SilentAdapter {
        fn agent_id(&self) -> &shadi_mas::AgentId {
            &self.0
        }
        fn snapshot_context(&self) -> Result<agentbridge::ContextPacket, agentbridge::CliAdapterError> {
            Err(agentbridge::CliAdapterError::Subprocess("not used".into()))
        }
        fn inject_context(&self, _: &agentbridge::ContextPacket) -> Result<(), agentbridge::CliAdapterError> {
            Ok(())
        }
        fn execute_prompt(&self, _: &str) -> Result<String, agentbridge::CliAdapterError> {
            panic!("a gated message must not reach the harness")
        }
    }

    fn silent_handler() -> AgentBridgeRequestHandler {
        AgentBridgeRequestHandler::new(
            Arc::new(SilentAdapter(shadi_mas::AgentId("claude-code".to_string()))),
            "claude-code",
            None,
            None,
            Some("127.0.0.1:4311"),
            A2ABinding::Jsonrpc,
            Arc::new(Notify::new()),
            false,
        )
    }

    #[tokio::test]
    async fn an_unsigned_message_parks_a_task_the_client_can_fetch() {
        let handler = silent_handler();
        let params = A2AServiceParams::default();

        let response = handler
            .send_message(&params, sample_request("plain task"))
            .await
            .expect("the gate parks rather than erroring");

        let task = match response {
            SendMessageResponse::Task(task) => task,
            SendMessageResponse::Message(m) => panic!("expected a task, got {m:?}"),
        };
        assert_eq!(task.status.state, TaskState::AuthRequired);

        // The point of the issue: a parked task has to exist in the store, or
        // the client is told about a task it cannot fetch or resume.
        let fetched = handler
            .get_task(
                &params,
                GetTaskRequest {
                    id: task.id.clone(),
                    history_length: None,
                    tenant: None,
                },
            )
            .await
            .expect("a parked task must be fetchable");
        assert_eq!(fetched.id, task.id);
        assert_eq!(fetched.status.state, TaskState::AuthRequired);
        assert_eq!(fetched.context_id, task.context_id);
    }

    #[tokio::test]
    async fn a_forged_did_is_rejected_as_a_stored_task() {
        let honest = shadi_identity::AgentIdentity::generate().unwrap();
        let impostor = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&honest, b"task").unwrap();
        let sig_line = {
            let text = String::from_utf8(envelope).unwrap();
            text.lines().nth(2).unwrap().to_string()
        };
        let forged = format!("SHADI-DID-PROOF/1\n{}\n{}\ntask", impostor.did(), sig_line);

        let handler = silent_handler();
        let params = A2AServiceParams::default();
        let response = handler
            .send_message(&params, sample_request(forged))
            .await
            .expect("rejection is a task state, not a transport error");
        let task = match response {
            SendMessageResponse::Task(task) => task,
            SendMessageResponse::Message(m) => panic!("expected a task, got {m:?}"),
        };
        assert_eq!(task.status.state, TaskState::Rejected);

        let fetched = handler
            .get_task(
                &params,
                GetTaskRequest {
                    id: task.id.clone(),
                    history_length: None,
                    tenant: None,
                },
            )
            .await
            .expect("a rejected task must be fetchable");
        assert_eq!(fetched.status.state, TaskState::Rejected);
    }

    #[tokio::test]
    async fn well_known_agent_card_matches_the_rpc_card() {
        use tower::ServiceExt;

        let listen = "127.0.0.1:4310";
        let binding = A2ABinding::Jsonrpc;
        let card = build_agent_card("claude-code", None, Some(listen), binding);

        // Through with_agent_card, which is what the listener calls, so this
        // fails if the mount is dropped rather than only if the library breaks.
        let router = with_agent_card(axum::Router::new(), "claude-code", listen, binding);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri(a2a_server::WELL_KNOWN_AGENT_CARD_PATH)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responds");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "well-known agent card must be served, not 404"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("card body");
        let served: serde_json::Value = serde_json::from_slice(&body).expect("card is JSON");
        let expected = serde_json::to_value(&card).expect("card serialises");
        assert_eq!(
            served, expected,
            "the served card must be the one get_extended_agent_card answers"
        );
    }

    #[test]
    fn parse_name_accepts_qualified_and_rejects_bare() {
        assert!(parse_name("agntcy/shadi/copilot-a2a").is_ok());
        assert!(parse_name("bare").is_err());
    }

    #[test]
    fn build_agent_card_sets_slim_interface_when_endpoint_given() {
        let card = build_agent_card("copilot", Some("127.0.0.1:47357"), None, A2ABinding::Grpc);
        assert_eq!(card.name, "copilot");
        assert_eq!(card.supported_interfaces.len(), 1);
        let iface = &card.supported_interfaces[0];
        assert_eq!(iface.protocol_binding, TRANSPORT_PROTOCOL_SLIMRPC);
        assert_eq!(iface.url, "slim://127.0.0.1:47357/agntcy/shadi/copilot-a2a");
    }

    #[test]
    fn build_agent_card_has_no_interfaces_without_endpoint() {
        let card = build_agent_card("copilot", None, None, A2ABinding::Grpc);
        assert!(card.supported_interfaces.is_empty());
    }

    #[test]
    fn build_agent_card_includes_default_skills() {
        let card = build_agent_card("codex", None, None, A2ABinding::Grpc);
        assert_eq!(card.skills.len(), 3);
        assert!(card
            .skills
            .iter()
            .any(|s| s.id.contains("task_decomposition")));
        assert!(card
            .skills
            .iter()
            .any(|s| s.id.contains("agent_coordination")));
        assert!(card.skills.iter().any(|s| s.id.contains("text_completion")));
    }

    #[test]
    fn build_agent_card_sets_grpc_interface_when_listen_given() {
        let card = build_agent_card(
            "copilot",
            None,
            Some("127.0.0.1:50051"),
            A2ABinding::Grpc,
        );
        assert_eq!(card.supported_interfaces.len(), 1);
        let iface = &card.supported_interfaces[0];
        assert_eq!(iface.protocol_binding, TRANSPORT_PROTOCOL_GRPC);
        // a2a-lf strips `http://` on GRPC interfaces (A2A card convention).
        assert_eq!(iface.url, "127.0.0.1:50051");
    }

    #[test]
    fn build_agent_card_sets_jsonrpc_interface_when_binding_given() {
        let card = build_agent_card(
            "copilot",
            None,
            Some("127.0.0.1:8080"),
            A2ABinding::Jsonrpc,
        );
        let iface = &card.supported_interfaces[0];
        assert_eq!(iface.protocol_binding, TRANSPORT_PROTOCOL_JSONRPC);
        assert!(iface.url.contains("127.0.0.1:8080"), "{}", iface.url);
    }

    #[test]
    fn advertised_a2a_url_uses_http_on_loopback_and_https_elsewhere() {
        assert_eq!(
            advertised_a2a_url("127.0.0.1:50051"),
            "http://127.0.0.1:50051"
        );
        assert_eq!(advertised_a2a_url("[::1]:50051"), "http://[::1]:50051");
        assert_eq!(
            advertised_a2a_url("0.0.0.0:50051"),
            "https://0.0.0.0:50051"
        );
        assert_eq!(
            advertised_a2a_url("https://example.test:443"),
            "https://example.test:443"
        );
    }

    /// `A2A_TLS_CERT` / `A2A_TLS_KEY` are process-global and
    /// `a2a_server_tls_paths` reads them inside the call under test, so these
    /// tests have to hold this across both the mutation and the call. Guarding
    /// only the mutation still lets a sibling's value reach the reader.
    static TLS_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn grpc_server_tls_loopback_is_plaintext() {
        let loopback: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(grpc_server_tls_config(&loopback).unwrap().is_none());
        let v6: SocketAddr = "[::1]:9".parse().unwrap();
        assert!(grpc_server_tls_config(&v6).unwrap().is_none());
    }

    #[test]
    fn grpc_server_tls_non_loopback_requires_cert_files() {
        let _guard = TLS_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let prev_cert = std::env::var_os("A2A_TLS_CERT");
        let prev_key = std::env::var_os("A2A_TLS_KEY");
        let prev_tmp = std::env::var_os("SHADI_TMP_DIR");
        std::env::remove_var("A2A_TLS_CERT");
        std::env::remove_var("A2A_TLS_KEY");
        let tmp = std::env::temp_dir().join(format!(
            "shadi-a2a-tls-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::create_dir_all(&tmp);
        std::env::set_var("SHADI_TMP_DIR", &tmp);
        let addr: SocketAddr = "0.0.0.0:9443".parse().unwrap();
        let err = grpc_server_tls_config(&addr).expect_err("non-loopback needs cert files");
        assert!(err.contains("TLS 1.3"), "{err}");
        assert!(err.contains("A2A_TLS_CERT"), "{err}");
        assert!(err.contains("Do not reuse SLIM_TLS_"), "{err}");
        match prev_cert {
            Some(v) => std::env::set_var("A2A_TLS_CERT", v),
            None => std::env::remove_var("A2A_TLS_CERT"),
        }
        match prev_key {
            Some(v) => std::env::set_var("A2A_TLS_KEY", v),
            None => std::env::remove_var("A2A_TLS_KEY"),
        }
        match prev_tmp {
            Some(v) => std::env::set_var("SHADI_TMP_DIR", v),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn grpc_server_tls_rejects_empty_pem() {
        let _guard = TLS_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let prev_cert = std::env::var_os("A2A_TLS_CERT");
        let prev_key = std::env::var_os("A2A_TLS_KEY");
        let tmp = std::env::temp_dir().join(format!(
            "shadi-a2a-tls-empty-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::create_dir_all(&tmp);
        let cert = tmp.join("empty.crt");
        let key = tmp.join("empty.key");
        fs::write(&cert, b"").unwrap();
        fs::write(&key, b"").unwrap();
        std::env::set_var("A2A_TLS_CERT", &cert);
        std::env::set_var("A2A_TLS_KEY", &key);
        let addr: SocketAddr = "0.0.0.0:9443".parse().unwrap();
        let err = grpc_server_tls_config(&addr).expect_err("empty PEM is not a cert");
        assert!(
            err.contains("has no certificates"),
            "{err}"
        );
        match prev_cert {
            Some(v) => std::env::set_var("A2A_TLS_CERT", v),
            None => std::env::remove_var("A2A_TLS_CERT"),
        }
        match prev_key {
            Some(v) => std::env::set_var("A2A_TLS_KEY", v),
            None => std::env::remove_var("A2A_TLS_KEY"),
        }
        let _ = fs::remove_dir_all(&tmp);
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
        assert_eq!(
            build_client_config("https://node:1", &tls).endpoint,
            "https://node:1"
        );
    }
}
