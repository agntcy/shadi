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
    AgentExecutor, DefaultRequestHandler, InMemoryTaskStore, RequestHandler,
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
};
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use shadi_a2a::{A2ABinding, SlimRpcHandler};
use shadi_mas::{
    experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig},
    Epoch, PatternKind, TaskAdapter, TaskEnvelope,
};
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

/// How a listener decides who may send it tasks.
pub struct AdmissionOptions<'a> {
    pub policy_file: &'a std::path::Path,
}

/// Set once, before any listener starts, then read by every request handler.
///
/// One process serves one policy for its whole life, so this is set-once
/// rather than threaded through four layers of listener plumbing that would
/// only forward it.
static ADMISSION: std::sync::OnceLock<AdmissionGate> = std::sync::OnceLock::new();

struct AdmissionGate {
    admitter: Option<Arc<shadi_identity::Admitter>>,
    replay: Arc<shadi_identity::ReplayCache>,
}

/// Bounds the seen-`jti` set. Eviction at the 300 s freshness window keeps it
/// far below this in practice; the cap is what a flood runs into.
const REPLAY_CACHE_CAPACITY: usize = 16_384;

fn install_admission(opts: Option<AdmissionOptions>) -> anyhow::Result<()> {
    let Some(opts) = opts else {
        return Ok(());
    };
    let policy = shadi_identity::AdmissionPolicy::load(opts.policy_file)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut anchors: Vec<Box<dyn shadi_identity::TrustAnchor>> = vec![Box::new(
        shadi_identity::LocalAnchor::new("local-policy-file", policy.local_attestations.clone()),
    )];
    // Pinned attestations first, so a peer named in the policy file needs no
    // network at all. A published-keys anchor per issuer that configures one.
    for issuer in &policy.trusted_issuers {
        let Some(template) = &issuer.keys_url_template else {
            continue;
        };
        tracing::info!(
            issuer = %issuer.issuer,
            principals = issuer.allowed_principals.len(),
            "admitting through published SSH keys"
        );
        anchors.push(Box::new(shadi_identity::GithubKeysAnchor::new(
            issuer.issuer.clone(),
            template.clone(),
            issuer.allowed_principals.clone(),
            Duration::from_secs(issuer.key_list_ttl_seconds),
            Duration::from_secs(policy.clock_skew_seconds),
            Box::new(fetch_key_listing),
        )));
    }
    let gate = AdmissionGate {
        replay: Arc::new(shadi_identity::ReplayCache::new(
            REPLAY_CACHE_CAPACITY,
            policy.require_freshness,
        )),
        admitter: Some(Arc::new(shadi_identity::Admitter::new(anchors, policy))),
    };
    if ADMISSION.set(gate).is_err() {
        anyhow::bail!("admission policy was already installed");
    }
    Ok(())
}

/// GET an account's published SSH keys. No credential is sent.
///
/// On its own thread because admission is synchronous but runs inside the
/// async request handlers, and `reqwest::blocking` panics if it finds a tokio
/// runtime on the current thread.
///
/// A 404 is an answer — the account publishes nothing — and returns empty so
/// the caller parks the peer as unattested instead of failing closed on it.
///
/// ponytail: a thread per fetch. The allow-list gate and the anchor's cache
/// keep these rare; pool them if that stops being true.
fn fetch_key_listing(url: &str) -> Result<String, String> {
    let url = url.to_string();
    std::thread::spawn(move || {
        let mut response = reqwest::blocking::Client::builder()
            .timeout(KEY_FETCH_TIMEOUT)
            // The policy check that the URL is https only binds the first hop;
            // following a redirect would let the server pick the next one.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("http client: {e}"))?
            .get(&url)
            .send()
            .map_err(|e| format!("get {url}: {e}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(String::new());
        }
        if !response.status().is_success() {
            return Err(format!("get {url}: HTTP {}", response.status()));
        }

        // Read a bounded prefix rather than the whole body: the timeout limits
        // how long a hostile endpoint can stream, not how much.
        use std::io::Read as _;
        let mut body = String::new();
        response
            .by_ref()
            .take(KEY_LISTING_MAX_BYTES)
            .read_to_string(&mut body)
            .map_err(|e| format!("read {url}: {e}"))?;
        Ok(body)
    })
    .join()
    .map_err(|_| "key fetch thread panicked".to_string())?
}

/// Bounds a key fetch end to end, body read included.
const KEY_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Generous for a key listing: 32 published keys are only a few KiB.
const KEY_LISTING_MAX_BYTES: u64 = 64 * 1024;

/// Without `--admission-policy-file` this is the permissive default: no admitter,
/// and unsealed payloads accepted, i.e. exactly today's behaviour.
fn admission_gate() -> &'static AdmissionGate {
    ADMISSION.get_or_init(|| AdmissionGate {
        admitter: None,
        replay: Arc::new(shadi_identity::ReplayCache::new(
            REPLAY_CACHE_CAPACITY,
            false,
        )),
    })
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
    admission: Option<AdmissionOptions>,
    verbose: bool,
) -> anyhow::Result<()> {
    // Before any listener exists, so no message can be served under a policy
    // that has not loaded yet.
    install_admission(admission)?;
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
                    eprintln!(
                        "[agentbridge] {} listener: {err}",
                        a2a_binding.as_protocol_binding()
                    );
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

struct AgentBridgeExecutor {
    adapter: Arc<dyn CliAdapter>,
    slim_endpoint: Option<String>,
    verbose: bool,
}

fn preview(s: &str, max: usize) -> String {
    let first_line = s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s);
    if first_line.len() > max {
        format!("{}…", &first_line[..max])
    } else {
        first_line.to_string()
    }
}

/// Print a request/response body inside the `┌─ .../└─` box: every line
/// when `verbose`, a single truncated preview line otherwise.
fn print_body(s: &str, max: usize, verbose: bool) {
    if verbose {
        for line in s.lines() {
            println!("│  {line}");
        }
    } else {
        println!("│  {}", preview(s, max));
    }
}

/// Opt-in: the collab demo sets this so a listener that just ran a coding
/// turn can A2A-dispatch to the peer named in `NEXT <id>`. Off by default
/// so one-shot `delegate` demos do not sprout extra client sends.
fn a2a_forward_enabled() -> bool {
    matches!(
        std::env::var("AGENTBRIDGE_A2A_FORWARD").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

fn allowed_a2a_peers() -> Vec<String> {
    std::env::var("AGENTBRIDGE_A2A_PEERS")
        .unwrap_or_else(|_| "claude-code,copilot,codex,cursor-agent".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Last `NEXT <id>` in the CLI reply. `DONE` or an error reply means no hop.
fn parse_next_peer(reply: &str) -> Option<String> {
    if reply.contains("agentbridge error:") {
        return None;
    }
    let mut chosen = None;
    for line in reply.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (head, rest) = line
            .split_once(char::is_whitespace)
            .map(|(h, r)| (h, r.trim()))
            .unwrap_or((line, ""));
        if head.eq_ignore_ascii_case("DONE") {
            return None;
        }
        if head.eq_ignore_ascii_case("NEXT") && !rest.is_empty() {
            chosen = Some(rest.split_whitespace().next().unwrap_or(rest).to_string());
        }
    }
    chosen
}

fn is_handoff_or_summary_prompt(prompt: &str) -> bool {
    let start = prompt.trim_start();
    start.starts_with("HANDOFF from ")
        || start.starts_with("You are continuing a coding session")
        || start.starts_with("Summarize this session for handoff")
        || start.contains("Acknowledge you have received the handoff")
}

fn is_peer_handoff_packet(prompt: &str) -> bool {
    prompt.trim_start().starts_with("HANDOFF from ")
}

fn section_after<'a>(text: &'a str, marker: &str, until: Option<&str>) -> &'a str {
    let rest = match text.split_once(marker) {
        Some((_, rest)) => rest,
        None => return "",
    };
    let rest = rest.trim_start_matches('\n');
    match until {
        Some(end) => rest
            .split_once(end)
            .map(|(head, _)| head)
            .unwrap_or(rest)
            .trim(),
        None => rest.trim(),
    }
}

/// Shared turn text for the next peer: last reply, goal, file, tests.
/// Not an "acknowledge" prompt — that was empty context and wasted a CLI turn.
fn render_peer_handoff(from: &str, to: &str, inbound: &str, reply: &str) -> String {
    let goal = section_after(inbound, "GOAL:", Some("HARD RULE:"));
    let goal = goal.lines().next().unwrap_or(goal).trim();
    let file = section_after(inbound, "Current src/lib.rs:", Some("Last cargo test:"));
    let tests = section_after(inbound, "Last cargo test:", None);
    format!(
        "HANDOFF from {from} to {to}\n\
         Do not write Rust. Store this turn; your next coding hop arrives separately.\n\n\
         ## Last reply from {from}\n{}\n\n\
         ## GOAL\n{goal}\n\n\
         ## src/lib.rs when they edited\n{file}\n\n\
         ## Last cargo test\n{tests}\n",
        reply.trim()
    )
}

fn next_peer_to_forward(self_id: &str, prompt: &str, reply: &str) -> Option<String> {
    if !a2a_forward_enabled() || is_handoff_or_summary_prompt(prompt) {
        return None;
    }
    let peer = parse_next_peer(reply)?;
    if peer == self_id {
        return None;
    }
    allowed_a2a_peers()
        .into_iter()
        .find(|allowed| allowed == &peer)
}

/// Where `NEXT <peer>` should go. DID is the name; URL / SLIM endpoint are locators.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HandoffTarget {
    peer_agent_id: String,
    peer_did: Option<String>,
    a2a_url: Option<String>,
    a2a_binding: Option<A2ABinding>,
    slim_endpoint: Option<String>,
}

/// Resolve a `NEXT` peer from on-host leases. Prefer the unicast locator when
/// the lease has one so an HTTP-only collab can token-pass without a SLIM node.
fn resolve_handoff_target(
    to: &str,
    slim_fallback: Option<&str>,
    registry: &LocalAdapterRegistry,
) -> Result<HandoffTarget, String> {
    match registry.resolve_live(to) {
        Ok(record) => {
            let a2a_url = if record.a2a_url.is_empty() {
                None
            } else {
                Some(record.a2a_url)
            };
            let a2a_binding = a2a_url.as_ref().map(|_| record.a2a_binding);
            let slim_endpoint = if !record.slim_endpoint.is_empty() {
                Some(record.slim_endpoint)
            } else {
                slim_fallback.map(str::to_string)
            };
            if a2a_url.is_none() && slim_endpoint.is_none() {
                return Err(format!(
                    "live adapter '{to}' has no A2A locator or SLIM endpoint"
                ));
            }
            Ok(HandoffTarget {
                peer_agent_id: record.name,
                peer_did: if record.did.is_empty() {
                    None
                } else {
                    Some(record.did)
                },
                a2a_url,
                a2a_binding,
                slim_endpoint,
            })
        }
        Err(err) if err.contains("ambiguous") => Err(err),
        Err(_) => match slim_fallback {
            Some(endpoint) => Ok(HandoffTarget {
                peer_agent_id: to.to_string(),
                peer_did: None,
                a2a_url: None,
                a2a_binding: None,
                slim_endpoint: Some(endpoint.to_string()),
            }),
            None => Err(format!(
                "no live locator for '{to}'; peer must appear in `list --local` \
                 (A2A locator or SLIM endpoint) so NEXT can be dispatched without a SLIM node"
            )),
        },
    }
}

/// Send an A2A inject to `to` while proving as `from`.
///
/// gRPC uses the peer's current lease URL and DID. SLIM uses a distinct
/// local name (`…-a2a-client`) so this process does not subscribe as its
/// own listener (`…-a2a`) and deadlock.
fn dispatch_peer_handoff(
    from: &str,
    to: &str,
    slim_fallback: Option<&str>,
    inbound_prompt: &str,
    reply: &str,
) -> Result<(), String> {
    let registry = LocalAdapterRegistry::from_env();
    let target = resolve_handoff_target(to, slim_fallback, &registry)?;
    let adapter = LiveA2ATaskAdapter::new(LiveA2ATaskAdapterConfig {
        endpoint: target.slim_endpoint.clone().unwrap_or_default(),
        agent_id: from.to_string(),
        local_name: Some(format!("agntcy/shadi/{from}-a2a-client")),
        peer_agent_id: target.peer_agent_id.clone(),
        destination: Some(format!("agntcy/shadi/{}-a2a", target.peer_agent_id)),
        a2a_url: target.a2a_url,
        a2a_binding: target.a2a_binding,
        peer_did: target.peer_did,
    });
    let prompt = render_peer_handoff(from, to, inbound_prompt, reply);
    adapter.dispatch(TaskEnvelope {
        task_id: format!("next-{}", uuid::Uuid::new_v4()),
        pattern: PatternKind::Development,
        epoch: Epoch(0),
        correlation_id: Some(format!("agentbridge-next-{from}-{to}")),
        body: prompt.into_bytes(),
    })
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
        println!("\n┌─ A2A recv [{agent_id}] task {}", ctx.task_id);
        print_body(&prompt, 120, self.verbose);
        println!("└─────────────────────────────────────────────────────────");

        let adapter = Arc::clone(&self.adapter);
        let slim_endpoint = self.slim_endpoint.clone();
        let verbose = self.verbose;
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        let history = ctx.message.clone().map(|m| vec![m]);
        let inbound_prompt = prompt.clone();

        let respond = async move {
            let started = std::time::Instant::now();
            let response_text = if is_peer_handoff_packet(&prompt) {
                // Do not run the coding CLI on a peer handoff. The last run
                // asked the model to "acknowledge" empty context; Claude
                // died on stdin and Copilot said no files were shared.
                format!("stored handoff ({})", preview(&prompt, 80))
            } else {
                let prompt_for_cli = prompt;
                match tokio::task::spawn_blocking(move || adapter.execute_prompt(&prompt_for_cli))
                    .await
                {
                    Ok(Ok(text)) => text,
                    Ok(Err(e)) => format!("agentbridge error: {e}"),
                    Err(join_err) => {
                        format!("agentbridge error: adapter task panicked: {join_err}")
                    }
                }
            };
            let elapsed_ms = started.elapsed().as_millis();

            println!("\n┌─ A2A send [{agent_id}] ({} ms)", elapsed_ms);
            print_body(&response_text, 120, verbose);
            println!("└─────────────────────────────────────────────────────────\n");

            if let Some(peer) = next_peer_to_forward(&agent_id, &inbound_prompt, &response_text) {
                let from = agent_id.clone();
                let to = peer.clone();
                let inbound = inbound_prompt.clone();
                let reply = response_text.clone();
                let slim_fallback = slim_endpoint.clone();
                let forwarded = tokio::task::spawn_blocking(move || {
                    dispatch_peer_handoff(&from, &to, slim_fallback.as_deref(), &inbound, &reply)
                })
                .await;
                match forwarded {
                    Ok(Ok(())) => println!(
                        "┌─ A2A client [{agent_id}] → {peer}\n│  NEXT dispatched by this listener\n└─────────────────────────────────────────────────────────\n"
                    ),
                    Ok(Err(err)) => println!(
                        "┌─ A2A client [{agent_id}] → {peer}\n│  dispatch failed: {err}\n└─────────────────────────────────────────────────────────\n"
                    ),
                    Err(join_err) => println!(
                        "┌─ A2A client [{agent_id}] → {peer}\n│  dispatch panicked: {join_err}\n└─────────────────────────────────────────────────────────\n"
                    ),
                }
            }

            let response = Message {
                message_id: new_message_id(),
                context_id: Some(context_id.clone()),
                task_id: Some(task_id.clone()),
                role: Role::Agent,
                parts: vec![Part::text(response_text)],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            };

            vec![
                Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                    task_id: task_id.clone(),
                    context_id: context_id.clone(),
                    status: TaskStatus {
                        state: TaskState::Working,
                        message: None,
                        timestamp: None,
                    },
                    metadata: None,
                })),
                Ok(StreamResponse::Task(Task {
                    id: task_id,
                    context_id,
                    status: TaskStatus {
                        state: TaskState::Completed,
                        message: Some(response),
                        timestamp: None,
                    },
                    artifacts: None,
                    history,
                    metadata: None,
                })),
            ]
        };

        Box::pin(futures::stream::once(respond).flat_map(futures::stream::iter))
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
    agent_did: Option<String>,
    slim_endpoint: Option<String>,
    a2a_listen: Option<String>,
    a2a_binding: A2ABinding,
    /// `None` keeps pre-attestation behaviour: envelope proof only.
    admitter: Option<Arc<shadi_identity::Admitter>>,
    replay: Arc<shadi_identity::ReplayCache>,
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
                AgentBridgeExecutor {
                    adapter,
                    slim_endpoint: slim_endpoint.map(str::to_string),
                    verbose,
                },
                InMemoryTaskStore::new(),
            ),
            ready,
            agent_id: agent_id.to_string(),
            agent_did: agent_did.filter(|did| !did.is_empty()).map(str::to_string),
            slim_endpoint: slim_endpoint.map(str::to_string),
            a2a_listen: a2a_listen.map(str::to_string),
            a2a_binding,
            admitter: admission_gate().admitter.clone(),
            replay: Arc::clone(&admission_gate().replay),
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
        if let Some(reason) = wrong_destination_reason(self.agent_did.as_deref(), &req.message) {
            return Ok(rejected_forged_did(&req, &reason));
        }
        match admit_incoming_message(
            req,
            self.admitter.as_deref(),
            &self.replay,
            self.agent_did.as_deref(),
        ) {
            IncomingAdmission::Proven {
                request,
                did,
                principal,
            } => {
                tracing::info!(
                    %did,
                    sub = principal.as_deref().map(hashed_sub).unwrap_or_else(|| "-".to_string()),
                    "admitted A2A message"
                );
                self.inner.send_message(params, request).await
            }
            IncomingAdmission::AuthRequired { request, reason } => {
                Ok(parked_auth_required(&request, &reason))
            }
            // Same A2A rejection shape as a forgery; only the reason differs.
            // If a distinct `TaskState` is wanted later, this is the one place.
            IncomingAdmission::Forged { request, reason }
            | IncomingAdmission::Denied { request, reason } => {
                Ok(rejected_forged_did(&request, &reason))
            }
        }
    }

    async fn send_streaming_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.ready.notify_waiters();
        if let Some(reason) = wrong_destination_reason(self.agent_did.as_deref(), &req.message) {
            let task = rejected_forged_did(&req, &reason);
            return Ok(Box::pin(futures::stream::once(async move {
                match task {
                    SendMessageResponse::Task(task) => Ok(StreamResponse::Task(task)),
                    SendMessageResponse::Message(message) => Ok(StreamResponse::Message(message)),
                }
            })));
        }
        match admit_incoming_message(
            req,
            self.admitter.as_deref(),
            &self.replay,
            self.agent_did.as_deref(),
        ) {
            IncomingAdmission::Proven {
                request,
                did,
                principal,
            } => {
                tracing::info!(
                    %did,
                    sub = principal.as_deref().map(hashed_sub).unwrap_or_else(|| "-".to_string()),
                    "admitted A2A stream"
                );
                self.inner.send_streaming_message(params, request).await
            }
            IncomingAdmission::AuthRequired { request, reason } => {
                let task = parked_auth_required(&request, &reason);
                Ok(Box::pin(futures::stream::once(async move {
                    match task {
                        SendMessageResponse::Task(task) => Ok(StreamResponse::Task(task)),
                        SendMessageResponse::Message(message) => {
                            Ok(StreamResponse::Message(message))
                        }
                    }
                })))
            }
            IncomingAdmission::Forged { request, reason }
            | IncomingAdmission::Denied { request, reason } => {
                let task = rejected_forged_did(&request, &reason);
                Ok(Box::pin(futures::stream::once(async move {
                    match task {
                        SendMessageResponse::Task(task) => Ok(StreamResponse::Task(task)),
                        SendMessageResponse::Message(message) => {
                            Ok(StreamResponse::Message(message))
                        }
                    }
                })))
            }
        }
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
        supported_interfaces.push(AgentInterface::new(url, a2a_binding.as_protocol_binding()));
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
                a2a_url: a2a_listen.map(advertised_a2a_url).unwrap_or_default(),
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
        if let Err(e) =
            publish_card_to_dir(agent_id, Some(endpoint), a2a_listen, a2a_binding, did, opts)
        {
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

#[derive(Debug)]
enum IncomingAdmission {
    Proven {
        did: String,
        /// The attested owner of `did`, when an admitter resolved one.
        principal: Option<String>,
        request: SendMessageRequest,
    },
    AuthRequired {
        request: SendMessageRequest,
        reason: String,
    },
    Forged {
        request: SendMessageRequest,
        reason: String,
    },
    /// Identified, and policy says no. Distinct from `AuthRequired` because
    /// retrying will not help.
    Denied {
        request: SendMessageRequest,
        reason: String,
    },
}

/// Application-layer gate: signature valid ⇒ fresh ⇒ attested ⇒ permitted.
///
/// `did` is only ever taken from the envelope, never from the payload or the
/// metadata: the payload is opaque application data and the hint is
/// unauthenticated. Missing or unsigned proof parks the task
/// (`AUTH_REQUIRED`); a member presenting another agent's DID is rejected.
///
/// `admitter: None` reproduces the pre-attestation behaviour exactly — proof
/// of possession and nothing more — which is what lets this land before any
/// policy exists.
fn admit_incoming_message(
    mut req: SendMessageRequest,
    admitter: Option<&shadi_identity::Admitter>,
    replay: &shadi_identity::ReplayCache,
    self_did: Option<&str>,
) -> IncomingAdmission {
    let text = extract_text(&req.message);
    if text == "(no text parts)" || !shadi_identity::looks_like_did_proof(text.as_bytes()) {
        return IncomingAdmission::AuthRequired {
            request: req,
            reason: "DID proof required on the message".to_string(),
        };
    }

    let verified = match shadi_identity::unwrap_signed_message(text.as_bytes()) {
        Ok(verified) => verified,
        Err(shadi_identity::IdentityError::ForgedDid(msg)) => {
            return IncomingAdmission::Forged {
                request: req,
                reason: format!("forged DID: {msg}"),
            }
        }
        Err(_) => {
            return IncomingAdmission::AuthRequired {
                request: req,
                reason: "DID proof required on the message".to_string(),
            }
        }
    };

    // Freshness lives inside the signed payload, so it is covered by the
    // signature checked above and cannot be stripped in flight.
    let (body, attestation) =
        match shadi_identity::Sealed::open(&verified.payload, self_did, replay) {
            Ok(opened) => opened,
            Err(reason) => {
                return IncomingAdmission::Denied {
                    request: req,
                    reason,
                }
            }
        };

    let principal = match admitter {
        None => None,
        Some(admitter) => match admitter.admit(&verified.did, attestation.as_deref()) {
            shadi_identity::Admission::Admitted { principal, .. } => Some(principal),
            shadi_identity::Admission::Denied { reason, .. } => {
                return IncomingAdmission::Denied {
                    request: req,
                    reason,
                }
            }
            // Both park the task. They stay distinct up to here so logs and
            // metrics can tell an unknown peer from an authority outage.
            shadi_identity::Admission::Unattested { did } => {
                return IncomingAdmission::AuthRequired {
                    request: req,
                    reason: format!("no authority attests {did}"),
                }
            }
            shadi_identity::Admission::AnchorUnavailable { did, reason } => {
                tracing::warn!(%did, %reason, "anchor unavailable; failing closed");
                return IncomingAdmission::AuthRequired {
                    request: req,
                    reason: "attestation authority unavailable".to_string(),
                };
            }
        },
    };

    // The adapter sees the bare body: neither the envelope nor the freshness
    // wrapper leaks into the tool's input.
    req.message.parts = vec![Part::text(String::from_utf8_lossy(&body).into_owned())];
    IncomingAdmission::Proven {
        did: verified.did,
        principal,
        request: req,
    }
}

/// A truncated SHA-256 of a principal, for log lines.
///
/// `principal=alice@corp.com` is PII and leaks the org's user directory, and
/// logs usually ship off-box. This keeps lines correlatable without that.
fn hashed_sub(principal: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(principal.as_bytes());
    format!(
        "sha256:{}",
        digest[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn task_ids_from(req: &SendMessageRequest) -> (String, String) {
    let task_id = req.message.task_id.clone().unwrap_or_else(new_task_id);
    let context_id = req
        .message
        .context_id
        .clone()
        .unwrap_or_else(new_context_id);
    (task_id, context_id)
}

fn parked_auth_required(req: &SendMessageRequest, reason: &str) -> SendMessageResponse {
    let (task_id, context_id) = task_ids_from(req);
    SendMessageResponse::Task(Task {
        id: task_id,
        context_id,
        status: TaskStatus {
            state: TaskState::AuthRequired,
            message: Some(Message::new(
                Role::Agent,
                vec![Part::text(reason.to_string())],
            )),
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    })
}

fn rejected_forged_did(req: &SendMessageRequest, reason: &str) -> SendMessageResponse {
    let (task_id, context_id) = task_ids_from(req);
    SendMessageResponse::Task(Task {
        id: task_id,
        context_id,
        status: TaskStatus {
            state: TaskState::Rejected,
            message: Some(Message::new(
                Role::Agent,
                vec![Part::text(reason.to_string())],
            )),
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    })
}

/// The URL is not the name. If the caller addressed a DID, only that agent
/// may execute — even when several agents are reachable at the same locator.
fn wrong_destination_reason(listener_did: Option<&str>, message: &Message) -> Option<String> {
    let dest = shadi_a2a::dest_did_from_message(message)?;
    match listener_did {
        Some(mine) if mine == dest => None,
        Some(mine) => Some(format!(
            "destination DID {dest} is not this agent ({mine}); URL is only a locator"
        )),
        None => Some(format!(
            "destination DID {dest} set but this listener has no agent DID"
        )),
    }
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
    use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    let cert_pem =
        fs::read(&cert).map_err(|e| format!("read A2A_TLS_CERT {}: {e}", cert.display()))?;
    let key_pem = fs::read(&key).map_err(|e| format!("read A2A_TLS_KEY {}: {e}", key.display()))?;
    // rustls-pki-types ≥ 1.9 `PemObject` replaces archived rustls-pemfile
    // (RUSTSEC-2025-0134). Certs stay on disk via A2A_TLS_CERT / A2A_TLS_KEY.
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse A2A_TLS_CERT {}: {e}", cert.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "A2A_TLS_CERT {} has no certificates",
            cert.display()
        ));
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
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("invalid --a2a-listen '{listen}' (expected host:port): {e}"))?;

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
        if let Err(e) = publish_card_to_dir(
            agent_id,
            None,
            Some(listen),
            a2a_binding,
            Some(did.as_str()),
            opts,
        ) {
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
            A2ABinding::Slim => Err("SLIM uses --slim-endpoint, not --a2a-listen".to_string()),
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
        let err = run(
            "gemini",
            None,
            &[],
            None,
            None,
            A2ABinding::Grpc,
            None,
            None,
            false,
        )
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

    #[test]
    fn preview_truncates_to_first_nonblank_line() {
        assert_eq!(preview("\n\nhello world", 5), "hello…");
        assert_eq!(preview("short", 20), "short");
    }

    #[test]
    fn parse_next_peer_reads_last_next_and_ignores_done() {
        assert_eq!(
            parse_next_peer("REPLACE 5\nv\nNEXT copilot\n").as_deref(),
            Some("copilot")
        );
        assert_eq!(parse_next_peer("REPLACE 5\nv\nDONE\n"), None);
        assert_eq!(
            parse_next_peer("NEXT copilot\nNEXT cursor-agent\n").as_deref(),
            Some("cursor-agent")
        );
        assert_eq!(
            parse_next_peer("agentbridge error: boom\nNEXT copilot"),
            None
        );
    }

    #[test]
    fn next_peer_to_forward_is_opt_in_and_allow_listed() {
        let prev_fwd = std::env::var("AGENTBRIDGE_A2A_FORWARD").ok();
        let prev_peers = std::env::var("AGENTBRIDGE_A2A_PEERS").ok();
        std::env::remove_var("AGENTBRIDGE_A2A_FORWARD");
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT copilot"),
            None
        );
        std::env::set_var("AGENTBRIDGE_A2A_FORWARD", "1");
        std::env::set_var("AGENTBRIDGE_A2A_PEERS", "claude-code,copilot,codex");
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT copilot").as_deref(),
            Some("copilot")
        );
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT claude-code"),
            None
        );
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT unknown"),
            None
        );
        assert_eq!(
            next_peer_to_forward(
                "claude-code",
                "You are continuing a coding session from copilot.",
                "NEXT codex"
            ),
            None
        );
        assert_eq!(
            next_peer_to_forward(
                "claude-code",
                "HANDOFF from copilot to claude-code\nDo not write Rust.",
                "NEXT codex"
            ),
            None
        );
        match prev_fwd {
            Some(v) => std::env::set_var("AGENTBRIDGE_A2A_FORWARD", v),
            None => std::env::remove_var("AGENTBRIDGE_A2A_FORWARD"),
        }
        match prev_peers {
            Some(v) => std::env::set_var("AGENTBRIDGE_A2A_PEERS", v),
            None => std::env::remove_var("AGENTBRIDGE_A2A_PEERS"),
        }
    }

    #[test]
    fn render_peer_handoff_shares_reply_file_and_tests() {
        let inbound = "\
You are claude-code on hop 1
GOAL: implement Fifo
HARD RULE: two lines
Current src/lib.rs:
 1| pub fn push() {}
Last cargo test:
test push ... FAILED
";
        let text = render_peer_handoff(
            "claude-code",
            "codex",
            inbound,
            "REPLACE 11\nself.items.push(_item);\nNEXT codex",
        );
        assert!(text.starts_with("HANDOFF from claude-code to codex"));
        assert!(text.contains("REPLACE 11"));
        assert!(text.contains("self.items.push(_item)"));
        assert!(text.contains("implement Fifo"));
        assert!(text.contains("pub fn push() {}"));
        assert!(text.contains("test push ... FAILED"));
        assert!(!text.contains("Acknowledge"));
    }

    fn sample_request(text: impl Into<String>) -> SendMessageRequest {
        SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text(text.into())]),
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }

    #[test]
    fn wrong_destination_did_is_rejected_even_on_the_same_url() {
        let message = shadi_a2a::insert_dest_did(
            Message::new(Role::User, vec![Part::text("task".to_string())]),
            "did:key:zOther",
        );
        let reason = wrong_destination_reason(Some("did:key:zMine"), &message).expect("mismatch");
        assert!(reason.contains("did:key:zOther"), "{reason}");
        assert!(reason.contains("locator"), "{reason}");
        assert!(wrong_destination_reason(Some("did:key:zOther"), &message).is_none());
        let unlabeled = Message::new(Role::User, vec![Part::text("task".to_string())]);
        assert!(wrong_destination_reason(Some("did:key:zMine"), &unlabeled).is_none());
        let unlabeled_reason =
            wrong_destination_reason(None, &message).expect("dest DID with no listener DID");
        assert!(
            unlabeled_reason.contains("no agent DID"),
            "{unlabeled_reason}"
        );
    }

    fn scratch_registry() -> (PathBuf, LocalAdapterRegistry) {
        let dir = std::env::temp_dir().join(format!(
            "ab-handoff-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        (dir.clone(), LocalAdapterRegistry::with_dir(dir))
    }

    fn handoff_record(name: &str, did: &str, slim: &str, url: &str) -> LocalAdapterRecord {
        LocalAdapterRecord {
            name: name.to_string(),
            did: did.to_string(),
            slim_endpoint: slim.to_string(),
            a2a_url: url.to_string(),
            a2a_binding: A2ABinding::Grpc,
            pid: std::process::id(),
        }
    }

    #[test]
    fn resolve_handoff_target_prefers_grpc_url_from_lease() {
        let (dir, registry) = scratch_registry();
        let _lease = registry
            .publish(&handoff_record(
                "copilot",
                "did:key:zCopilot",
                "127.0.0.1:47357",
                "http://127.0.0.1:50151",
            ))
            .unwrap();
        let target =
            resolve_handoff_target("copilot", Some("127.0.0.1:9"), &registry).expect("lease");
        assert_eq!(target.peer_agent_id, "copilot");
        assert_eq!(target.peer_did.as_deref(), Some("did:key:zCopilot"));
        assert_eq!(target.a2a_url.as_deref(), Some("http://127.0.0.1:50151"));
        assert_eq!(target.slim_endpoint.as_deref(), Some("127.0.0.1:47357"));
        let by_did = resolve_handoff_target("did:key:zCopilot", None, &registry).expect("did");
        assert_eq!(by_did.a2a_url, target.a2a_url);
        drop(_lease);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_handoff_target_uses_grpc_only_lease_without_slim() {
        let (dir, registry) = scratch_registry();
        let _lease = registry
            .publish(&handoff_record(
                "codex",
                "did:key:zCodex",
                "",
                "http://127.0.0.1:50152",
            ))
            .unwrap();
        let target = resolve_handoff_target("codex", None, &registry).expect("grpc-only");
        assert_eq!(target.a2a_url.as_deref(), Some("http://127.0.0.1:50152"));
        assert_eq!(target.slim_endpoint, None);
        drop(_lease);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_handoff_target_falls_back_to_slim_when_peer_is_unlisted() {
        let (dir, registry) = scratch_registry();
        let target = resolve_handoff_target("claude-code", Some("127.0.0.1:47357"), &registry)
            .expect("slim fallback");
        assert_eq!(target.peer_agent_id, "claude-code");
        assert_eq!(target.a2a_url, None);
        assert_eq!(target.slim_endpoint.as_deref(), Some("127.0.0.1:47357"));
        let err = resolve_handoff_target("claude-code", None, &registry).unwrap_err();
        assert!(err.contains("list --local"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    /// No policy configured: envelope proof only, exactly as before.
    fn lenient() -> shadi_identity::ReplayCache {
        shadi_identity::ReplayCache::new(64, false)
    }

    fn admit_bare(req: SendMessageRequest) -> IncomingAdmission {
        admit_incoming_message(req, None, &lenient(), None)
    }

    /// A listener that pins `did` to `principal`, trusting `authority` for
    /// whichever principals are `permitted`.
    fn pinned_admitter(did: &str, principal: &str, permitted: &[&str]) -> shadi_identity::Admitter {
        const AUTHORITY: &str = "https://sso.example";
        let policy = shadi_identity::AdmissionPolicy {
            trusted_issuers: vec![shadi_identity::TrustedIssuer {
                issuer: AUTHORITY.to_string(),
                allowed_principals: permitted.iter().map(|p| p.to_string()).collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pinned = shadi_identity::Attestation {
            did: did.to_string(),
            principal: principal.to_string(),
            authority: AUTHORITY.to_string(),
            email: None,
            email_verified: false,
            claims: serde_json::Map::new(),
        };
        shadi_identity::Admitter::new(
            vec![Box::new(shadi_identity::LocalAnchor::new(
                AUTHORITY,
                vec![pinned],
            ))],
            policy,
        )
    }

    fn signed_request(id: &shadi_identity::AgentIdentity, body: &str) -> SendMessageRequest {
        let envelope = shadi_identity::wrap_signed_message(id, body.as_bytes()).unwrap();
        sample_request(String::from_utf8(envelope).unwrap())
    }

    #[test]
    fn admit_unsigned_message_parks_auth_required() {
        match admit_bare(sample_request("plain task")) {
            IncomingAdmission::AuthRequired { reason, .. } => {
                assert!(reason.contains("DID proof required"));
            }
            other => panic!("expected AUTH_REQUIRED, got {other:?}"),
        }
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
    fn admit_forged_did_is_rejected() {
        let honest = shadi_identity::AgentIdentity::generate().unwrap();
        let impostor = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&honest, b"task").unwrap();
        // Claim the impostor's DID while keeping the honest signature.
        let sig_line = {
            let text = String::from_utf8(envelope.clone()).unwrap();
            text.lines().nth(2).unwrap().to_string()
        };
        let forged = format!("SHADI-DID-PROOF/1\n{}\n{}\ntask", impostor.did(), sig_line);
        match admit_bare(sample_request(forged)) {
            IncomingAdmission::Forged { reason, .. } => {
                assert!(reason.contains("forged DID"), "{reason}");
            }
            other => panic!("forged DID must be rejected as Forged, got {other:?}"),
        }
    }

    #[test]
    fn admit_honest_proof_unwraps_payload() {
        let id = shadi_identity::AgentIdentity::generate().unwrap();
        match admit_bare(signed_request(&id, "real prompt")) {
            IncomingAdmission::Proven {
                did,
                principal,
                request,
            } => {
                assert_eq!(did, id.did());
                assert_eq!(principal, None, "no admitter means no principal");
                assert_eq!(extract_text(&request.message), "real prompt");
            }
            other => panic!("honest proof must be admitted, got {other:?}"),
        }
    }

    /// Bob has never heard of Alice and admits her because an authority
    /// vouches for the DID her envelope proves possession of.
    #[test]
    fn an_attested_peer_is_admitted_and_names_its_principal() {
        let alice = shadi_identity::AgentIdentity::generate().unwrap();
        let admitter = pinned_admitter(&alice.did(), "alice", &["alice"]);
        match admit_incoming_message(
            signed_request(&alice, "review PR 412"),
            Some(&admitter),
            &lenient(),
            None,
        ) {
            IncomingAdmission::Proven {
                principal, request, ..
            } => {
                assert_eq!(principal.as_deref(), Some("alice"));
                assert_eq!(extract_text(&request.message), "review PR 412");
            }
            other => panic!("expected Proven, got {other:?}"),
        }
    }

    /// Eve holds a valid key nobody vouches for. A good signature is not an
    /// identity, so she parks rather than being admitted.
    #[test]
    fn an_unattested_peer_parks_instead_of_admitting() {
        let alice = shadi_identity::AgentIdentity::generate().unwrap();
        let eve = shadi_identity::AgentIdentity::generate().unwrap();
        let admitter = pinned_admitter(&alice.did(), "alice", &["alice"]);
        match admit_incoming_message(
            signed_request(&eve, "rm -rf /"),
            Some(&admitter),
            &lenient(),
            None,
        ) {
            IncomingAdmission::AuthRequired { reason, .. } => {
                assert!(reason.contains("no authority attests"), "{reason}");
            }
            other => panic!("Eve must not be admitted, got {other:?}"),
        }
    }

    /// Attested by a trusted authority, and still not permitted.
    #[test]
    fn an_attested_peer_outside_policy_is_denied_not_parked() {
        let eve = shadi_identity::AgentIdentity::generate().unwrap();
        let admitter = pinned_admitter(&eve.did(), "eve", &["alice"]);
        match admit_incoming_message(
            signed_request(&eve, "task"),
            Some(&admitter),
            &lenient(),
            None,
        ) {
            IncomingAdmission::Denied { reason, .. } => {
                assert!(reason.contains("not permitted"), "{reason}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    /// The payload is opaque application data. Claiming to be Alice in it
    /// changes nothing, because no such field is ever consulted.
    #[test]
    fn a_principal_claimed_in_the_payload_is_ignored() {
        let eve = shadi_identity::AgentIdentity::generate().unwrap();
        let req = signed_request(&eve, r#"{"principal":"alice","task":"x"}"#);
        match admit_bare(req) {
            IncomingAdmission::Proven { did, principal, .. } => {
                assert_eq!(did, eve.did(), "the DID comes from the envelope only");
                assert_eq!(principal, None);
            }
            other => panic!("expected Proven as Eve, got {other:?}"),
        }
    }

    /// Freshness rides inside the signed payload, so the whole sealed envelope
    /// is what gets replayed — and rejected on second delivery.
    #[test]
    fn a_replayed_envelope_is_rejected_on_second_delivery() {
        let alice = shadi_identity::AgentIdentity::generate().unwrap();
        let me = "did:key:zBob";
        let sealed = shadi_identity::Sealed::seal(me, "review PR 412", None).unwrap();
        let envelope = shadi_identity::wrap_signed_message(&alice, &sealed).unwrap();
        let text = String::from_utf8(envelope).unwrap();
        let replay = lenient();

        match admit_incoming_message(sample_request(text.clone()), None, &replay, Some(me)) {
            IncomingAdmission::Proven { request, .. } => {
                assert_eq!(extract_text(&request.message), "review PR 412");
            }
            other => panic!("first delivery must be admitted, got {other:?}"),
        }
        match admit_incoming_message(sample_request(text), None, &replay, Some(me)) {
            IncomingAdmission::Denied { reason, .. } => {
                assert!(reason.contains("replayed"), "{reason}");
            }
            other => panic!("replay must be denied, got {other:?}"),
        }
    }

    /// Captured en route to Bob, redelivered to Carol. `aud` is inside the
    /// signature, so it cannot be rewritten.
    #[test]
    fn an_envelope_addressed_to_another_peer_is_rejected() {
        let alice = shadi_identity::AgentIdentity::generate().unwrap();
        let sealed = shadi_identity::Sealed::seal("did:key:zBob", "task", None).unwrap();
        let envelope = shadi_identity::wrap_signed_message(&alice, &sealed).unwrap();
        let req = sample_request(String::from_utf8(envelope).unwrap());
        match admit_incoming_message(req, None, &lenient(), Some("did:key:zCarol")) {
            IncomingAdmission::Denied { reason, .. } => {
                assert!(reason.contains("addressed to did:key:zBob"), "{reason}");
            }
            other => panic!("cross-peer replay must be denied, got {other:?}"),
        }
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
        let card = build_agent_card("copilot", None, Some("127.0.0.1:50051"), A2ABinding::Grpc);
        assert_eq!(card.supported_interfaces.len(), 1);
        let iface = &card.supported_interfaces[0];
        assert_eq!(iface.protocol_binding, TRANSPORT_PROTOCOL_GRPC);
        // a2a-lf strips `http://` on GRPC interfaces (A2A card convention).
        assert_eq!(iface.url, "127.0.0.1:50051");
    }

    #[test]
    fn build_agent_card_sets_jsonrpc_interface_when_binding_given() {
        let card = build_agent_card("copilot", None, Some("127.0.0.1:8080"), A2ABinding::Jsonrpc);
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
        assert_eq!(advertised_a2a_url("0.0.0.0:50051"), "https://0.0.0.0:50051");
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
        assert!(err.contains("has no certificates"), "{err}");
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

    /// The only check that the admission fetch works for real: TLS roots,
    /// redirects and the 404 mapping all come from the live service. Ignored
    /// because it needs the network.
    ///
    /// `cargo test -p agntcy-agentbridge-cli -- --ignored live_key_listing`
    #[test]
    #[ignore = "requires network access to github.com"]
    fn live_key_listing_fetch_works() {
        let listing = fetch_key_listing("https://github.com/markpmarton.keys")
            .expect("fetch should succeed — a TLS trust-store failure shows up here");
        assert!(
            listing.contains("ssh-ed25519"),
            "expected published keys, got: {listing}"
        );

        // A missing account is an answer, not an outage.
        let absent = fetch_key_listing("https://github.com/shadi-no-such-account-xyzzy-42.keys")
            .expect("a 404 must not be an error");
        assert!(absent.is_empty(), "404 should map to an empty listing");
    }
}
