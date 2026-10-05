use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use a2a::*;
use a2a_client::A2AClient;
use agent_secrets::{
    AgentVerifier, DidProofVerifier, RequestContext, SecretResult, SessionContext,
};

pub mod auth_required;
pub use auth_required::{
    audit_auth_required, decide_auth_required, is_auth_required, run_auth_required_loop,
    AuthRequiredAction, AuthRequiredConfig, AuthRequiredPolicy,
};
use crate::adapters::{MessagingAdapter, TaskAdapter, TaskEnvelope};
use shadi_a2a::{insert_dest_did, A2ABinding, A2AChannel, A2AChannelBuilder, A2ALocator};
use slim_bindings::{
    BackoffConfig, CaSource, ClientConfig, ExponentialBackoff, Name, Service, TlsClientConfig,
    TlsSource,
};
use tokio::runtime::Builder as TokioRuntimeBuilder;

const DEFAULT_LOCAL_ORG: &str = "agntcy";
const DEFAULT_LOCAL_NAMESPACE: &str = "shadi";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedMessage {
    pub topic: String,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct RecordingMessagingAdapter {
    published: Mutex<Vec<PublishedMessage>>,
}

impl RecordingMessagingAdapter {
    pub fn published_messages(&self) -> Result<Vec<PublishedMessage>, String> {
        self.published
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "recording messaging adapter lock poisoned".to_string())
    }
}

impl MessagingAdapter for RecordingMessagingAdapter {
    fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), String> {
        self.published
            .lock()
            .map_err(|_| "recording messaging adapter lock poisoned".to_string())?
            .push(PublishedMessage {
                topic: topic.to_string(),
                payload: payload.to_vec(),
            });
        Ok(())
    }
}

#[derive(Default)]
pub struct RecordingTaskAdapter {
    tasks: Mutex<Vec<TaskEnvelope>>,
}

impl RecordingTaskAdapter {
    pub fn dispatched_tasks(&self) -> Result<Vec<TaskEnvelope>, String> {
        self.tasks
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "recording task adapter lock poisoned".to_string())
    }
}

impl TaskAdapter for RecordingTaskAdapter {
    fn dispatch(&self, task: TaskEnvelope) -> Result<(), String> {
        self.tasks
            .lock()
            .map_err(|_| "recording task adapter lock poisoned".to_string())?
            .push(task);
        Ok(())
    }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveA2ATaskAdapterConfig {
    pub endpoint: String,
    pub agent_id: String,
    pub local_name: Option<String>,
    pub peer_agent_id: String,
    pub destination: Option<String>,
    /// When set, dispatch over official A2A unicast to this URL instead of SLIM.
    /// Locator only — [`Self::peer_did`] is the portable name.
    pub a2a_url: Option<String>,
    /// Binding for [`Self::a2a_url`]. `None` means gRPC (old callers).
    pub a2a_binding: Option<A2ABinding>,
    /// Recipient DID. Set as `a2a-dst-did` on unicast sends so a shared URL
    /// cannot execute a task meant for a different agent.
    pub peer_did: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LiveTaskDispatchRecord {
    pub task: TaskEnvelope,
    pub response: String,
    pub elapsed_ms: f64,
}

pub struct LiveA2ATaskAdapter {
    config: LiveA2ATaskAdapterConfig,
    dispatches: Mutex<Vec<LiveTaskDispatchRecord>>,
    policy: Option<Arc<dyn AgentVerifier>>,
}

impl LiveA2ATaskAdapter {
    pub fn new(config: LiveA2ATaskAdapterConfig) -> Self {
        Self {
            config,
            dispatches: Mutex::new(Vec::new()),
            policy: None,
        }
    }

    /// Check every task this adapter sends with `policy` as well. The DID
    /// proof check always runs first, so a policy can refuse what it allows
    /// but never allow what it refuses.
    pub fn with_verifier(mut self, policy: Arc<dyn AgentVerifier>) -> Self {
        self.policy = Some(policy);
        self
    }

    fn verifier(&self) -> Arc<dyn AgentVerifier> {
        match &self.policy {
            Some(policy) => Arc::new(DidProofThen(Arc::clone(policy))),
            None => Arc::new(DidProofVerifier),
        }
    }

    pub fn dispatches(&self) -> Result<Vec<LiveTaskDispatchRecord>, String> {
        self.dispatches
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "live A2A task adapter lock poisoned".to_string())
    }

    fn is_transient_dispatch_error(message: &str) -> bool {
        message.contains("Session handshake failed")
            || message.contains("failed to add participant to session")
            || message.contains("Connection refused")
            || message.contains("data plane is shutting down")
            || message.contains("Session already closed")
            || message.contains("Session closed")
            || message.contains("dropped")
            || message.contains("retries exhausted")
            || message.contains("unable to reconnect")
    }

    fn send_task(&self, task: &TaskEnvelope) -> Result<String, String> {
        let span = tracing::info_span!(
            "shadi.a2a.send",
            otel.kind = "client",
            a2a.task_id = %task.task_id,
            peer.agent_id = %self.config.peer_agent_id,
            peer.did = tracing::field::Empty,
            a2a.outcome = tracing::field::Empty,
        );
        if let Some(did) = self.config.peer_did.as_deref() {
            span.record("peer.did", did);
        }
        let _guard = span.enter();

        let body = Mutex::new(render_task_message(task));
        let auth_cfg = AuthRequiredConfig::from_env();
        let response = run_auth_required_loop(
            || {
                let current = body
                    .lock()
                    .map_err(|_| "live A2A task body lock poisoned".to_string())?
                    .clone();
                let signed = shadi_identity::sign_message_from_env(&self.config.agent_id, current.as_bytes())
                    .map_err(|err| err.to_string())?;
                let signed_text = String::from_utf8(signed)
                    .map_err(|err| format!("DID proof envelope is not UTF-8: {err}"))?;
                self.send_signed_task(task, &signed_text)
            },
            &auth_cfg,
            || {
                let note = escalate_auth_required(&auth_cfg)?;
                let mut guard = body
                    .lock()
                    .map_err(|_| "live A2A task body lock poisoned".to_string())?;
                guard.push_str("\n\nauth_escalate:\n");
                guard.push_str(&note);
                Ok(note)
            },
        )
        .inspect_err(|error| {
            span.record("a2a.outcome", "error");
            tracing::warn!(%error, "A2A send failed");
        })?;
        span.record("a2a.outcome", reply_outcome(&response));
        a2a_reply(&response).inspect_err(|reason| {
            tracing::warn!(%reason, "the peer did not complete the task");
        })
    }

    fn send_signed_task(
        &self,
        task: &TaskEnvelope,
        signed_text: &str,
    ) -> Result<SendMessageResponse, String> {
        let message = self.task_message(signed_text);
        if let Some(a2a_url) = self.config.a2a_url.as_deref() {
            let locator = A2ALocator::new(
                self.config.a2a_binding.unwrap_or(A2ABinding::Grpc),
                a2a_url,
            );
            if locator.binding.is_unicast() {
                return self.send_signed_task_unicast(task, &message, &locator);
            }
        }
        self.send_signed_task_slim(task, &message)
    }

    /// Both transports send this, so the receiver can check the destination
    /// DID whichever way the task arrives.
    fn task_message(&self, signed_text: &str) -> Message {
        let message = Message::new(Role::User, vec![Part::text(signed_text.to_string())]);
        match self.config.peer_did.as_deref() {
            Some(peer_did) => insert_dest_did(message, peer_did),
            None => message,
        }
    }

    fn send_signed_task_unicast(
        &self,
        task: &TaskEnvelope,
        message: &Message,
        locator: &A2ALocator,
    ) -> Result<SendMessageResponse, String> {
        let auth = shadi_identity::require_did_auth_from_env(&self.config.agent_id)
            .map_err(|e| e.to_string())?;
        let proven_did = match &auth {
            shadi_identity::SlimAuth::Did { did, .. } => did.clone(),
            shadi_identity::SlimAuth::SharedSecret(_) => {
                return Err(
                    "application auth requires an agent DID; shared-secret node auth is not enough"
                        .to_string(),
                );
            }
        };
        let session = SessionContext::new(
            &self.config.agent_id,
            format!("mas-task-session-{}", task.task_id),
        )
        .with_proven_did(proven_did);
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("failed to create tokio runtime: {}", err))?;
        let locator = locator.clone();
        runtime.block_on(async {
            let via = locator.display_uri();
            let channel = A2AChannel::connect(locator, self.verifier(), session)
                .await
                .map_err(|err| format!("A2A connect {via}: {err}"))?;
            let client = A2AClient::new(Box::new(channel));
            let request = SendMessageRequest {
                message: message.clone(),
                configuration: None,
                metadata: None,
                tenant: None,
            };
            let response = client
                .send_message(&request)
                .await
                .map_err(|err| format!("failed to send A2A task {}: {}", task.task_id, err))?;
            client.destroy().await.ok();
            Ok(response)
        })
    }

    fn send_signed_task_slim(
        &self,
        task: &TaskEnvelope,
        message: &Message,
    ) -> Result<SendMessageResponse, String> {
        let tls = resolve_client_tls_material_for_agent(Some(&self.config.agent_id))?;
        let local_name = self
            .config
            .local_name
            .clone()
            .unwrap_or_else(|| canonical_slim_name(&self.config.agent_id));
        let destination = self
            .config
            .destination
            .clone()
            .unwrap_or_else(|| canonical_slim_name(&self.config.peer_agent_id));

        let max_retries = std::env::var("SHADI_LIVE_A2A_RETRY_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(3);
        let retry_backoff_ms = std::env::var("SHADI_LIVE_A2A_RETRY_BACKOFF_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1000);

        let mut last_error: Option<String> = None;
        for attempt in 0..=max_retries {
            let service = Service::new(format!(
                "shadi-mas-a2a-client-{}-{}-{}",
                std::process::id(),
                task.task_id,
                attempt
            ));
            let attempt_result = (|| -> Result<SendMessageResponse, String> {
                let connection_id = service
                    .connect(build_client_config_for_endpoint(&self.config.endpoint, &tls))
                    .map_err(format_slim_error)?;
                let local_name_ref = Arc::new(parse_slim_name(&local_name)?);
                let remote_name_ref = Arc::new(parse_slim_name(&destination)?);

                let auth = shadi_identity::require_did_auth_from_env(&self.config.agent_id)
                    .map_err(|e| e.to_string())?;
                let proven_did = match &auth {
                    shadi_identity::SlimAuth::Did { did, .. } => did.clone(),
                    shadi_identity::SlimAuth::SharedSecret(_) => {
                        return Err(
                            "application auth requires an agent DID; shared-secret node auth is not enough"
                                .to_string(),
                        );
                    }
                };
                let app = shadi_identity::create_app(&service, local_name_ref.clone(), &auth)
                    .map_err(format_slim_error)?;
                app.subscribe(local_name_ref.clone(), Some(connection_id))
                    .map_err(format_slim_error)?;

                let runtime = TokioRuntimeBuilder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| format!("failed to create tokio runtime: {}", err))?;

                // Outbound payload is DID-signed above; the verifier requires that proof.
                let session = SessionContext::new(
                    &self.config.agent_id,
                    format!("mas-task-session-{}", task.task_id),
                )
                .with_proven_did(proven_did);

                // slim_rpc::Channel captures `tokio::runtime::Handle::current()` at
                // construction, so build the transport inside the runtime context.
                let channel = {
                    let _enter = runtime.enter();
                    A2AChannelBuilder::new(app.clone(), remote_name_ref, self.verifier(), session)
                        .connection_id(connection_id)
                        .build()
                };
                let client = A2AClient::new(Box::new(channel));
                let request = SendMessageRequest {
                    message: message.clone(),
                    configuration: None,
                    metadata: None,
                    tenant: None,
                };

                let response = runtime
                    .block_on(async {
                        let response = client.send_message(&request).await?;
                        client.destroy().await?;
                        Ok::<SendMessageResponse, A2AError>(response)
                    })
                    .map_err(|err| format!("failed to send A2A task {}: {}", task.task_id, err))?;

                let _ = app.unsubscribe(local_name_ref.clone(), Some(connection_id));
                let _ = service.disconnect(connection_id);
                Ok(response)
            })();
            let _ = service.shutdown();

            match attempt_result {
                Ok(response) => return Ok(response),
                Err(err) => {
                    if attempt == max_retries || !Self::is_transient_dispatch_error(&err) {
                        return Err(err);
                    }
                    last_error = Some(err);
                    thread::sleep(Duration::from_millis(retry_backoff_ms));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            format!("failed to send A2A task {} for an unknown reason", task.task_id)
        }))
    }
}

fn escalate_auth_required(config: &AuthRequiredConfig) -> Result<String, String> {
    if let Ok(note) = std::env::var("SHADI_AUTH_REQUIRED_ESCALATE") {
        if !note.trim().is_empty() {
            return Ok(note);
        }
    }
    Err(format!(
        "AUTH_REQUIRED denied: no harness escalate answer within {}ms",
        config.timeout.as_millis()
    ))
}

impl TaskAdapter for LiveA2ATaskAdapter {
    fn dispatch(&self, task: TaskEnvelope) -> Result<(), String> {
        let started_at = Instant::now();
        let response = self.send_task(&task)?;
        self.dispatches
            .lock()
            .map_err(|_| "live A2A task adapter lock poisoned".to_string())?
            .push(LiveTaskDispatchRecord {
                task,
                response,
                elapsed_ms: started_at.elapsed().as_secs_f64() * 1000.0,
            });
        Ok(())
    }
}


/// [`DidProofVerifier`], then the caller's policy.
struct DidProofThen(Arc<dyn AgentVerifier>);

impl AgentVerifier for DidProofThen {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        DidProofVerifier.verify(session)?;
        self.0.verify(session)
    }

    fn verify_request(
        &self,
        session: &SessionContext,
        request: &RequestContext,
    ) -> SecretResult<()> {
        DidProofVerifier.verify_request(session, request)?;
        let evaluation_id = request.evaluation_id();
        let decision = self.0.verify_request(session, request);
        match &decision {
            Ok(()) => tracing::info!(evaluation_id, "egress policy allowed a message"),
            Err(err) => tracing::warn!(evaluation_id, %err, "egress policy refused a message"),
        }
        decision
    }

    fn wants_content(&self) -> bool {
        self.0.wants_content()
    }
}

#[derive(Clone)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

fn render_task_message(task: &TaskEnvelope) -> String {
    format!(
        "task_id: {}\npattern: {:?}\nepoch: {}\nbody:\n{}",
        task.task_id,
        task.pattern,
        task.epoch.0,
        String::from_utf8(task.body.clone())
            .unwrap_or_else(|_| String::from_utf8_lossy(&task.body).into_owned())
    )
}

fn describe_a2a_response(response: &SendMessageResponse) -> String {
    match response {
        SendMessageResponse::Message(message) => readable_message_text(message),
        SendMessageResponse::Task(task) => task
            .status
            .message
            .as_ref()
            .map(readable_message_text)
            .unwrap_or_else(|| format!("task {} completed", task.id)),
    }
}

/// The `a2a.outcome` a send span records for the peer's reply.
fn reply_outcome(response: &SendMessageResponse) -> &'static str {
    let SendMessageResponse::Task(task) = response else {
        return "replied";
    };
    match task.status.state {
        TaskState::Completed => "completed",
        TaskState::Rejected => "rejected",
        TaskState::Failed => "failed",
        TaskState::Canceled => "canceled",
        TaskState::AuthRequired => "auth_required",
        TaskState::InputRequired => "input_required",
        TaskState::Unspecified | TaskState::Submitted | TaskState::Working => "working",
    }
}

/// A peer's `Rejected` or `Failed` task is an error, so callers never mistake
/// its reason for a result.
fn a2a_reply(response: &SendMessageResponse) -> Result<String, String> {
    let SendMessageResponse::Task(task) = response else {
        return Ok(describe_a2a_response(response));
    };
    let outcome = match task.status.state {
        TaskState::Rejected => "rejected by the peer",
        TaskState::Failed => "failed on the peer",
        _ => return Ok(describe_a2a_response(response)),
    };
    let reason = task
        .status
        .message
        .as_ref()
        .map(readable_message_text)
        .unwrap_or_else(|| "no reason given".to_string());
    Err(format!("A2A task {} {outcome}: {reason}", task.id))
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

fn build_client_config_for_endpoint(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.endpoint = resolve_client_endpoint_value(endpoint);
    // The adapter owns retries; SLIM's default connection retry loop is unbounded.
    config.connect_timeout = Some(Duration::from_secs(5));
    config.backoff = Some(BackoffConfig::Exponential {
        config: ExponentialBackoff {
            max_attempts: 1,
            ..Default::default()
        },
    });
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

fn resolve_client_tls_material_for_agent(agent_id_override: Option<&str>) -> Result<TlsMaterial, String> {
    let cert_override = std::env::var_os("SLIM_TLS_CERT").map(PathBuf::from);
    let key_override = std::env::var_os("SLIM_TLS_KEY").map(PathBuf::from);
    let ca = std::env::var_os("SLIM_TLS_CA")
        .map(PathBuf::from)
        .unwrap_or_else(|| slim_tls_dir().join("ca.crt"));
    let agent_id = agent_id_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("SHADI_AGENT_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });

    let (cert, key) = match (cert_override, key_override) {
        (Some(cert), Some(key)) => (cert, key),
        (Some(_), None) | (None, Some(_)) => {
            return Err("SLIM_TLS_CERT and SLIM_TLS_KEY must be set together".to_string())
        }
        (None, None) => {
            let base_dir = slim_tls_dir();
            client_identity_candidates(&base_dir, agent_id.as_deref())
                .into_iter()
                .find(|(cert, key)| cert.is_file() && key.is_file())
                .ok_or_else(|| {
                    let candidates = client_identity_candidates(&base_dir, agent_id.as_deref())
                        .into_iter()
                        .map(|(cert, key)| format!("{} + {}", cert.display(), key.display()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "no SLIM client certificate found; checked {}. Set SHADI_AGENT_ID or SLIM_TLS_CERT/SLIM_TLS_KEY explicitly",
                        candidates
                    )
                })?
        }
    };

    ensure_file_exists(&cert, "SLIM client certificate")?;
    ensure_file_exists(&key, "SLIM client key")?;
    ensure_file_exists(&ca, "SLIM client CA")?;

    Ok(TlsMaterial { cert, key, ca })
}

fn client_identity_candidates(base_dir: &Path, agent_id: Option<&str>) -> Vec<(PathBuf, PathBuf)> {
    let mut candidates = Vec::new();

    if let Some(agent_id) = agent_id {
        let stem = format!("client-{}", agent_id);
        candidates.push((
            base_dir.join(format!("{}.crt", stem)),
            base_dir.join(format!("{}.key", stem)),
        ));
    }

    candidates.push((base_dir.join("client.crt"), base_dir.join("client.key")));
    candidates
}

fn slim_tls_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_tmp_dir)
        .join("shadi-slim-mtls")
}

fn default_tmp_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".tmp")
}

fn ensure_file_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("{} not found at {}", label, path.display()))
    }
}

fn resolve_client_endpoint_value(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{}", endpoint)
    }
}

fn parse_slim_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|err| {
        format!(
            "invalid SLIM name {}: {} (expected organization/namespace/application)",
            raw, err
        )
    })
}

fn canonical_slim_name(agent_id: &str) -> String {
    if agent_id.contains('/') {
        agent_id.to_string()
    } else {
        format!("{}/{}/{}", DEFAULT_LOCAL_ORG, DEFAULT_LOCAL_NAMESPACE, agent_id)
    }
}

fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use agent_secrets::AgentVerifier;
    use crate::types::{Epoch, PatternKind};

    fn sample_task() -> TaskEnvelope {
        TaskEnvelope {
            task_id: "task-1".to_string(),
            pattern: PatternKind::Development,
            epoch: Epoch(3),
            correlation_id: Some("corr-1".to_string()),
            body: b"hello world".to_vec(),
        }
    }

    #[test]
    fn canonical_slim_name_qualifies_bare_agent_ids() {
        assert_eq!(canonical_slim_name("avatar"), "agntcy/shadi/avatar");
    }

    #[test]
    fn canonical_slim_name_preserves_qualified_names() {
        assert_eq!(
            canonical_slim_name("acme/team/avatar"),
            "acme/team/avatar"
        );
    }

    #[test]
    fn parse_slim_name_accepts_three_part_names() {
        let name = parse_slim_name("agntcy/shadi/avatar").expect("valid name");
        // Round-trips back through the canonical string form.
        assert!(format!("{name:?}").contains("avatar") || !format!("{name:?}").is_empty());
    }

    #[test]
    fn parse_slim_name_rejects_malformed_names() {
        assert!(parse_slim_name("not-a-valid-name").is_err());
    }

    #[test]
    fn resolve_client_endpoint_value_defaults_to_https() {
        assert_eq!(
            resolve_client_endpoint_value("127.0.0.1:47357"),
            "https://127.0.0.1:47357"
        );
    }

    #[test]
    fn resolve_client_endpoint_value_preserves_explicit_scheme() {
        assert_eq!(
            resolve_client_endpoint_value("http://node:1234"),
            "http://node:1234"
        );
    }

    #[test]
    fn render_task_message_includes_envelope_fields() {
        let rendered = render_task_message(&sample_task());
        assert!(rendered.contains("task_id: task-1"));
        assert!(rendered.contains("pattern: Development"));
        assert!(rendered.contains("epoch: 3"));
        assert!(rendered.contains("body:\nhello world"));
    }

    #[test]
    fn readable_message_text_joins_text_parts() {
        let message = Message::new(
            Role::Agent,
            vec![Part::text("first".to_string()), Part::text("second".to_string())],
        );
        assert_eq!(readable_message_text(&message), "first second");
    }

    #[test]
    fn readable_message_text_reports_when_no_text_parts() {
        let message = Message::new(Role::Agent, vec![]);
        assert_eq!(readable_message_text(&message), "(no text parts)");
    }

    #[test]
    fn describe_a2a_response_renders_message_payload() {
        let response = SendMessageResponse::Message(Message::new(
            Role::Agent,
            vec![Part::text("done".to_string())],
        ));
        assert_eq!(describe_a2a_response(&response), "done");
    }

    #[test]
    fn describe_a2a_response_falls_back_for_taskless_status() {
        let task = Task {
            id: "task-9".to_string(),
            context_id: "ctx-9".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        assert_eq!(
            describe_a2a_response(&SendMessageResponse::Task(task)),
            "task task-9 completed"
        );
    }

    fn task_reply(state: TaskState, reason: Option<&str>) -> SendMessageResponse {
        SendMessageResponse::Task(Task {
            id: "task-9".to_string(),
            context_id: "ctx-9".to_string(),
            status: TaskStatus {
                state,
                message: reason
                    .map(|text| Message::new(Role::Agent, vec![Part::text(text.to_string())])),
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        })
    }

    thread_local! {
        static CAPTURING: std::cell::RefCell<Option<Vec<String>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The span fields and events `run` leaves, as `span field=value` and
    /// `span: message` lines.
    ///
    /// Recorded by one subscriber the whole test binary shares, into a buffer
    /// for this thread. A per-thread subscriber is not enough: a callsite
    /// another thread reaches first can cache "no subscriber" and drop the
    /// event here.
    fn trace_of(run: impl FnOnce()) -> Vec<String> {
        use tracing_subscriber::layer::{Context, SubscriberExt};
        use tracing_subscriber::registry::LookupSpan;

        struct Fields(Vec<(String, String)>);

        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                let name = field.name().to_string();
                self.0.push((name, format!("{value:?}")));
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.push((field.name().to_string(), value.to_string()));
            }
        }

        fn push(lines: impl IntoIterator<Item = String>) {
            CAPTURING.with(|current| {
                if let Some(recorded) = current.borrow_mut().as_mut() {
                    recorded.extend(lines);
                }
            });
        }

        struct Capture;

        impl<S> tracing_subscriber::Layer<S> for Capture
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_record(
                &self,
                id: &tracing::span::Id,
                values: &tracing::span::Record<'_>,
                ctx: Context<'_, S>,
            ) {
                let span = ctx.span(id).map_or("-", |span| span.name());
                let mut fields = Fields(Vec::new());
                values.record(&mut fields);
                push(fields.0.into_iter().map(|(k, v)| format!("{span} {k}={v}")));
            }

            fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
                let span = ctx.event_span(event).map_or("-", |span| span.name());
                let mut fields = Fields(Vec::new());
                event.record(&mut fields);
                let message = fields.0.into_iter().find(|(k, _)| k == "message");
                let message = message.map(|(_, v)| v).unwrap_or_default();
                push([format!("{span}: {message}")]);
            }
        }

        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            let subscriber = tracing_subscriber::registry().with(Capture);
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
        tracing::callsite::rebuild_interest_cache();

        CAPTURING.with(|current| *current.borrow_mut() = Some(Vec::new()));
        run();
        CAPTURING.with(|current| current.borrow_mut().take().unwrap_or_default())
    }

    #[test]
    fn a_failed_send_records_its_outcome_on_the_send_span() {
        let adapter = LiveA2ATaskAdapter::new(LiveA2ATaskAdapterConfig {
            endpoint: "node:47357".to_string(),
            agent_id: "avatar".to_string(),
            local_name: None,
            peer_agent_id: "peer".to_string(),
            destination: None,
            a2a_url: None,
            a2a_binding: None,
            peer_did: Some("did:key:zPeer".to_string()),
        });
        let lines = trace_of(|| {
            assert!(adapter.dispatch(sample_task()).is_err());
        });
        let has = |line: &str| lines.iter().any(|l| l == line);
        assert!(has("shadi.a2a.send peer.did=did:key:zPeer"), "{lines:#?}");
        assert!(has("shadi.a2a.send a2a.outcome=error"), "{lines:#?}");
        assert!(has("shadi.a2a.send: A2A send failed"), "{lines:#?}");
    }

    #[test]
    fn a_policy_decision_is_an_event_with_its_evaluation_id() {
        let proven = SessionContext::new("avatar", "s").with_proven_did("did:key:zAvatar");
        let request = RequestContext::new();
        let refusing = sample_adapter().with_verifier(Arc::new(Refuse)).verifier();
        let allowing = sample_adapter().with_verifier(Arc::new(Allow)).verifier();
        let lines = trace_of(|| {
            let _ = refusing.verify_request(&proven, &request);
            let _ = allowing.verify_request(&proven, &request);
        });
        let has = |line: &str| lines.iter().any(|l| l == line);
        assert!(has("-: egress policy refused a message"), "{lines:#?}");
        assert!(has("-: egress policy allowed a message"), "{lines:#?}");
    }

    #[test]
    fn reply_outcome_names_the_peer_state() {
        let cases = [
            (TaskState::Completed, "completed"),
            (TaskState::Rejected, "rejected"),
            (TaskState::Failed, "failed"),
            (TaskState::Working, "working"),
        ];
        for (state, outcome) in cases {
            assert_eq!(reply_outcome(&task_reply(state, None)), outcome);
        }
        let message = SendMessageResponse::Message(Message::new(Role::Agent, vec![]));
        assert_eq!(reply_outcome(&message), "replied");
    }

    #[test]
    fn a2a_reply_turns_rejected_and_failed_tasks_into_errors() {
        assert_eq!(
            a2a_reply(&task_reply(TaskState::Rejected, Some("unsigned request"))),
            Err("A2A task task-9 rejected by the peer: unsigned request".to_string())
        );
        assert_eq!(
            a2a_reply(&task_reply(TaskState::Failed, None)),
            Err("A2A task task-9 failed on the peer: no reason given".to_string())
        );
    }

    #[test]
    fn a2a_reply_passes_other_replies_through() {
        assert_eq!(
            a2a_reply(&task_reply(TaskState::Completed, Some("done"))),
            Ok("done".to_string())
        );
        let message = SendMessageResponse::Message(Message::new(
            Role::Agent,
            vec![Part::text("hi".to_string())],
        ));
        assert_eq!(a2a_reply(&message), Ok("hi".to_string()));
    }

    #[test]
    fn ensure_file_exists_reports_missing_paths() {
        let err = ensure_file_exists(Path::new("/no/such/shadi/file"), "test file")
            .expect_err("missing file must error");
        assert!(err.contains("test file not found"));
    }

    #[test]
    fn ensure_file_exists_accepts_present_files() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("shadi-ensure-{}.tmp", std::process::id()));
        std::fs::write(&path, b"x").expect("write temp file");
        assert!(ensure_file_exists(&path, "temp file").is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn client_identity_candidates_prefers_agent_scoped_certs() {
        let base = Path::new("/tls");
        let candidates = client_identity_candidates(base, Some("avatar"));
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].0, base.join("client-avatar.crt"));
        assert_eq!(candidates[0].1, base.join("client-avatar.key"));
        assert_eq!(candidates[1].0, base.join("client.crt"));
    }

    #[test]
    fn client_identity_candidates_without_agent_only_uses_default() {
        let base = Path::new("/tls");
        let candidates = client_identity_candidates(base, None);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, base.join("client.crt"));
    }

    #[test]
    fn slim_tls_dir_ends_with_mtls_subdir() {
        assert!(slim_tls_dir().ends_with("shadi-slim-mtls"));
    }

    #[test]
    fn default_tmp_dir_targets_workspace_tmp() {
        assert!(default_tmp_dir().ends_with(".tmp"));
    }

    #[test]
    fn transient_dispatch_errors_are_classified() {
        assert!(LiveA2ATaskAdapter::is_transient_dispatch_error(
            "Session closed by peer"
        ));
        assert!(LiveA2ATaskAdapter::is_transient_dispatch_error(
            "Connection refused"
        ));
        assert!(!LiveA2ATaskAdapter::is_transient_dispatch_error(
            "invalid SLIM name"
        ));
    }

    #[test]
    fn build_client_config_for_endpoint_sets_mtls_material() {
        let tls = TlsMaterial {
            cert: PathBuf::from("/tls/client.crt"),
            key: PathBuf::from("/tls/client.key"),
            ca: PathBuf::from("/tls/ca.crt"),
        };
        let config = build_client_config_for_endpoint("node:47357", &tls);
        assert_eq!(config.endpoint, "https://node:47357");
        assert_eq!(config.connect_timeout, Some(Duration::from_secs(5)));
        assert!(matches!(config.backoff,
            Some(BackoffConfig::Exponential { config }) if config.max_attempts == 1));
        assert!(!config.tls.insecure);
        assert_eq!(config.tls.tls_version, "tls1.3");
        match config.tls.source {
            TlsSource::File { cert, key } => {
                assert_eq!(cert, "/tls/client.crt");
                assert_eq!(key, "/tls/client.key");
            }
            _ => panic!("expected file-based TLS source"),
        }
    }

    #[test]
    fn live_task_adapter_starts_with_no_dispatches() {
        let adapter = LiveA2ATaskAdapter::new(LiveA2ATaskAdapterConfig {
            endpoint: "node:47357".to_string(),
            agent_id: "avatar".to_string(),
            local_name: None,
            peer_agent_id: "peer".to_string(),
            destination: None,
            a2a_url: None,
            a2a_binding: None,
            peer_did: None,
        });
        assert!(adapter.dispatches().expect("lock").is_empty());
    }

    #[test]
    fn task_message_carries_the_peer_did() {
        let adapter = |peer_did: Option<&str>| {
            LiveA2ATaskAdapter::new(LiveA2ATaskAdapterConfig {
                endpoint: "node:47357".to_string(),
                agent_id: "avatar".to_string(),
                local_name: None,
                peer_agent_id: "peer".to_string(),
                destination: None,
                a2a_url: None,
                a2a_binding: None,
                peer_did: peer_did.map(str::to_string),
            })
        };
        let tagged = adapter(Some("did:key:zPeer")).task_message("signed");
        assert_eq!(
            shadi_a2a::dest_did_from_message(&tagged),
            Some("did:key:zPeer")
        );
        assert_eq!(readable_message_text(&tagged), "signed");
        let untagged = adapter(None).task_message("signed");
        assert_eq!(shadi_a2a::dest_did_from_message(&untagged), None);
    }

    struct Allow;

    impl AgentVerifier for Allow {
        fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
            Ok(())
        }

        fn wants_content(&self) -> bool {
            true
        }
    }

    struct Refuse;

    impl AgentVerifier for Refuse {
        fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
            Err(agent_secrets::SecretError::NotAuthorized)
        }
    }

    fn sample_adapter() -> LiveA2ATaskAdapter {
        LiveA2ATaskAdapter::new(LiveA2ATaskAdapterConfig {
            endpoint: "node:47357".to_string(),
            agent_id: "avatar".to_string(),
            local_name: None,
            peer_agent_id: "peer".to_string(),
            destination: None,
            a2a_url: None,
            a2a_binding: None,
            peer_did: None,
        })
    }

    #[test]
    fn a_policy_runs_after_the_did_check_and_cannot_replace_it() {
        let proven = SessionContext::new("avatar", "s").with_proven_did("did:key:zAvatar");
        let unproven = SessionContext::new("avatar", "s");
        let request = RequestContext::new();

        let plain = sample_adapter().verifier();
        assert!(plain.verify_request(&proven, &request).is_ok());
        assert!(plain.verify_request(&unproven, &request).is_err());
        assert!(!plain.wants_content());

        let allowing = sample_adapter().with_verifier(Arc::new(Allow)).verifier();
        assert!(allowing.verify_request(&proven, &request).is_ok());
        assert!(allowing.verify_request(&unproven, &request).is_err());
        assert!(allowing.verify(&unproven).is_err());
        assert!(allowing.wants_content());

        let refusing = sample_adapter().with_verifier(Arc::new(Refuse)).verifier();
        assert!(refusing.verify_request(&proven, &request).is_err());
        assert!(refusing.verify(&proven).is_err());
    }

    #[test]
    fn recording_messaging_adapter_captures_published_messages() {
        let adapter = RecordingMessagingAdapter::default();
        adapter.publish("topic-a", b"payload").expect("publish");
        let published = adapter.published_messages().expect("read");
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].topic, "topic-a");
        assert_eq!(published[0].payload, b"payload");
    }

    #[test]
    fn recording_task_adapter_captures_dispatched_tasks() {
        let adapter = RecordingTaskAdapter::default();
        adapter.dispatch(sample_task()).expect("dispatch");
        let tasks = adapter.dispatched_tasks().expect("read");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].task_id, "task-1");
    }

    #[test]
    fn did_proof_verifier_rejects_asserted_verified_flag() {
        let mut session = SessionContext::new("avatar", "unit-test");
        session.verified = true;
        assert!(DidProofVerifier.verify(&session).is_err());
        let proven = SessionContext::new("avatar", "unit-test").with_proven_did("did:key:zexample");
        assert!(DidProofVerifier.verify(&proven).is_ok());
    }
}
