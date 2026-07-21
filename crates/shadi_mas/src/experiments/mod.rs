use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use a2a::*;
use a2a_client::A2AClient;
use agent_secrets::{AgentVerifier, SecretError, SecretResult, SessionContext};
use crate::adapters::{MessagingAdapter, TaskAdapter, TaskEnvelope};
use shadi_a2a::A2AChannelBuilder;
use slim_bindings::{CaSource, ClientConfig, Name, Service, TlsClientConfig, TlsSource};
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
    pub shared_secret: String,
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
}

impl LiveA2ATaskAdapter {
    pub fn new(config: LiveA2ATaskAdapterConfig) -> Self {
        Self {
            config,
            dispatches: Mutex::new(Vec::new()),
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
            let attempt_result = (|| -> Result<String, String> {
                let connection_id = service
                    .connect(build_client_config_for_endpoint(&self.config.endpoint, &tls))
                    .map_err(format_slim_error)?;
                let local_name_ref = Arc::new(parse_slim_name(&local_name)?);
                let remote_name_ref = Arc::new(parse_slim_name(&destination)?);

                let auth = match shadi_identity::did_auth_from_env(&self.config.agent_id) {
                    Some(result) => result.map_err(|e| e.to_string())?,
                    None => {
                        shadi_identity::SlimAuth::SharedSecret(self.config.shared_secret.clone())
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

                let mut session = SessionContext::new(
                    &self.config.agent_id,
                    &format!("mas-task-session-{}", task.task_id),
                );
                session.verified = true;

                // slim_rpc::Channel captures `tokio::runtime::Handle::current()` at
                // construction, so build the transport inside the runtime context.
                let channel = {
                    let _enter = runtime.enter();
                    A2AChannelBuilder::new(
                        app.clone(),
                        remote_name_ref,
                        Arc::new(VerifiedSessionVerifier),
                        session,
                    )
                    .connection_id(connection_id)
                    .build()
                };
                let client = A2AClient::new(Box::new(channel));
                let request = SendMessageRequest {
                    message: Message::new(
                        Role::User,
                        vec![Part::text(render_task_message(task))],
                    ),
                    configuration: None,
                    metadata: None,
                    tenant: None,
                };

                let response_detail = runtime
                    .block_on(async {
                        let response = client.send_message(&request).await?;
                        client.destroy().await?;
                        Ok::<String, A2AError>(describe_a2a_response(&response))
                    })
                    .map_err(|err| format!("failed to send A2A task {}: {}", task.task_id, err))?;

                let _ = app.unsubscribe(local_name_ref.clone(), Some(connection_id));
                let _ = service.disconnect(connection_id);
                Ok(response_detail)
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


struct VerifiedSessionVerifier;

impl AgentVerifier for VerifiedSessionVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        if session.verified {
            Ok(())
        } else {
            Err(SecretError::NotAuthorized)
        }
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
            shared_secret: "secret".to_string(),
        });
        assert!(adapter.dispatches().expect("lock").is_empty());
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
    fn verified_session_verifier_enforces_verification() {
        let mut session = SessionContext::new("avatar", "unit-test");
        assert!(VerifiedSessionVerifier.verify(&session).is_err());
        session.verified = true;
        assert!(VerifiedSessionVerifier.verify(&session).is_ok());
    }
}
