use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use slim_bindings::{
    App, CaSource, ClientConfig, MlsSettings, Name, ServerConfig, Service, Session, SessionConfig,
    SessionType, TlsClientConfig, TlsServerConfig, TlsSource,
};

const DEFAULT_SLIM_ENDPOINT: &str = "127.0.0.1:47357";
const DEFAULT_LOCAL_ORG: &str = "agntcy";
const DEFAULT_LOCAL_NAMESPACE: &str = "shadi";
const DEFAULT_LOCAL_APP: &str = "agent";
const DEFAULT_SHARED_SECRET_KEY: &str = "secops/slim_shared_secret";

/// Membership role in the active SLIM group session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlimRole {
    /// Created the channel and invites members (bound to a human identity under DID auth).
    Moderator,
    /// Joined a channel created by a moderator.
    Participant,
}

impl SlimRole {
    fn as_str(self) -> &'static str {
        match self {
            SlimRole::Moderator => "moderator",
            SlimRole::Participant => "participant",
        }
    }
}

pub(crate) struct SlimShellState {
    node_service: Option<Service>,
    client_service: Option<Service>,
    connection_id: Option<u64>,
    app: Option<Arc<App>>,
    local_name: Option<Arc<Name>>,
    shared_secret: Option<String>,
    active_session: Option<Arc<Session>>,
    active_channel: Option<String>,
    subscribed_channel: Option<String>,
    node_started: bool,
    role: Option<SlimRole>,
}

pub(crate) struct SlimStatus {
    pub(crate) local_name: String,
    pub(crate) endpoint: String,
    pub(crate) node_started: bool,
    pub(crate) connection_id: Option<u64>,
    pub(crate) active_channel: Option<String>,
    pub(crate) active_session_id: Option<u32>,
}

#[derive(Clone)]
pub(crate) struct TlsMaterial {
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
    pub(crate) ca: PathBuf,
}

impl SlimShellState {
    pub(crate) fn new() -> Self {
        Self {
            node_service: None,
            client_service: None,
            connection_id: None,
            app: None,
            local_name: None,
            shared_secret: None,
            active_session: None,
            active_channel: None,
            subscribed_channel: None,
            node_started: false,
            role: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_test_runtime_state(
        &mut self,
        connection_id: Option<u64>,
        active_channel: Option<String>,
        node_started: bool,
    ) {
        self.connection_id = connection_id;
        self.active_channel = active_channel;
        self.node_started = node_started;
    }

    pub(crate) fn status(&self) -> Result<SlimStatus, String> {
        let active_session_id = self
            .active_session
            .as_ref()
            .map(|session| session.session_id().map_err(format_slim_error))
            .transpose()?;

        Ok(SlimStatus {
            local_name: resolve_local_name()?,
            endpoint: resolve_endpoint(),
            node_started: self.node_started,
            connection_id: self.connection_id,
            active_channel: self.active_channel.clone(),
            active_session_id,
        })
    }

    pub(crate) fn start_node(&mut self) -> Result<String, String> {
        if self.node_started {
            return Ok(format!(
                "SLIM node already running in this shell on {}",
                resolve_endpoint()
            ));
        }

        let server_config = build_server_config()?;
        self.node_service_mut()
            .run_server(server_config)
            .map_err(format_slim_error)?;
        self.node_started = true;

        Ok(format!("started SLIM node on {}", resolve_endpoint()))
    }

    pub(crate) fn create_group_session(&mut self, channel: &str) -> Result<String, String> {
        let channel_name = Arc::new(parse_name(channel)?);
        let app = self.ensure_app()?;
        let session = app
            .create_session_and_wait(default_group_session_config(), channel_name.clone())
            .map_err(format_slim_error)?;

        self.replace_active_session(app, session, channel_name.to_string())?;
        self.role = Some(SlimRole::Moderator);

        let local = self.local_name_string()?;
        let agent_id = self.agent_id()?;
        Ok(format_create_channel_message(
            &channel_name.to_string(),
            &local,
            did_identity_for_display(&agent_id),
        ))
    }

    pub(crate) fn invite_participant(&mut self, participant: &str) -> Result<String, String> {
        let participant_name = Arc::new(parse_name(participant)?);
        let connection_id = self.ensure_connection()?;
        let app = self.ensure_app()?;
        let session = self.active_session.clone().ok_or_else(|| {
            "no active SLIM session; create or join a channel first".to_string()
        })?;

        app.set_route(participant_name.clone(), connection_id)
            .map_err(format_slim_error)?;
        session
            .invite_and_wait(participant_name.clone())
            .map_err(format_slim_error)?;

        let channel = self
            .active_channel
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        let agent_id = self.agent_id()?;
        Ok(format_invite_message(
            &participant_name.to_string(),
            &channel,
            did_identity_for_display(&agent_id),
        ))
    }

    /// Broadcast a text message to the active group session (all members receive it).
    pub(crate) fn send_group_message(&mut self, text: &str) -> Result<String, String> {
        let session = self.active_session.clone().ok_or_else(|| {
            "no active SLIM session; create or join a channel first".to_string()
        })?;
        session
            .publish(text.as_bytes().to_vec(), None, Some(HashMap::new()))
            .map_err(format_slim_error)?;
        let channel = self
            .active_channel
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        Ok(format!("sent to {channel}: {text}"))
    }

    /// Block up to `timeout` for the next message on the active group session.
    pub(crate) fn receive_group_message(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<String, String> {
        let session = self.active_session.clone().ok_or_else(|| {
            "no active SLIM session; create or join a channel first".to_string()
        })?;
        let message = session.get_message(timeout).map_err(format_slim_error)?;
        Ok(format!(
            "received: {}",
            String::from_utf8_lossy(&message.payload)
        ))
    }

    pub(crate) fn join_group_session(
        &mut self,
        channel: &str,
        timeout: Option<Duration>,
    ) -> Result<String, String> {
        let expected = parse_name(channel)?;
        self.ensure_channel_subscription(channel)?;
        let connection_id = self.ensure_connection()?;
        let app = self.ensure_app()?;
        // Subscribing only enables *receiving*. To broadcast to the group, a member
        // also needs a route to the channel — otherwise its `/slim send` never
        // reaches the other members.
        app.set_route(Arc::new(parse_name(channel)?), connection_id)
            .map_err(format_slim_error)?;
        let session = app
            .listen_for_session(timeout)
            .map_err(format_slim_error)?;
        let actual = session.destination().map_err(format_slim_error)?;
        let actual_name = actual.to_string();

        if actual_name != expected.to_string() {
            let _ = app.delete_session_and_wait(session);
            return Err(format!(
                "received session for {} while waiting for {}",
                actual_name, expected
            ));
        }

        self.replace_active_session(app, session, actual_name.clone())?;
        self.role = Some(SlimRole::Participant);

        Ok(format!(
            "joined group session for channel {} as {}",
            actual_name,
            self.local_name_string()?
        ))
    }

    pub(crate) fn shutdown(&mut self) {
        if let Some(app) = self.app.clone() {
            if let Some(session) = self.active_session.take() {
                let _ = app.delete_session_and_wait(session);
            }

            if let (Some(connection_id), Some(channel)) =
                (self.connection_id, self.subscribed_channel.take())
            {
                if let Ok(channel_name) = parse_name(&channel) {
                    let _ = app.unsubscribe(Arc::new(channel_name), Some(connection_id));
                }
            }
        }

        if let (Some(service), Some(connection_id)) =
            (self.client_service.as_ref(), self.connection_id)
        {
            let _ = service.disconnect(connection_id);
        }

        if let Some(service) = self.client_service.take() {
            let _ = service.shutdown();
        }

        if let Some(service) = self.node_service.take() {
            let _ = service.shutdown();
        }

        self.connection_id = None;
        self.app = None;
        self.local_name = None;
        self.shared_secret = None;
        self.active_channel = None;
        self.subscribed_channel = None;
        self.node_started = false;
    }

    fn replace_active_session(
        &mut self,
        app: Arc<App>,
        session: Arc<Session>,
        channel: String,
    ) -> Result<(), String> {
        if let Some(existing) = self.active_session.take() {
            app.delete_session_and_wait(existing)
                .map_err(format_slim_error)?;
        }

        self.active_channel = Some(channel);
        self.active_session = Some(session);
        Ok(())
    }

    fn ensure_app(&mut self) -> Result<Arc<App>, String> {
        if let Some(app) = &self.app {
            return Ok(app.clone());
        }

        let connection_id = self.ensure_connection()?;
        let local_name = self.local_name()?;
        // DID derivation uses the app (last) component of the local name as the agent id.
        let agent_id = local_name.components().last().cloned().unwrap_or_default();
        let auth = match shadi_identity::did_auth_from_env(&agent_id) {
            Some(result) => result.map_err(|e| e.to_string())?,
            None => shadi_identity::SlimAuth::SharedSecret(self.shared_secret()?),
        };
        let app = shadi_identity::create_app(self.client_service_mut(), local_name.clone(), &auth)
            .map_err(format_slim_error)?;

        app.subscribe(local_name, Some(connection_id))
            .map_err(format_slim_error)?;
        self.app = Some(app.clone());
        Ok(app)
    }

    fn ensure_channel_subscription(&mut self, channel: &str) -> Result<(), String> {
        if self.subscribed_channel.as_deref() == Some(channel) {
            return Ok(());
        }

        let connection_id = self.ensure_connection()?;
        let app = self.ensure_app()?;

        if let Some(existing) = self.subscribed_channel.take() {
            let existing_name = Arc::new(parse_name(&existing)?);
            app.unsubscribe(existing_name, Some(connection_id))
                .map_err(format_slim_error)?;
        }

        let channel_name = Arc::new(parse_name(channel)?);
        app.subscribe(channel_name, Some(connection_id))
            .map_err(format_slim_error)?;
        self.subscribed_channel = Some(channel.to_string());
        Ok(())
    }

    fn ensure_connection(&mut self) -> Result<u64, String> {
        if let Some(connection_id) = self.connection_id {
            return Ok(connection_id);
        }

        let client_config = build_client_config()?;
        let connection_id = self
            .client_service_mut()
            .connect(client_config)
            .map_err(format_slim_error)?;
        self.connection_id = Some(connection_id);
        Ok(connection_id)
    }

    fn local_name(&mut self) -> Result<Arc<Name>, String> {
        if let Some(name) = &self.local_name {
            return Ok(name.clone());
        }

        let raw = resolve_local_name()?;
        let name = Arc::new(parse_name(&raw)?);
        self.local_name = Some(name.clone());
        Ok(name)
    }

    fn local_name_string(&mut self) -> Result<String, String> {
        Ok(self.local_name()?.to_string())
    }

    /// Agent id used for DID derivation: the app (last) component of the local name.
    fn agent_id(&mut self) -> Result<String, String> {
        Ok(self
            .local_name()?
            .components()
            .last()
            .cloned()
            .unwrap_or_default())
    }

    /// Report this agent's identity and role: agent name, auth mode, session role,
    /// and (under DID auth) its derived DID plus the human DID it belongs to.
    pub(crate) fn whoami(&mut self) -> Result<String, String> {
        let local = self.local_name_string()?;
        let agent_id = self.agent_id()?;
        let role = self.role.map(SlimRole::as_str).unwrap_or("none");
        Ok(match did_identity_for_display(&agent_id) {
            Some((did, human)) => format!(
                "agent {local}\n  auth:  did\n  role:  {role}\n  did:   {did}\n  human: {}",
                human.unwrap_or_else(|| "<unset SLIM_HUMAN_DID>".to_string())
            ),
            None => format!("agent {local}\n  auth:  shared-secret\n  role:  {role}"),
        })
    }

    fn shared_secret(&mut self) -> Result<String, String> {
        if let Some(shared_secret) = &self.shared_secret {
            return Ok(shared_secret.clone());
        }

        let shared_secret = resolve_default_shared_secret()?;
        self.shared_secret = Some(shared_secret.clone());
        Ok(shared_secret)
    }

    fn node_service_mut(&mut self) -> &mut Service {
        self.node_service
            .get_or_insert_with(|| Service::new(node_service_name()))
    }

    fn client_service_mut(&mut self) -> &mut Service {
        self.client_service
            .get_or_insert_with(|| Service::new(client_service_name()))
    }
}

pub(crate) fn run_foreground_node() -> Result<(), String> {
    let endpoint = resolve_endpoint();
    let server_config = build_server_config()?;
    let service = Service::new(node_service_name());
    service.run_server(server_config).map_err(format_slim_error)?;
    eprintln!("started SLIM node on {}", endpoint);

    wait_for_shutdown_signal()?;

    service.shutdown().map_err(format_slim_error)?;
    eprintln!("stopped SLIM node on {}", endpoint);
    Ok(())
}

fn node_service_name() -> String {
    format!("shadictl-node-{}", std::process::id())
}

fn client_service_name() -> String {
    format!("shadictl-client-{}", std::process::id())
}

#[cfg(unix)]
fn wait_for_shutdown_signal() -> Result<(), String> {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    use std::sync::atomic::{AtomicBool, Ordering};

    let interrupted = Arc::new(AtomicBool::new(false));
    for signal in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] {
        signal_hook::flag::register(signal, Arc::clone(&interrupted))
            .map_err(|err| format!("failed to install signal handler for {}: {}", signal, err))?;
    }

    while !interrupted.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(windows)]
fn wait_for_shutdown_signal() -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let interrupted = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || {
        handler_flag.store(true, Ordering::SeqCst);
    })
    .map_err(|err| format!("failed to install signal handler: {}", err))?;

    while !interrupted.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

fn default_group_session_config() -> SessionConfig {
    SessionConfig {
        session_type: SessionType::Group,
        mls_settings: Some(MlsSettings::default()),
        max_retries: Some(5),
        interval: Some(Duration::from_secs(5)),
        metadata: HashMap::new(),
    }
}

fn build_client_config() -> Result<ClientConfig, String> {
    let tls = resolve_client_tls_material_for_agent(None)?;
    Ok(build_client_config_for_endpoint(&resolve_endpoint(), &tls))
}

pub(crate) fn build_client_config_for_endpoint(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
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

fn build_server_config() -> Result<ServerConfig, String> {
    let tls = resolve_server_tls_material()?;
    Ok(build_server_config_for_endpoint(&resolve_endpoint(), &tls))
}

pub(crate) fn build_server_config_for_endpoint(endpoint: &str, tls: &TlsMaterial) -> ServerConfig {
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

pub(crate) fn resolve_server_tls_material() -> Result<TlsMaterial, String> {
    let cert_dir = slim_tls_dir();
    let tls = TlsMaterial {
        cert: cert_dir.join("server.crt"),
        key: cert_dir.join("server.key"),
        ca: cert_dir.join("ca.crt"),
    };

    ensure_file_exists(&tls.cert, "SLIM server certificate")?;
    ensure_file_exists(&tls.key, "SLIM server key")?;
    ensure_file_exists(&tls.ca, "SLIM client CA")?;

    Ok(tls)
}

#[cfg(test)]
fn resolve_client_tls_material() -> Result<TlsMaterial, String> {
    resolve_client_tls_material_for_agent(None)
}

pub(crate) fn resolve_client_tls_material_for_agent(
    agent_id_override: Option<&str>,
) -> Result<TlsMaterial, String> {
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

pub(crate) fn resolve_default_shared_secret() -> Result<String, String> {
    if let Ok(shared_secret) = std::env::var("SLIM_SHARED_SECRET") {
        if !shared_secret.trim().is_empty() {
            return Ok(shared_secret);
        }
    }

    let key_name = std::env::var("SHADI_SLIM_SHARED_SECRET_KEY")
        .unwrap_or_else(|_| DEFAULT_SHARED_SECRET_KEY.to_string());
    let store = crate::default_secret_store();
    let secret = store.get(&key_name).map_err(|err| {
        format!(
            "failed to read SLIM shared secret from {}: {}",
            key_name, err
        )
    })?;
    let bytes = secret.expose(|data| data.to_vec());
    String::from_utf8(bytes)
        .map_err(|_| format!("SLIM shared secret {} is not valid UTF-8", key_name))
}

/// Resolve how this agent authenticates to the SLIM mesh.
///
/// `SHADI_SLIM_AUTH=did` selects DID-JWT admission (agent key derived from
/// `SLIM_HUMAN_SEED`, allow-list `SLIM_MEMBER_DIDS`); anything else uses the
/// shared-secret mesh key. The DID env contract lives in
/// [`shadi_identity::did_auth_from_env`], shared by every SHADI create_app site.
pub(crate) fn resolve_slim_auth(agent_id: &str) -> Result<shadi_identity::SlimAuth, String> {
    match shadi_identity::did_auth_from_env(agent_id) {
        Some(result) => result.map_err(|e| e.to_string()),
        None => Ok(shadi_identity::SlimAuth::SharedSecret(
            resolve_default_shared_secret()?,
        )),
    }
}

/// The DID identity to display for `agent_id` when DID auth is active: its derived
/// `did:key` plus the human DID it belongs to (`SLIM_HUMAN_DID`, optional). Returns
/// `None` under shared-secret auth, so callers keep their legacy output.
fn did_identity_for_display(agent_id: &str) -> Option<(String, Option<String>)> {
    if !std::env::var("SHADI_SLIM_AUTH")
        .unwrap_or_default()
        .eq_ignore_ascii_case("did")
    {
        return None;
    }
    let seed = std::env::var("SLIM_HUMAN_SEED").ok()?;
    let agent = shadi_identity::AgentIdentity::derive(seed.as_bytes(), agent_id).ok()?;
    let human = std::env::var("SLIM_HUMAN_DID")
        .ok()
        .filter(|value| !value.trim().is_empty());
    Some((agent.did(), human))
}

/// Format the `create-channel` result: moderator DID (+ human DID) under DID auth,
/// legacy text under shared-secret. Pure so the role-visible output is unit-tested.
fn format_create_channel_message(
    channel: &str,
    local: &str,
    did: Option<(String, Option<String>)>,
) -> String {
    match did {
        Some((moderator_did, human)) => format!(
            "created channel {channel} as moderator {local} ({moderator_did}){}",
            human.map(|h| format!(" — human {h}")).unwrap_or_default()
        ),
        None => format!("created group session for channel {channel} as {local}"),
    }
}

/// Format the `invite` result: annotate with the moderator DID under DID auth.
fn format_invite_message(
    participant: &str,
    channel: &str,
    did: Option<(String, Option<String>)>,
) -> String {
    match did {
        Some((moderator_did, _)) => {
            format!("invited {participant} to {channel} (moderator {moderator_did})")
        }
        None => format!("invited {participant} to {channel}"),
    }
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

    candidates.push((
        base_dir.join("client.crt"),
        base_dir.join("client.key"),
    ));
    candidates
}

fn resolve_endpoint() -> String {
    std::env::var("SLIM_ENDPOINT").unwrap_or_else(|_| DEFAULT_SLIM_ENDPOINT.to_string())
}

fn resolve_client_endpoint_value(endpoint: &str) -> String {
    let endpoint = endpoint.to_string();
    if endpoint.contains("://") {
        endpoint
    } else {
        format!("https://{}", endpoint)
    }
}

fn resolve_local_name() -> Result<String, String> {
    let custom = std::env::var("SHADI_SLIM_LOCAL_NAME").ok();
    let agent_id = std::env::var("SHADI_AGENT_ID").ok();
    resolve_local_name_value(custom.as_deref(), agent_id.as_deref())
}

fn resolve_local_name_value(
    custom_local_name: Option<&str>,
    agent_id: Option<&str>,
) -> Result<String, String> {
    if let Some(custom_local_name) = custom_local_name {
        if custom_local_name.trim().is_empty() {
            return Err("SHADI_SLIM_LOCAL_NAME cannot be empty".to_string());
        }
        return Ok(custom_local_name.to_string());
    }

    let app = agent_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_LOCAL_APP);
    Ok(format!(
        "{}/{}/{}",
        DEFAULT_LOCAL_ORG, DEFAULT_LOCAL_NAMESPACE, app
    ))
}

pub(crate) fn parse_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|err| {
        format!(
            "invalid SLIM name {}: {} (expected organization/namespace/application)",
            raw, err
        )
    })
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

pub(crate) fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::net::TcpListener;
    #[cfg(not(windows))]
    use std::process::Command;
    #[cfg(not(windows))]
    use std::sync::mpsc;
    use std::sync::MutexGuard;
    #[cfg(not(windows))]
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[cfg(not(windows))]
    const TEST_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";

    fn lock_env() -> MutexGuard<'static, ()> {
        crate::lock_test_env()
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

    #[test]
    fn did_identity_for_display_selects_did_mode() {
        let _guard = lock_env();
        let _auth = ScopedEnvVar::set("SHADI_SLIM_AUTH", "did");
        let _seed = ScopedEnvVar::set("SLIM_HUMAN_SEED", "human-root");
        let _human = ScopedEnvVar::set("SLIM_HUMAN_DID", "did:key:zHUMAN");

        let (did, human) = did_identity_for_display("avatar").expect("did identity");
        assert!(did.starts_with("did:key:z"));
        assert_eq!(human.as_deref(), Some("did:key:zHUMAN"));
        // Deterministic, and name-scoped.
        assert_eq!(did_identity_for_display("avatar").unwrap().0, did);
        assert_ne!(did_identity_for_display("secops-a").unwrap().0, did);
    }

    #[test]
    fn did_identity_for_display_none_under_shared_secret() {
        let _guard = lock_env();
        let _auth = ScopedEnvVar::unset("SHADI_SLIM_AUTH");
        assert!(did_identity_for_display("avatar").is_none());
    }

    #[test]
    fn format_create_channel_message_covers_all_modes() {
        // Shared-secret: legacy text, no DID.
        assert_eq!(
            format_create_channel_message("agntcy/shadi/room", "agntcy/shadi/avatar", None),
            "created group session for channel agntcy/shadi/room as agntcy/shadi/avatar"
        );
        // DID, no human DID.
        let did = format_create_channel_message(
            "agntcy/shadi/room",
            "agntcy/shadi/avatar",
            Some(("did:key:zMOD".to_string(), None)),
        );
        assert!(did.contains("as moderator agntcy/shadi/avatar (did:key:zMOD)"), "{did}");
        assert!(!did.contains("human"), "{did}");
        // DID + human DID.
        let both = format_create_channel_message(
            "agntcy/shadi/room",
            "agntcy/shadi/avatar",
            Some(("did:key:zMOD".to_string(), Some("did:key:zHUMAN".to_string()))),
        );
        assert!(both.contains("(did:key:zMOD)"), "{both}");
        assert!(both.contains("human did:key:zHUMAN"), "{both}");
    }

    #[test]
    fn format_invite_message_covers_all_modes() {
        assert_eq!(
            format_invite_message("agntcy/shadi/secops-a", "agntcy/shadi/room", None),
            "invited agntcy/shadi/secops-a to agntcy/shadi/room"
        );
        let did = format_invite_message(
            "agntcy/shadi/secops-a",
            "agntcy/shadi/room",
            Some(("did:key:zMOD".to_string(), Some("did:key:zHUMAN".to_string()))),
        );
        assert_eq!(
            did,
            "invited agntcy/shadi/secops-a to agntcy/shadi/room (moderator did:key:zMOD)"
        );
    }

    #[test]
    fn whoami_reports_moderator_did_and_human() {
        let _guard = lock_env();
        let _custom = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
        let _agent = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
        let _auth = ScopedEnvVar::set("SHADI_SLIM_AUTH", "did");
        let _seed = ScopedEnvVar::set("SLIM_HUMAN_SEED", "human-root");
        let _human = ScopedEnvVar::set("SLIM_HUMAN_DID", "did:key:zHUMAN");

        let mut state = SlimShellState::new();
        state.role = Some(SlimRole::Moderator);
        let out = state.whoami().expect("whoami");
        assert!(out.contains("role:  moderator"), "{out}");
        assert!(out.contains("auth:  did"), "{out}");
        assert!(out.contains("did:key:zHUMAN"), "{out}");
        assert!(out.contains("agntcy/shadi/avatar"), "{out}");
    }

    #[test]
    fn whoami_shared_secret_has_no_did_lines() {
        let _guard = lock_env();
        let _custom = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
        let _agent = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
        let _auth = ScopedEnvVar::unset("SHADI_SLIM_AUTH");

        let mut state = SlimShellState::new();
        let out = state.whoami().expect("whoami");
        assert!(out.contains("auth:  shared-secret"), "{out}");
        assert!(out.contains("role:  none"), "{out}");
        assert!(!out.contains("did:key:"), "{out}");
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "shadi-slim-shell-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_test_file(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(path, b"test").expect("write test file");
    }

    #[cfg(not(windows))]
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

    #[test]
    fn given_custom_local_name_when_resolving_then_it_is_used_verbatim() {
        let resolved = resolve_local_name_value(Some("agntcy/secops/observer"), Some("avatar"))
            .expect("local name");

        assert_eq!(resolved, "agntcy/secops/observer");
    }

    #[test]
    fn given_agent_id_when_resolving_local_name_then_it_uses_canonical_components() {
        let resolved = resolve_local_name_value(None, Some("avatar")).expect("local name");

        assert_eq!(resolved, "agntcy/shadi/avatar");
    }

    #[test]
    fn given_missing_agent_id_when_resolving_local_name_then_default_app_is_used() {
        let resolved = resolve_local_name_value(None, None).expect("local name");

        assert_eq!(resolved, "agntcy/shadi/agent");
    }

    #[test]
    fn given_bare_endpoint_when_resolving_client_endpoint_then_https_is_added() {
        let endpoint = resolve_client_endpoint_value("127.0.0.1:47357");

        assert_eq!(endpoint, "https://127.0.0.1:47357");
    }

    #[test]
    fn given_url_endpoint_when_resolving_client_endpoint_then_it_is_preserved() {
        let endpoint = resolve_client_endpoint_value("https://127.0.0.1:47357");

        assert_eq!(endpoint, "https://127.0.0.1:47357");
    }

    #[test]
    fn given_agent_id_when_building_client_identity_candidates_then_agent_pair_is_first() {
        let base = Path::new("/tmp/shadi-slim-mtls");
        let candidates = client_identity_candidates(base, Some("avatar"));

        assert_eq!(
            candidates[0],
            (
                PathBuf::from("/tmp/shadi-slim-mtls/client-avatar.crt"),
                PathBuf::from("/tmp/shadi-slim-mtls/client-avatar.key")
            )
        );
        assert_eq!(
            candidates[1],
            (
                PathBuf::from("/tmp/shadi-slim-mtls/client.crt"),
                PathBuf::from("/tmp/shadi-slim-mtls/client.key")
            )
        );
    }

    #[test]
    fn given_invalid_name_when_parsing_then_error_mentions_canonical_format() {
        let err = parse_name("did:key:z6Mk...").expect_err("invalid name");

        assert!(err.contains("organization/namespace/application"));
    }

    #[test]
    fn given_empty_custom_local_name_when_resolving_then_it_is_rejected() {
        let err = resolve_local_name_value(Some("  "), Some("avatar"))
            .expect_err("empty local name");

        assert!(err.contains("cannot be empty"));
    }

    #[test]
    fn given_status_when_state_has_values_then_it_reports_them() {
        let _guard = lock_env();
        let _local_name = ScopedEnvVar::set("SHADI_SLIM_LOCAL_NAME", "agntcy/shadi/custom");
        let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", "10.0.0.9:8855");

        let mut state = SlimShellState::new();
        state.connection_id = Some(17);
        state.active_channel = Some("agntcy/shadi/secops-room".to_string());
        state.node_started = true;

        let status = state.status().expect("status");

        assert_eq!(status.local_name, "agntcy/shadi/custom");
        assert_eq!(status.endpoint, "10.0.0.9:8855");
        assert!(status.node_started);
        assert_eq!(status.connection_id, Some(17));
        assert_eq!(
            status.active_channel.as_deref(),
            Some("agntcy/shadi/secops-room")
        );
        assert_eq!(status.active_session_id, None);
    }

    #[test]
    fn given_started_node_when_starting_again_then_existing_message_is_returned() {
        let mut state = SlimShellState::new();
        state.node_started = true;

        let message = state.start_node().expect("already started message");

        assert!(message.contains("already running"));
    }

    #[test]
    fn given_state_when_shutting_down_then_runtime_fields_are_cleared() {
        let mut state = SlimShellState::new();
        state.connection_id = Some(5);
        state.local_name = Some(Arc::new(parse_name("agntcy/shadi/avatar").expect("name")));
        state.shared_secret = Some("shared-secret".to_string());
        state.active_channel = Some("agntcy/shadi/secops-room".to_string());
        state.subscribed_channel = Some("agntcy/shadi/secops-room".to_string());
        state.node_started = true;

        state.shutdown();

        assert!(state.connection_id.is_none());
        assert!(state.local_name.is_none());
        assert!(state.shared_secret.is_none());
        assert!(state.active_channel.is_none());
        assert!(state.subscribed_channel.is_none());
        assert!(!state.node_started);
    }

    #[test]
    fn given_existing_channel_subscription_when_ensuring_then_it_is_a_noop() {
        let mut state = SlimShellState::new();
        state.subscribed_channel = Some("agntcy/shadi/secops-room".to_string());

        state
            .ensure_channel_subscription("agntcy/shadi/secops-room")
            .expect("same subscription");
    }

    #[test]
    fn given_existing_connection_id_when_ensuring_then_it_is_reused() {
        let mut state = SlimShellState::new();
        state.connection_id = Some(23);

        assert_eq!(state.ensure_connection().expect("existing connection"), 23);
    }

    #[test]
    fn given_cached_local_name_when_loading_then_it_is_reused() {
        let mut state = SlimShellState::new();
        state.local_name = Some(Arc::new(parse_name("agntcy/shadi/avatar").expect("name")));

        assert_eq!(
            state.local_name().expect("local name").to_string(),
            parse_name("agntcy/shadi/avatar")
                .expect("expected name")
                .to_string()
        );
    }

    #[test]
    fn given_cached_local_name_when_stringifying_then_it_is_returned() {
        let mut state = SlimShellState::new();
        state.local_name = Some(Arc::new(parse_name("agntcy/shadi/avatar").expect("name")));

        assert_eq!(
            state.local_name_string().expect("local name string"),
            parse_name("agntcy/shadi/avatar")
                .expect("expected name")
                .to_string()
        );
    }

    #[test]
    fn given_cached_shared_secret_when_loading_then_it_is_reused() {
        let mut state = SlimShellState::new();
        state.shared_secret = Some("cached-secret".to_string());

        assert_eq!(state.shared_secret().expect("shared secret"), "cached-secret");
    }

    #[test]
    fn given_default_group_session_config_when_built_then_defaults_are_expected() {
        let config = default_group_session_config();

        assert_eq!(config.session_type, SessionType::Group);
        assert!(config.mls_settings.is_some());
        assert_eq!(config.max_retries, Some(5));
        assert_eq!(config.interval, Some(Duration::from_secs(5)));
        assert!(config.metadata.is_empty());
    }

    #[test]
    fn given_node_and_client_service_names_when_generated_then_prefixes_match() {
        assert!(node_service_name().starts_with("shadictl-node-"));
        assert!(client_service_name().starts_with("shadictl-client-"));
    }

    #[test]
    fn given_endpoint_and_tls_when_building_client_config_then_paths_are_embedded() {
        let tls = TlsMaterial {
            cert: PathBuf::from("/tmp/client.crt"),
            key: PathBuf::from("/tmp/client.key"),
            ca: PathBuf::from("/tmp/ca.crt"),
        };

        let config = build_client_config_for_endpoint("127.0.0.1:47357", &tls);

        assert_eq!(config.endpoint, "https://127.0.0.1:47357");
        match config.tls.source {
            TlsSource::File { cert, key } => {
                assert_eq!(cert, "/tmp/client.crt");
                assert_eq!(key, "/tmp/client.key");
            }
            other => panic!("unexpected TLS source: {:?}", other),
        }
        match config.tls.ca_source {
            CaSource::File { path } => assert_eq!(path, "/tmp/ca.crt"),
            other => panic!("unexpected CA source: {:?}", other),
        }
        assert!(!config.tls.include_system_ca_certs_pool);
        assert_eq!(config.tls.tls_version, "tls1.3");
    }

    #[test]
    fn given_endpoint_and_tls_when_building_server_config_then_paths_are_embedded() {
        let tls = TlsMaterial {
            cert: PathBuf::from("/tmp/server.crt"),
            key: PathBuf::from("/tmp/server.key"),
            ca: PathBuf::from("/tmp/ca.crt"),
        };

        let config = build_server_config_for_endpoint("127.0.0.1:47357", &tls);

        assert_eq!(config.endpoint, "127.0.0.1:47357");
        match config.tls.source {
            TlsSource::File { cert, key } => {
                assert_eq!(cert, "/tmp/server.crt");
                assert_eq!(key, "/tmp/server.key");
            }
            other => panic!("unexpected TLS source: {:?}", other),
        }
        match config.tls.client_ca {
            CaSource::File { path } => assert_eq!(path, "/tmp/ca.crt"),
            other => panic!("unexpected client CA source: {:?}", other),
        }
        assert_eq!(config.tls.include_system_ca_certs_pool, Some(false));
        assert_eq!(config.tls.tls_version.as_deref(), Some("tls1.3"));
        assert_eq!(config.tls.reload_client_ca_file, Some(false));
    }

    #[test]
    fn given_only_cert_override_when_resolving_client_tls_then_it_is_rejected() {
        let _guard = lock_env();
        let _cert = ScopedEnvVar::set("SLIM_TLS_CERT", "/tmp/client.crt");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");

        let err = match resolve_client_tls_material() {
            Ok(_) => panic!("expected missing key override to fail"),
            Err(err) => err,
        };

        assert!(err.contains("must be set together"));
    }

    #[test]
    fn given_explicit_tls_overrides_when_resolving_client_tls_then_they_are_used() {
        let _guard = lock_env();
        let dir = TestDir::new("shell-explicit-tls");
        let cert = dir.path().join("client.crt");
        let key = dir.path().join("client.key");
        let ca = dir.path().join("ca.crt");
        write_test_file(&cert);
        write_test_file(&key);
        write_test_file(&ca);

        let _cert = ScopedEnvVar::set("SLIM_TLS_CERT", cert.as_os_str());
        let _key = ScopedEnvVar::set("SLIM_TLS_KEY", key.as_os_str());
        let _ca = ScopedEnvVar::set("SLIM_TLS_CA", ca.as_os_str());
        let _agent_id = ScopedEnvVar::unset("SHADI_AGENT_ID");

        let tls = resolve_client_tls_material().expect("tls material");

        assert_eq!(tls.cert, cert);
        assert_eq!(tls.key, key);
        assert_eq!(tls.ca, ca);
    }

    #[test]
    fn given_shared_secret_env_when_loading_then_override_is_used() {
        let _guard = lock_env();
        let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", "shared-secret");

        assert_eq!(SlimShellState::new().shared_secret().expect("shared secret"), "shared-secret");
    }

    #[test]
    fn given_store_key_override_when_loading_shared_secret_then_store_value_is_used() {
        let _guard = lock_env();
        let key_name = format!("secops/test-shared-secret-{}", std::process::id());
        crate::test_store_put(&key_name, b"stored-shared-secret");

        let _secret = ScopedEnvVar::unset("SLIM_SHARED_SECRET");
        let _key_name = ScopedEnvVar::set("SHADI_SLIM_SHARED_SECRET_KEY", &key_name);

        assert_eq!(
            resolve_default_shared_secret().expect("shared secret from store"),
            "stored-shared-secret"
        );
    }

    #[test]
    fn given_non_utf8_store_secret_when_loading_shared_secret_then_error_is_returned() {
        let _guard = lock_env();
        let key_name = format!("secops/test-shared-secret-nonutf8-{}", std::process::id());
        crate::test_store_put(&key_name, &[0xff, 0xfe]);

        let _secret = ScopedEnvVar::unset("SLIM_SHARED_SECRET");
        let _key_name = ScopedEnvVar::set("SHADI_SLIM_SHARED_SECRET_KEY", &key_name);

        let err = resolve_default_shared_secret().expect_err("non-utf8 secret should fail");
        assert!(err.contains("not valid UTF-8"));
    }

    #[test]
    fn given_agent_specific_tls_material_when_resolving_then_agent_pair_is_used() {
        let _guard = lock_env();
        let dir = TestDir::new("shell-agent-specific-tls");
        let tls_dir = dir.path().join("shadi-slim-mtls");
        fs::create_dir_all(&tls_dir).expect("create tls dir");

        let cert = tls_dir.join("client-avatar.crt");
        let key = tls_dir.join("client-avatar.key");
        let ca = tls_dir.join("ca.crt");
        write_test_file(&cert);
        write_test_file(&key);
        write_test_file(&ca);

        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");
        let _agent_id = ScopedEnvVar::unset("SHADI_AGENT_ID");

        let tls = resolve_client_tls_material_for_agent(Some("avatar")).expect("agent tls material");

        assert_eq!(tls.cert, cert);
        assert_eq!(tls.key, key);
        assert_eq!(tls.ca, ca);
    }

    #[test]
    #[cfg(not(windows))]
    fn given_generated_assets_when_inviting_without_active_session_then_error_is_returned() {
        let _guard = lock_env();
        let dir = TestDir::new("shell-invite-without-session");
        let endpoint = reserve_test_endpoint();

        generate_test_tls_dir(dir.path());

        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", &endpoint);
        let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", TEST_SHARED_SECRET);
        let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
        let _local_name = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

        let mut state = SlimShellState::new();
        let start_message = state.start_node().expect("start node");
        assert!(start_message.contains("started SLIM node on"));
        thread::sleep(Duration::from_millis(250));

        let err = state
            .invite_participant("agntcy/shadi/secops-a")
            .expect_err("invite without active session");

        assert!(err.contains("no active SLIM session"));
        state.shutdown();
    }

    #[test]
    #[cfg(not(windows))]
    fn given_generated_assets_when_joining_group_session_then_state_is_updated() {
        let _guard = lock_env();
        let dir = TestDir::new("shell-join-group-flow");
        let tls_dir = generate_test_tls_dir(dir.path());
        let endpoint = reserve_test_endpoint();
        let moderator_tls = test_client_tls_material(&tls_dir, "avatar");
        let participant_name =
            Arc::new(parse_name("agntcy/shadi/secops-a").expect("participant name"));
        let channel_name =
            Arc::new(parse_name("agntcy/shadi/secops-room").expect("channel name"));

        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", &endpoint);
        let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", TEST_SHARED_SECRET);
        let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "secops-a");
        let _local_name = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

        let mut state = SlimShellState::new();
        let start_message = state.start_node().expect("start node");
        assert!(start_message.contains("started SLIM node on"));
        thread::sleep(Duration::from_millis(250));

        let (start_tx, start_rx) = mpsc::channel();
        let endpoint_for_moderator = endpoint.clone();
        let participant_name_for_thread = participant_name.clone();
        let channel_name_for_thread = channel_name.clone();
        let moderator_handle = thread::spawn(move || -> Result<(u32, String), String> {
            let moderator_service =
                Service::new(format!("shadictl-test-moderator-{}", std::process::id()));
            let moderator_name = Arc::new(parse_name("agntcy/shadi/avatar").expect("moderator name"));
            let connection_id = moderator_service
                .connect(build_client_config_for_endpoint(
                    &endpoint_for_moderator,
                    &moderator_tls,
                ))
                .map_err(format_slim_error)?;
            let moderator_app = moderator_service
                .create_app_with_secret(moderator_name.clone(), TEST_SHARED_SECRET.to_string())
                .map_err(format_slim_error)?;

            moderator_app
                .subscribe(moderator_name, Some(connection_id))
                .map_err(format_slim_error)?;
            start_rx.recv().map_err(|err| err.to_string())?;
            thread::sleep(Duration::from_millis(300));

            let session = moderator_app
                .create_session_and_wait(default_group_session_config(), channel_name_for_thread)
                .map_err(format_slim_error)?;
            let session_id = session.session_id().map_err(format_slim_error)?;
            moderator_app
                .set_route(participant_name_for_thread.clone(), connection_id)
                .map_err(format_slim_error)?;
            session
                .invite_and_wait(participant_name_for_thread)
                .map_err(format_slim_error)?;

            // Regression check for the participant->channel route fix in
            // join_group_session: without it, a participant's broadcast never
            // reaches the moderator (it has nowhere to route to but back to the
            // moderator's own session).
            let received = session
                .get_message(Some(Duration::from_secs(15)))
                .map_err(format_slim_error)?;
            let payload = String::from_utf8_lossy(&received.payload).to_string();

            let _ = moderator_app.delete_session_and_wait(session);
            moderator_service
                .disconnect(connection_id)
                .map_err(format_slim_error)?;
            moderator_service.shutdown().map_err(format_slim_error)?;
            Ok((session_id, payload))
        });

        start_tx.send(()).expect("start moderator flow");

        let join_message = state
            .join_group_session("agntcy/shadi/secops-room", Some(Duration::from_secs(20)))
            .expect("join group session");
        assert!(join_message.contains("joined group session"));

        let sent_message = state
            .send_group_message("hello from participant")
            .expect("participant broadcast to the group");
        assert!(sent_message.contains("sent to"));

        let status = state.status().expect("status after join");
        let joined_session_id = status.active_session_id.expect("joined session id");
        let (moderator_session_id, moderator_received) = moderator_handle
            .join()
            .expect("moderator thread panicked")
            .expect("moderator session id and received payload");

        assert_eq!(joined_session_id, moderator_session_id);
        assert_eq!(moderator_received, "hello from participant");
        state.shutdown();
    }

    #[test]
    #[cfg(not(windows))]
    fn given_generated_assets_when_group_session_is_created_then_state_methods_succeed() {
        let _guard = lock_env();
        let dir = TestDir::new("shell-generated-group-flow");
        let tls_dir = generate_test_tls_dir(dir.path());
        let participant_tls = test_client_tls_material(&tls_dir, "secops-a");
        let endpoint = reserve_test_endpoint();
        let participant_name =
            Arc::new(parse_name("agntcy/shadi/secops-a").expect("participant name"));
        let channel_name =
            Arc::new(parse_name("agntcy/shadi/secops-room").expect("channel name"));

        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", &endpoint);
        let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", TEST_SHARED_SECRET);
        let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
        let _local_name = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

        let (ready_tx, ready_rx) = mpsc::channel();
        let endpoint_for_participant = endpoint.clone();
        let participant_name_for_thread = participant_name.clone();
        let channel_name_for_thread = channel_name.clone();
        let participant_handle = thread::spawn(move || -> Result<u32, String> {
            let participant_service =
                Service::new(format!("shadictl-test-participant-{}", std::process::id()));
            let connection_id = participant_service
                .connect(build_client_config_for_endpoint(
                    &endpoint_for_participant,
                    &participant_tls,
                ))
                .map_err(format_slim_error)?;
            let participant_app = participant_service
                .create_app_with_secret(
                    participant_name_for_thread.clone(),
                    TEST_SHARED_SECRET.to_string(),
                )
                .map_err(format_slim_error)?;

            participant_app
                .subscribe(participant_name_for_thread, Some(connection_id))
                .map_err(format_slim_error)?;
            participant_app
                .subscribe(channel_name_for_thread.clone(), Some(connection_id))
                .map_err(format_slim_error)?;
            thread::sleep(Duration::from_millis(200));
            ready_tx.send(()).map_err(|err| err.to_string())?;

            let session = participant_app
                .listen_for_session(Some(Duration::from_secs(20)))
                .map_err(format_slim_error)?;
            let actual_channel = session.destination().map_err(format_slim_error)?;
            if actual_channel.to_string() != channel_name_for_thread.to_string() {
                return Err(format!(
                    "participant received session for {} instead of {}",
                    actual_channel, channel_name_for_thread
                ));
            }

            let session_id = session.session_id().map_err(format_slim_error)?;
            let _ = participant_app.delete_session_and_wait(session);
            participant_service
                .disconnect(connection_id)
                .map_err(format_slim_error)?;
            participant_service.shutdown().map_err(format_slim_error)?;
            Ok(session_id)
        });

        let mut state = SlimShellState::new();
        let start_message = state.start_node().expect("start node");
        assert!(start_message.contains("started SLIM node on"));
        thread::sleep(Duration::from_millis(250));

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("participant ready");

        let create_message = state
            .create_group_session("agntcy/shadi/secops-room")
            .expect("create group session");
        assert!(create_message.contains("created group session"));

        let created_status = state.status().expect("status after create");
        assert!(created_status.node_started);
        assert_eq!(
            created_status.active_channel.as_deref(),
            Some(
                parse_name("agntcy/shadi/secops-room")
                    .expect("expected channel name")
                    .to_string()
                    .as_str(),
            )
        );
        let session_id = created_status.active_session_id.expect("active session id");

        let invite_message = state
            .invite_participant("agntcy/shadi/secops-a")
            .expect("invite participant");
        assert!(invite_message.contains("invited"));
        assert!(invite_message.contains("agntcy/shadi/secops-a"));

        let joined_session_id = participant_handle
            .join()
            .expect("participant thread panicked")
            .expect("participant joined session");
        assert_eq!(session_id, joined_session_id);

        state.shutdown();

        let shutdown_status = state.status().expect("status after shutdown");
        assert!(!shutdown_status.node_started);
        assert!(shutdown_status.active_channel.is_none());
        assert!(shutdown_status.active_session_id.is_none());
        assert!(shutdown_status.connection_id.is_none());
    }

    #[cfg(not(windows))]
    fn test_client_tls_material(base_dir: &Path, agent_id: &str) -> TlsMaterial {
        let (cert, key) = client_identity_candidates(base_dir, Some(agent_id))
            .into_iter()
            .find(|(cert, key)| cert.is_file() && key.is_file())
            .unwrap_or_else(|| panic!("missing client TLS material for {}", agent_id));

        TlsMaterial {
            cert,
            key,
            ca: base_dir.join("ca.crt"),
        }
    }

    #[cfg(not(windows))]
    fn reserve_test_endpoint() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let endpoint = listener.local_addr().expect("local addr").to_string();
        drop(listener);
        endpoint
    }
}