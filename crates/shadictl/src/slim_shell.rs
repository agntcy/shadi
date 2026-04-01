use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use slim_bindings::{
    App, CaSource, ClientConfig, Name, ServerConfig, Service, Session, SessionConfig,
    SessionType, TlsClientConfig, TlsServerConfig, TlsSource,
};

const DEFAULT_SLIM_ENDPOINT: &str = "127.0.0.1:47357";
const DEFAULT_LOCAL_ORG: &str = "agntcy";
const DEFAULT_LOCAL_NAMESPACE: &str = "shadi";
const DEFAULT_LOCAL_APP: &str = "agent";
const DEFAULT_SHARED_SECRET_KEY: &str = "secops/slim_shared_secret";

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
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
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
        }
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

        Ok(format!(
            "created group session for channel {} as {}",
            channel_name,
            self.local_name_string()?
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
        Ok(format!("invited {} to {}", participant_name, channel))
    }

    pub(crate) fn join_group_session(
        &mut self,
        channel: &str,
        timeout: Option<Duration>,
    ) -> Result<String, String> {
        let expected = parse_name(channel)?;
        self.ensure_channel_subscription(channel)?;
        let app = self.ensure_app()?;
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
        let shared_secret = self.shared_secret()?;
        let app = self
            .client_service_mut()
            .create_app_with_secret(local_name.clone(), shared_secret)
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

    fn shared_secret(&mut self) -> Result<String, String> {
        if let Some(shared_secret) = &self.shared_secret {
            return Ok(shared_secret.clone());
        }

        if let Ok(shared_secret) = std::env::var("SLIM_SHARED_SECRET") {
            if !shared_secret.trim().is_empty() {
                self.shared_secret = Some(shared_secret.clone());
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
        let shared_secret = String::from_utf8(bytes)
            .map_err(|_| format!("SLIM shared secret {} is not valid UTF-8", key_name))?;

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

fn node_service_name() -> String {
    format!("shadictl-node-{}", std::process::id())
}

fn client_service_name() -> String {
    format!("shadictl-client-{}", std::process::id())
}

fn default_group_session_config() -> SessionConfig {
    SessionConfig {
        session_type: SessionType::Group,
        enable_mls: true,
        max_retries: Some(5),
        interval: Some(Duration::from_secs(5)),
        metadata: HashMap::new(),
    }
}

fn build_client_config() -> Result<ClientConfig, String> {
    let tls = resolve_client_tls_material()?;
    Ok(build_client_config_for_endpoint(&resolve_endpoint(), &tls))
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
        include_system_ca_certs_pool: true,
        tls_version: "tls1.3".to_string(),
    };
    config
}

fn build_server_config() -> Result<ServerConfig, String> {
    let cert_dir = slim_tls_dir();
    let tls = TlsMaterial {
        cert: cert_dir.join("server.crt"),
        key: cert_dir.join("server.key"),
        ca: cert_dir.join("ca.crt"),
    };

    ensure_file_exists(&tls.cert, "SLIM server certificate")?;
    ensure_file_exists(&tls.key, "SLIM server key")?;
    ensure_file_exists(&tls.ca, "SLIM client CA")?;

    Ok(build_server_config_for_endpoint(&resolve_endpoint(), &tls))
}

fn build_server_config_for_endpoint(endpoint: &str, tls: &TlsMaterial) -> ServerConfig {
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
        include_system_ca_certs_pool: Some(true),
        tls_version: Some("tls1.3".to_string()),
        reload_client_ca_file: Some(false),
    };
    config
}

fn resolve_client_tls_material() -> Result<TlsMaterial, String> {
    let cert_override = std::env::var_os("SLIM_TLS_CERT").map(PathBuf::from);
    let key_override = std::env::var_os("SLIM_TLS_KEY").map(PathBuf::from);
    let ca = std::env::var_os("SLIM_TLS_CA")
        .map(PathBuf::from)
        .unwrap_or_else(|| slim_tls_dir().join("ca.crt"));

    let (cert, key) = match (cert_override, key_override) {
        (Some(cert), Some(key)) => (cert, key),
        (Some(_), None) | (None, Some(_)) => {
            return Err("SLIM_TLS_CERT and SLIM_TLS_KEY must be set together".to_string())
        }
        (None, None) => {
            let base_dir = slim_tls_dir();
            let agent_id = std::env::var("SHADI_AGENT_ID")
                .ok()
                .filter(|value| !value.trim().is_empty());
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

fn parse_name(raw: &str) -> Result<Name, String> {
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

fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use super::*;

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
    #[ignore = "requires local SLIM mTLS assets and secret access"]
    fn live_group_session_flow_works_with_local_assets() {
        let tls_dir = default_tmp_dir().join("shadi-slim-mtls");
        let ca = tls_dir.join("ca.crt");
        ensure_file_exists(&ca, "SLIM client CA").expect("local SLIM CA");

        let server_tls = TlsMaterial {
            cert: tls_dir.join("server.crt"),
            key: tls_dir.join("server.key"),
            ca: ca.clone(),
        };
        ensure_file_exists(&server_tls.cert, "SLIM server certificate").expect("server cert");
        ensure_file_exists(&server_tls.key, "SLIM server key").expect("server key");

        let moderator_tls = live_client_tls_material(&tls_dir, "avatar");
        let participant_tls = live_client_tls_material(&tls_dir, "secops-a");
        let shared_secret = load_live_shared_secret().expect("live shared secret");
        let endpoint = reserve_test_endpoint();

        let node_service = Service::new(format!("shadictl-live-node-{}", std::process::id()));
        node_service
            .run_server(build_server_config_for_endpoint(&endpoint, &server_tls))
            .expect("start local SLIM node");
        thread::sleep(Duration::from_millis(250));

        let participant_name = Arc::new(parse_name("agntcy/shadi/secops-a").expect("participant name"));
        let moderator_name = Arc::new(parse_name("agntcy/shadi/avatar").expect("moderator name"));
        let channel_name = Arc::new(parse_name("agntcy/shadi/secops-room").expect("channel name"));

        let (ready_tx, ready_rx) = mpsc::channel();
        let endpoint_for_participant = endpoint.clone();
        let participant_name_for_thread = participant_name.clone();
        let channel_name_for_thread = channel_name.clone();
        let participant_secret = shared_secret.clone();
        let participant_handle = thread::spawn(move || -> Result<u32, String> {
            let participant_service =
                Service::new(format!("shadictl-live-participant-{}", std::process::id()));
            let connection_id = participant_service
                .connect(build_client_config_for_endpoint(
                    &endpoint_for_participant,
                    &participant_tls,
                ))
                .map_err(format_slim_error)?;
            let participant_app = participant_service
                .create_app_with_secret(participant_name_for_thread.clone(), participant_secret)
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

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("participant ready");

        let moderator_service = Service::new(format!("shadictl-live-moderator-{}", std::process::id()));
        let moderator_connection = moderator_service
            .connect(build_client_config_for_endpoint(&endpoint, &moderator_tls))
            .expect("moderator connection");
        let moderator_app = moderator_service
            .create_app_with_secret(moderator_name.clone(), shared_secret)
            .expect("moderator app");

        moderator_app
            .subscribe(moderator_name, Some(moderator_connection))
            .expect("moderator subscribe local name");
        thread::sleep(Duration::from_millis(200));

        let session = moderator_app
            .create_session_and_wait(default_group_session_config(), channel_name)
            .expect("create group session");
        let moderator_session_id = session.session_id().expect("moderator session id");
        moderator_app
            .set_route(participant_name.clone(), moderator_connection)
            .expect("set participant route");
        session
            .invite_and_wait(participant_name)
            .expect("invite participant");

        let joined_session_id = participant_handle
            .join()
            .expect("participant thread panicked")
            .expect("participant joined session");
        assert_eq!(
            moderator_session_id,
            joined_session_id,
            "moderator and participant should observe the same session id"
        );

        let _ = moderator_app.delete_session_and_wait(session);
        moderator_service
            .disconnect(moderator_connection)
            .expect("disconnect moderator client");
        moderator_service.shutdown().expect("shutdown moderator service");
        node_service
            .stop_server(endpoint.clone())
            .expect("stop node server");
        node_service.shutdown().expect("shutdown node service");
    }

    fn live_client_tls_material(base_dir: &Path, agent_id: &str) -> TlsMaterial {
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

    fn load_live_shared_secret() -> Result<String, String> {
        if let Ok(shared_secret) = std::env::var("SLIM_SHARED_SECRET") {
            if !shared_secret.trim().is_empty() {
                return Ok(shared_secret);
            }
        }

        let store = agent_secrets::default_store();
        let secret = store.get(DEFAULT_SHARED_SECRET_KEY).map_err(|err| {
            format!(
                "failed to load {} from the default secret store: {}",
                DEFAULT_SHARED_SECRET_KEY, err
            )
        })?;
        let bytes = secret.expose(|data| data.to_vec());
        String::from_utf8(bytes)
            .map_err(|_| format!("{} is not valid UTF-8", DEFAULT_SHARED_SECRET_KEY))
    }

    fn reserve_test_endpoint() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let endpoint = listener.local_addr().expect("local addr").to_string();
        drop(listener);
        endpoint
    }
}