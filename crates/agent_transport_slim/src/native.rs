// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_secrets::{SecretError, SecretResult};
use slim_bindings::{
    App, MlsSettings, Name, Service, Session, SessionConfig, SessionType, SlimError,
};

use crate::client_access::ClientAccess;
use crate::SlimSession;

const DEFAULT_SLIM_ENDPOINT: &str = "127.0.0.1:47357";
const DEFAULT_LOCAL_ORG: &str = "agntcy";
const DEFAULT_LOCAL_NAMESPACE: &str = "shadi";
const DEFAULT_LOCAL_APP: &str = "agent";
const DEFAULT_SHARED_SECRET_KEY: &str = "secops/slim_shared_secret";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeSlimBootstrap {
    PointToPoint { destination: String },
    GroupJoin {
        channel: String,
        timeout: Option<Duration>,
    },
}

impl NativeSlimBootstrap {
    pub(crate) fn description(&self) -> &'static str {
        match self {
            Self::PointToPoint { .. } => "point-to-point",
            Self::GroupJoin { .. } => "group",
        }
    }
}

pub struct NativeSlimSession {
    service: Service,
    app: Arc<App>,
    session: Arc<Session>,
    connection_id: u64,
    subscriptions: Vec<Arc<Name>>,
    local_name: String,
    target: String,
    mode: NativeSlimBootstrap,
}

impl NativeSlimSession {
    pub fn from_env(bootstrap: NativeSlimBootstrap) -> Result<Self, String> {
        let local_name = resolve_local_name()?;
        let local_name_ref = Arc::new(parse_name(&local_name)?);
        // DID derivation uses the app (last) component of the local name.
        let agent_id = local_name.rsplit('/').next().unwrap_or(&local_name).to_string();
        let client_config = ClientAccess::from_env(None)?.client_config(&resolve_endpoint());
        let service = Service::new(client_service_name());

        let mut connection_id = None;
        let mut app: Option<Arc<App>> = None;
        let mut session: Option<Arc<Session>> = None;
        let mut subscriptions: Vec<Arc<Name>> = Vec::new();

        let established = (|| -> Result<(Arc<App>, Arc<Session>, u64, String), String> {
            let connected_id = service.connect(client_config).map_err(format_slim_error)?;
            connection_id = Some(connected_id);

            let auth = match shadi_identity::did_auth_from_env(&agent_id) {
                Some(result) => result.map_err(|e| e.to_string())?,
                None => shadi_identity::SlimAuth::SharedSecret(resolve_shared_secret()?),
            };
            let created_app = shadi_identity::create_app(&service, local_name_ref.clone(), &auth)
                .map_err(format_slim_error)?;
            created_app
                .subscribe(local_name_ref.clone(), Some(connected_id))
                .map_err(format_slim_error)?;
            subscriptions.push(local_name_ref.clone());
            app = Some(created_app.clone());

            let (created_session, target) = match bootstrap.clone() {
                NativeSlimBootstrap::PointToPoint { destination } => {
                    let destination_name = Arc::new(parse_name(&destination)?);
                    created_app
                        .set_route(destination_name.clone(), connected_id)
                        .map_err(format_slim_error)?;
                    let created_session = created_app
                        .create_session_and_wait(
                            point_to_point_session_config(),
                            destination_name,
                        )
                        .map_err(format_slim_error)?;
                    let actual_target = created_session
                        .destination()
                        .map_err(format_slim_error)?
                        .to_string();
                    (created_session, actual_target)
                }
                NativeSlimBootstrap::GroupJoin { channel, timeout } => {
                    let channel_name = Arc::new(parse_name(&channel)?);
                    created_app
                        .subscribe(channel_name.clone(), Some(connected_id))
                        .map_err(format_slim_error)?;
                    subscriptions.push(channel_name.clone());

                    let created_session = created_app
                        .listen_for_session(timeout)
                        .map_err(format_slim_error)?;
                    let actual_target = created_session
                        .destination()
                        .map_err(format_slim_error)?
                        .to_string();
                    if actual_target != channel_name.to_string() {
                        let _ = created_app.delete_session_and_wait(created_session.clone());
                        return Err(format!(
                            "received session for {} while waiting for {}",
                            actual_target, channel_name
                        ));
                    }
                    (created_session, actual_target)
                }
            };

            session = Some(created_session.clone());
            Ok((created_app, created_session, connected_id, target))
        })();

        match established {
            Ok((app, session, connection_id, target)) => Ok(Self {
                service,
                app,
                session,
                connection_id,
                subscriptions,
                local_name,
                target,
                mode: bootstrap,
            }),
            Err(err) => {
                if let (Some(app), Some(session)) = (app.as_ref(), session.take()) {
                    let _ = app.delete_session_and_wait(session);
                }
                if let (Some(app), Some(connection_id)) = (app.as_ref(), connection_id) {
                    for subscription in &subscriptions {
                        let _ = app.unsubscribe(subscription.clone(), Some(connection_id));
                    }
                }
                if let Some(connection_id) = connection_id {
                    let _ = service.disconnect(connection_id);
                }
                let _ = service.shutdown();
                Err(err)
            }
        }
    }

    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn mode(&self) -> &NativeSlimBootstrap {
        &self.mode
    }

    pub fn session_id(&self) -> Result<u32, String> {
        self.session.session_id().map_err(format_slim_error)
    }

    pub fn publish_bytes(
        &self,
        payload: Vec<u8>,
        payload_type: Option<String>,
    ) -> Result<(), String> {
        self.session
            .publish_and_wait(payload, payload_type, Some(HashMap::new()))
            .map_err(format_slim_error)
    }

    pub fn receive_bytes(&self, timeout: Option<Duration>) -> Result<Vec<u8>, String> {
        self.receive_bytes_raw(timeout).map_err(format_slim_error)
    }

    pub fn receive_bytes_raw(&self, timeout: Option<Duration>) -> Result<Vec<u8>, SlimError> {
        self.session.get_message(timeout).map(|message| message.payload)
    }
}

impl SlimSession for NativeSlimSession {
    fn send(&self, message: &[u8]) -> SecretResult<()> {
        self.publish_bytes(message.to_vec(), None)
            .map_err(|_| SecretError::StorageFailure)
    }

    fn recv(&self) -> SecretResult<Vec<u8>> {
        self.receive_bytes(None)
            .map_err(|_| SecretError::StorageFailure)
    }
}

impl Drop for NativeSlimSession {
    fn drop(&mut self) {
        let _ = self.app.delete_session_and_wait(self.session.clone());
        for subscription in &self.subscriptions {
            let _ = self
                .app
                .unsubscribe(subscription.clone(), Some(self.connection_id));
        }
        let _ = self.service.disconnect(self.connection_id);
        let _ = self.service.shutdown();
    }
}

fn client_service_name() -> String {
    format!("shadi-slim-bridge-{}", std::process::id())
}

fn point_to_point_session_config() -> SessionConfig {
    SessionConfig {
        session_type: SessionType::PointToPoint,
        mls_settings: Some(MlsSettings::default()),
        max_retries: Some(5),
        interval: Some(Duration::from_secs(5)),
        metadata: HashMap::new(),
    }
}

fn resolve_endpoint() -> String {
    std::env::var("SLIM_ENDPOINT").unwrap_or_else(|_| DEFAULT_SLIM_ENDPOINT.to_string())
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

fn resolve_shared_secret() -> Result<String, String> {
    if let Ok(shared_secret) = std::env::var("SLIM_SHARED_SECRET") {
        if !shared_secret.trim().is_empty() {
            return Ok(shared_secret);
        }
    }

    let key_name = std::env::var("SHADI_SLIM_SHARED_SECRET_KEY")
        .unwrap_or_else(|_| DEFAULT_SHARED_SECRET_KEY.to_string());
    let store = agent_secrets::default_store();
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

fn parse_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|err| {
        format!(
            "invalid SLIM name {}: {} (expected organization/namespace/application)",
            raw, err
        )
    })
}

fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    #[cfg(not(windows))]
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    #[cfg(not(windows))]
    use std::process::Command;
    #[cfg(not(windows))]
    use std::sync::mpsc;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    #[cfg(not(windows))]
    const TEST_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";

    fn env_lock() -> &'static Mutex<()> {
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
                "shadi-agent-transport-slim-{label}-{}-{unique}",
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

    #[cfg(not(windows))]
    struct TlsMaterial {
        cert: PathBuf,
        key: PathBuf,
        ca: PathBuf,
    }

    #[cfg(not(windows))]
    fn test_client_tls_material(base_dir: &Path, agent_id: &str) -> ClientAccess {
        ClientAccess::mtls(
            base_dir.join(format!("client-{agent_id}.crt")),
            base_dir.join(format!("client-{agent_id}.key")),
            base_dir.join("ca.crt"),
        )
    }

    #[cfg(not(windows))]
    fn test_server_tls_material(base_dir: &Path) -> TlsMaterial {
        TlsMaterial {
            cert: base_dir.join("server.crt"),
            key: base_dir.join("server.key"),
            ca: base_dir.join("ca.crt"),
        }
    }

    #[cfg(not(windows))]
    fn build_test_server_config(endpoint: &str, tls: &TlsMaterial) -> slim_bindings::ServerConfig {
        slim_bindings::ServerConfig {
            endpoint: endpoint.to_string(),
            tls: slim_bindings::TlsServerConfig {
                insecure: false,
                source: slim_bindings::TlsSource::File {
                    cert: tls.cert.display().to_string(),
                    key: tls.key.display().to_string(),
                },
                client_ca: slim_bindings::CaSource::File {
                    path: tls.ca.display().to_string(),
                },
                include_system_ca_certs_pool: Some(false),
                tls_version: Some("tls1.3".to_string()),
                reload_client_ca_file: Some(false),
            },
            ..slim_bindings::ServerConfig::default()
        }
    }

    #[cfg(not(windows))]
    fn reserve_test_endpoint() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let endpoint = listener.local_addr().expect("local addr").to_string();
        drop(listener);
        endpoint
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
    fn given_invalid_name_when_parsing_then_error_mentions_canonical_format() {
        let err = parse_name("did:key:z6Mk...").expect_err("invalid name");

        assert!(err.contains("organization/namespace/application"));
    }

    #[test]
    fn given_empty_custom_local_name_when_resolving_then_it_is_rejected() {
        let err = resolve_local_name_value(Some("   "), Some("avatar"))
            .expect_err("empty local name");

        assert!(err.contains("cannot be empty"));
    }

    #[test]
    fn given_group_bootstrap_when_describing_then_it_reports_group_mode() {
        let bootstrap = NativeSlimBootstrap::GroupJoin {
            channel: "agntcy/shadi/secops-room".to_string(),
            timeout: Some(Duration::from_secs(30)),
        };

        assert_eq!(bootstrap.description(), "group");
        match bootstrap {
            NativeSlimBootstrap::GroupJoin { channel, .. } => {
                assert_eq!(channel, "agntcy/shadi/secops-room");
            }
            other => panic!("unexpected bootstrap: {:?}", other),
        }
    }

    #[test]
    fn given_point_to_point_bootstrap_when_describing_then_it_reports_point_to_point_mode() {
        let bootstrap = NativeSlimBootstrap::PointToPoint {
            destination: "agntcy/shadi/avatar".to_string(),
        };

        assert_eq!(bootstrap.description(), "point-to-point");
    }

    #[test]
    fn given_client_service_name_when_generated_then_it_uses_expected_prefix() {
        let service_name = client_service_name();

        assert!(service_name.starts_with("shadi-slim-bridge-"));
    }

    #[test]
    fn given_point_to_point_session_config_when_built_then_defaults_are_expected() {
        let config = point_to_point_session_config();

        assert_eq!(config.session_type, SessionType::PointToPoint);
        assert!(config.mls_settings.is_some());
        assert_eq!(config.max_retries, Some(5));
        assert_eq!(config.interval, Some(Duration::from_secs(5)));
        assert!(config.metadata.is_empty());
    }

    #[test]
    fn given_endpoint_env_when_resolving_then_override_is_used() {
        let _guard = lock_env();
        let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", "10.0.0.8:7744");

        assert_eq!(resolve_endpoint(), "10.0.0.8:7744");
    }

    #[test]
    fn given_shared_secret_env_when_resolving_then_override_is_used() {
        let _guard = lock_env();
        let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", "shared-secret");

        assert_eq!(resolve_shared_secret().expect("shared secret"), "shared-secret");
    }

    #[test]
    #[cfg(not(windows))]
    fn given_generated_assets_when_point_to_point_session_exchanges_messages_then_native_session_works() {
        let _guard = lock_env();
        let dir = TestDir::new("native-point-to-point");
        let tls_dir = generate_test_tls_dir(dir.path());
        let endpoint = reserve_test_endpoint();
        let participant_tls = test_client_tls_material(&tls_dir, "secops-a");
        let server_tls = test_server_tls_material(&tls_dir);
        let participant_name = Arc::new(parse_name("agntcy/shadi/secops-a").expect("participant name"));

        let node_service = Service::new(format!("agent-transport-native-node-{}", std::process::id()));
        node_service
            .run_server(build_test_server_config(&endpoint, &server_tls))
            .expect("start local SLIM node");
        std::thread::sleep(Duration::from_millis(250));

        let (ready_tx, ready_rx) = mpsc::channel();
        let endpoint_for_participant = endpoint.clone();
        let participant_name_for_thread = participant_name.clone();
        let participant_handle = std::thread::spawn(move || -> Result<(u32, Vec<u8>), String> {
            let participant_service =
                Service::new(format!("agent-transport-native-participant-{}", std::process::id()));
            let connection_id = participant_service
                .connect(participant_tls.client_config(&endpoint_for_participant))
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
            std::thread::sleep(Duration::from_millis(200));
            ready_tx.send(()).map_err(|err| err.to_string())?;

            let session = participant_app
                .listen_for_session(Some(Duration::from_secs(20)))
                .map_err(format_slim_error)?;
            let session_id = session.session_id().map_err(format_slim_error)?;
            let payload = session
                .get_message(Some(Duration::from_secs(20)))
                .map_err(format_slim_error)?
                .payload;
            session
                .publish_and_wait(b"reply".to_vec(), None, Some(HashMap::new()))
                .map_err(format_slim_error)?;

            let _ = participant_app.delete_session_and_wait(session);
            participant_service
                .disconnect(connection_id)
                .map_err(format_slim_error)?;
            participant_service.shutdown().map_err(format_slim_error)?;
            Ok((session_id, payload))
        });

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("participant ready");

        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", &endpoint);
        let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", TEST_SHARED_SECRET);
        let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
        let _local_name = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

        let session = NativeSlimSession::from_env(NativeSlimBootstrap::PointToPoint {
            destination: "agntcy/shadi/secops-a".to_string(),
        })
        .expect("native point-to-point session");
        let session_id = session.session_id().expect("native session id");

        crate::SlimSession::send(&session, b"hello").expect("send payload");
        let reply = crate::SlimSession::recv(&session).expect("receive reply");

        let (participant_session_id, participant_payload) = participant_handle
            .join()
            .expect("participant thread panicked")
            .expect("participant session result");

        assert_eq!(session.local_name(), "agntcy/shadi/avatar");
        assert_eq!(reply, b"reply".to_vec());
        assert_eq!(participant_payload, b"hello".to_vec());
        assert_eq!(session_id, participant_session_id);

        drop(session);
        node_service
            .stop_server(endpoint.clone())
            .expect("stop node server");
        node_service.shutdown().expect("shutdown node service");
    }

    #[test]
    #[cfg(not(windows))]
    fn given_generated_assets_when_group_join_times_out_then_native_session_returns_error() {
        let _guard = lock_env();
        let dir = TestDir::new("native-group-timeout");
        let tls_dir = generate_test_tls_dir(dir.path());
        let endpoint = reserve_test_endpoint();
        let server_tls = test_server_tls_material(&tls_dir);

        let node_service = Service::new(format!("agent-transport-native-node-timeout-{}", std::process::id()));
        node_service
            .run_server(build_test_server_config(&endpoint, &server_tls))
            .expect("start local SLIM node");
        std::thread::sleep(Duration::from_millis(250));

        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", &endpoint);
        let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", TEST_SHARED_SECRET);
        let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "secops-a");
        let _local_name = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

        let err = match NativeSlimSession::from_env(NativeSlimBootstrap::GroupJoin {
            channel: "agntcy/shadi/secops-room".to_string(),
            timeout: Some(Duration::from_millis(250)),
        }) {
            Ok(_) => panic!("expected group join timeout"),
            Err(err) => err,
        };

        let err_lower = err.to_lowercase();
        assert!(
            err_lower.contains("timeout") || err_lower.contains("timed out"),
            "unexpected error: {err}"
        );

        node_service
            .stop_server(endpoint.clone())
            .expect("stop node server");
        node_service.shutdown().expect("shutdown node service");
    }
}