// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_secrets::{SecretError, SecretResult};
use slim_bindings::{
    App, CaSource, ClientConfig, MlsSettings, Name, Service, Session, SessionConfig, SessionType,
    SlimError,
    TlsClientConfig, TlsSource,
};

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
        let shared_secret = resolve_shared_secret()?;
        let client_config = build_client_config()?;
        let service = Service::new(client_service_name());

        let mut connection_id = None;
        let mut app: Option<Arc<App>> = None;
        let mut session: Option<Arc<Session>> = None;
        let mut subscriptions: Vec<Arc<Name>> = Vec::new();

        let established = (|| -> Result<(Arc<App>, Arc<Session>, u64, String), String> {
            let connected_id = service.connect(client_config).map_err(format_slim_error)?;
            connection_id = Some(connected_id);

            let created_app = service
                .create_app_with_secret(local_name_ref.clone(), shared_secret)
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

#[derive(Clone)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
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

fn build_client_config() -> Result<ClientConfig, String> {
    let tls = resolve_client_tls_material()?;
    Ok(build_client_config_for_endpoint(&resolve_endpoint(), &tls))
}

fn build_client_config_for_endpoint(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.endpoint = resolve_client_endpoint_value(endpoint);
    // Pin require_header_mac=false to match the node MessageProcessor and avoid
    // the rotating link-HMAC key gating the SLIM session handshake (mTLS +
    // shared-secret already secure the transport).
    config.require_header_mac = Some(false);
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

    candidates.push((base_dir.join("client.crt"), base_dir.join("client.key")));
    candidates
}

fn resolve_endpoint() -> String {
    std::env::var("SLIM_ENDPOINT").unwrap_or_else(|_| DEFAULT_SLIM_ENDPOINT.to_string())
}

fn resolve_client_endpoint_value(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
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
    use std::ffi::{OsStr, OsString};
    use std::fs;
    #[cfg(not(windows))]
    use std::net::TcpListener;
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
    fn test_server_tls_material(base_dir: &Path) -> TlsMaterial {
        TlsMaterial {
            cert: base_dir.join("server.crt"),
            key: base_dir.join("server.key"),
            ca: base_dir.join("ca.crt"),
        }
    }

    #[cfg(not(windows))]
    fn build_test_server_config(endpoint: &str, tls: &TlsMaterial) -> slim_bindings::ServerConfig {
        let mut config = slim_bindings::ServerConfig::default();
        config.endpoint = endpoint.to_string();
        config.require_header_mac = Some(false);
        config.tls = slim_bindings::TlsServerConfig {
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
    fn given_tmp_dir_override_when_resolving_tls_dir_then_custom_base_is_used() {
        let _guard = lock_env();
        let dir = TestDir::new("native-tmp-dir");
        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());

        assert_eq!(slim_tls_dir(), dir.path().join("shadi-slim-mtls"));
    }

    #[test]
    fn given_present_file_when_ensuring_then_it_succeeds() {
        let dir = TestDir::new("native-existing-file");
        let file = dir.path().join("present.txt");
        write_test_file(&file);

        ensure_file_exists(&file, "present file").expect("existing file");
    }

    #[test]
    fn given_missing_file_when_ensuring_then_error_mentions_label_and_path() {
        let dir = TestDir::new("native-missing-file");
        let file = dir.path().join("missing.txt");

        let err = ensure_file_exists(&file, "missing file").expect_err("missing file");

        assert!(err.contains("missing file"));
        assert!(err.contains(&file.display().to_string()));
    }

    #[test]
    fn given_only_cert_override_when_resolving_tls_then_it_is_rejected() {
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
    fn given_only_key_override_when_resolving_tls_then_it_is_rejected() {
        let _guard = lock_env();
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::set("SLIM_TLS_KEY", "/tmp/client.key");

        let err = match resolve_client_tls_material() {
            Ok(_) => panic!("expected missing cert override to fail"),
            Err(err) => err,
        };

        assert!(err.contains("must be set together"));
    }

    #[test]
    fn given_explicit_tls_overrides_when_resolving_then_they_are_used() {
        let _guard = lock_env();
        let dir = TestDir::new("native-explicit-tls");
        let cert = dir.path().join("client.crt");
        let key = dir.path().join("client.key");
        let ca = dir.path().join("ca.crt");
        write_test_file(&cert);
        write_test_file(&key);
        write_test_file(&ca);

        let _cert = ScopedEnvVar::set("SLIM_TLS_CERT", cert.as_os_str());
        let _key = ScopedEnvVar::set("SLIM_TLS_KEY", key.as_os_str());
        let _ca = ScopedEnvVar::set("SLIM_TLS_CA", ca.as_os_str());
        let _tmp_dir = ScopedEnvVar::unset("SHADI_TMP_DIR");
        let _agent_id = ScopedEnvVar::unset("SHADI_AGENT_ID");

        let tls = resolve_client_tls_material().expect("tls material");

        assert_eq!(tls.cert, cert);
        assert_eq!(tls.key, key);
        assert_eq!(tls.ca, ca);
    }

    #[test]
    fn given_missing_tls_material_when_resolving_then_candidates_are_reported() {
        let _guard = lock_env();
        let dir = TestDir::new("native-missing-tls");
        fs::create_dir_all(dir.path().join("shadi-slim-mtls")).expect("create tls dir");

        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

        let err = match resolve_client_tls_material() {
            Ok(_) => panic!("expected missing tls material to fail"),
            Err(err) => err,
        };

        assert!(err.contains("no SLIM client certificate found"));
        assert!(err.contains("client-avatar.crt"));
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