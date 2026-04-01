// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_secrets::{SecretError, SecretResult};
use slim_bindings::{
    App, CaSource, ClientConfig, Name, Service, Session, SessionConfig, SessionType,
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
}