// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! What a SLIM client presents to its node, and how it checks the node.
//!
//! Without `SLIM_AUTH_TOKEN_FILE` the connection is mTLS against the CA in
//! [`slim_tls_dir`]. With it, the token is sent as a bearer on the
//! connection, a client certificate is optional, and the node is checked
//! against the system roots unless `SLIM_TLS_CA` names a CA.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use slim_bindings::{
    CaSource, ClientAuthenticationConfig, ClientConfig, StaticJwtAuth, TlsClientConfig, TlsSource,
};

/// The bindings also reload the token file whenever it changes.
const TOKEN_REREAD: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAccess {
    /// Certificate presented to the node; `None` presents none.
    pub identity: Option<ClientIdentity>,
    /// CA the node's certificate must chain to; `None` uses the system roots.
    pub ca: Option<PathBuf>,
    /// File holding a bearer token sent on the connection.
    pub token_file: Option<PathBuf>,
}

impl ClientAccess {
    pub fn mtls(cert: PathBuf, key: PathBuf, ca: PathBuf) -> Self {
        Self {
            identity: Some(ClientIdentity { cert, key }),
            ca: Some(ca),
            token_file: None,
        }
    }

    /// Reads `SLIM_AUTH_TOKEN_FILE`, `SLIM_TLS_CERT`, `SLIM_TLS_KEY` and
    /// `SLIM_TLS_CA`. Without a token, the certificate defaults to the
    /// agent's (`agent_id`, else `SHADI_AGENT_ID`) or the shared one.
    pub fn from_env(agent_id: Option<&str>) -> Result<Self, String> {
        Self::resolve(|name| std::env::var_os(name), agent_id)
    }

    fn resolve(
        var: impl Fn(&str) -> Option<OsString>,
        agent_id: Option<&str>,
    ) -> Result<Self, String> {
        let path = |name: &str| {
            var(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        let identity = match (path("SLIM_TLS_CERT"), path("SLIM_TLS_KEY")) {
            (Some(cert), Some(key)) => Some(ClientIdentity { cert, key }),
            (None, None) => None,
            _ => return Err("SLIM_TLS_CERT and SLIM_TLS_KEY must be set together".to_string()),
        };
        let ca = path("SLIM_TLS_CA");

        let access = match path("SLIM_AUTH_TOKEN_FILE") {
            Some(token_file) => {
                check_token_file(&token_file)?;
                Self {
                    identity,
                    ca,
                    token_file: Some(token_file),
                }
            }
            None => {
                let base = tls_dir(var("SHADI_TMP_DIR"));
                let identity = match identity {
                    Some(identity) => identity,
                    None => {
                        let named =
                            |id: &str| Some(id.trim().to_owned()).filter(|id| !id.is_empty());
                        let agent_id = agent_id.and_then(named).or_else(|| {
                            var("SHADI_AGENT_ID")?
                                .into_string()
                                .ok()
                                .as_deref()
                                .and_then(named)
                        });
                        default_identity(&base, agent_id.as_deref())?
                    }
                };
                Self {
                    identity: Some(identity),
                    ca: Some(ca.unwrap_or_else(|| base.join("ca.crt"))),
                    token_file: None,
                }
            }
        };

        if let Some(identity) = &access.identity {
            ensure_file(&identity.cert, "SLIM client certificate")?;
            ensure_file(&identity.key, "SLIM client key")?;
        }
        if let Some(ca) = &access.ca {
            ensure_file(ca, "SLIM client CA")?;
        }
        Ok(access)
    }

    pub fn tls(&self) -> TlsClientConfig {
        TlsClientConfig {
            insecure: false,
            insecure_skip_verify: false,
            source: match &self.identity {
                Some(identity) => TlsSource::File {
                    cert: identity.cert.display().to_string(),
                    key: identity.key.display().to_string(),
                },
                None => TlsSource::None,
            },
            ca_source: match &self.ca {
                Some(ca) => CaSource::File {
                    path: ca.display().to_string(),
                },
                None => CaSource::None,
            },
            include_system_ca_certs_pool: self.ca.is_none(),
            tls_version: "tls1.3".to_string(),
        }
    }

    pub fn auth(&self) -> Option<ClientAuthenticationConfig> {
        self.token_file
            .as_ref()
            .map(|file| ClientAuthenticationConfig::StaticJwt {
                config: StaticJwtAuth {
                    token_file: file.display().to_string(),
                    duration: TOKEN_REREAD,
                },
            })
    }

    /// `endpoint` without a scheme is taken as `https://`.
    pub fn client_config(&self, endpoint: &str) -> ClientConfig {
        ClientConfig {
            endpoint: if endpoint.contains("://") {
                endpoint.to_string()
            } else {
                format!("https://{endpoint}")
            },
            tls: self.tls(),
            auth: self.auth(),
            ..ClientConfig::default()
        }
    }
}

/// Where the local node's generated mTLS material lives.
pub fn slim_tls_dir() -> PathBuf {
    tls_dir(std::env::var_os("SHADI_TMP_DIR"))
}

fn tls_dir(tmp_dir: Option<OsString>) -> PathBuf {
    tmp_dir
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.tmp"))
        .join("shadi-slim-mtls")
}

fn default_identity(base: &Path, agent_id: Option<&str>) -> Result<ClientIdentity, String> {
    let mut stems = Vec::new();
    if let Some(agent_id) = agent_id {
        stems.push(format!("client-{agent_id}"));
    }
    stems.push("client".to_string());

    let candidates: Vec<ClientIdentity> = stems
        .iter()
        .map(|stem| ClientIdentity {
            cert: base.join(format!("{stem}.crt")),
            key: base.join(format!("{stem}.key")),
        })
        .collect();
    if let Some(found) = candidates
        .iter()
        .find(|c| c.cert.is_file() && c.key.is_file())
    {
        return Ok(found.clone());
    }
    let checked = candidates
        .iter()
        .map(|c| format!("{} + {}", c.cert.display(), c.key.display()))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "no SLIM client certificate found; checked {checked}. Set SHADI_AGENT_ID or SLIM_TLS_CERT/SLIM_TLS_KEY explicitly, or SLIM_AUTH_TOKEN_FILE for a node that takes a bearer token"
    ))
}

fn ensure_file(path: &Path, label: &str) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("{label} not found at {}", path.display()))
    }
}

/// The bindings send the file's bytes as the header value, and panic if they
/// can't read it, so refuse what would fail later.
fn check_token_file(path: &Path) -> Result<(), String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read SLIM_AUTH_TOKEN_FILE {}: {err}", path.display()))?;
    if contents.is_empty() {
        return Err(format!("SLIM_AUTH_TOKEN_FILE {} is empty", path.display()));
    }
    if contents.chars().any(char::is_whitespace) {
        return Err(format!(
            "SLIM_AUTH_TOKEN_FILE {} must hold only the token, with no whitespace or trailing newline",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("shadi-client-access-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("shadi-slim-mtls")).expect("create dir");
            Self(path)
        }

        fn file(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).expect("write file");
            path
        }

        fn tls(&self, name: &str) -> PathBuf {
            self.file(&format!("shadi-slim-mtls/{name}"), "pem")
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn resolve(vars: &[(&str, &Path)], agent_id: Option<&str>) -> Result<ClientAccess, String> {
        let vars: HashMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_os_str().to_owned()))
            .collect();
        ClientAccess::resolve(|name| vars.get(name).cloned(), agent_id)
    }

    #[test]
    fn without_a_token_the_agent_certificate_and_local_ca_are_used() {
        let dir = Dir::new("agent-cert");
        let cert = dir.tls("client-avatar.crt");
        let key = dir.tls("client-avatar.key");
        dir.tls("client.crt");
        dir.tls("client.key");
        let ca = dir.tls("ca.crt");

        let access = resolve(&[("SHADI_TMP_DIR", &dir.0)], Some("avatar")).expect("access");

        assert_eq!(access, ClientAccess::mtls(cert, key, ca));
    }

    #[test]
    fn without_a_token_the_shared_certificate_is_the_fallback() {
        let dir = Dir::new("shared-cert");
        let cert = dir.tls("client.crt");
        let key = dir.tls("client.key");
        dir.tls("ca.crt");
        let agent = Path::new("avatar");

        let access = resolve(
            &[("SHADI_TMP_DIR", &dir.0), ("SHADI_AGENT_ID", agent)],
            None,
        )
        .expect("access");

        assert_eq!(access.identity, Some(ClientIdentity { cert, key }));
    }

    #[test]
    fn without_a_token_a_missing_certificate_lists_the_candidates() {
        let dir = Dir::new("no-cert");
        let agent = Path::new("avatar");

        let err = resolve(
            &[("SHADI_TMP_DIR", &dir.0), ("SHADI_AGENT_ID", agent)],
            None,
        )
        .expect_err("no certificate");

        assert!(err.contains("no SLIM client certificate found"), "{err}");
        assert!(err.contains("client-avatar.crt"), "{err}");
        assert!(err.contains("SLIM_AUTH_TOKEN_FILE"), "{err}");
    }

    #[test]
    fn explicit_certificate_and_ca_override_the_defaults() {
        let dir = Dir::new("explicit");
        let cert = dir.file("my.crt", "pem");
        let key = dir.file("my.key", "pem");
        let ca = dir.file("my-ca.crt", "pem");

        let access = resolve(
            &[
                ("SHADI_TMP_DIR", &dir.0),
                ("SLIM_TLS_CERT", &cert),
                ("SLIM_TLS_KEY", &key),
                ("SLIM_TLS_CA", &ca),
            ],
            Some("avatar"),
        )
        .expect("access");

        assert_eq!(access, ClientAccess::mtls(cert, key, ca));
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let dir = Dir::new("half-pair");
        let cert = dir.file("my.crt", "pem");

        for var in ["SLIM_TLS_CERT", "SLIM_TLS_KEY"] {
            let err = resolve(&[(var, &cert)], None).expect_err("half pair");
            assert!(err.contains("must be set together"), "{err}");
        }
    }

    #[test]
    fn a_missing_ca_is_reported() {
        let dir = Dir::new("no-ca");
        dir.tls("client.crt");
        dir.tls("client.key");

        let err = resolve(&[("SHADI_TMP_DIR", &dir.0)], None).expect_err("no CA");

        assert!(err.contains("SLIM client CA not found"), "{err}");
    }

    #[test]
    fn a_token_alone_uses_system_roots_and_no_certificate() {
        let dir = Dir::new("token-only");
        dir.tls("client.crt");
        dir.tls("client.key");
        dir.tls("ca.crt");
        let token = dir.file("token", "header.payload.sig");

        let access = resolve(
            &[("SHADI_TMP_DIR", &dir.0), ("SLIM_AUTH_TOKEN_FILE", &token)],
            Some("avatar"),
        )
        .expect("access");

        assert_eq!(
            access,
            ClientAccess {
                identity: None,
                ca: None,
                token_file: Some(token.clone()),
            }
        );
        let config = access.client_config("node.example:443");
        assert_eq!(config.endpoint, "https://node.example:443");
        assert!(matches!(config.tls.source, TlsSource::None));
        assert!(matches!(config.tls.ca_source, CaSource::None));
        assert!(config.tls.include_system_ca_certs_pool);
        match config.auth {
            Some(ClientAuthenticationConfig::StaticJwt { config }) => {
                assert_eq!(config.token_file, token.display().to_string());
            }
            other => panic!("expected a static bearer token, got {other:?}"),
        }
    }

    #[test]
    fn a_token_keeps_an_explicit_certificate_and_ca() {
        let dir = Dir::new("token-mtls");
        let cert = dir.file("my.crt", "pem");
        let key = dir.file("my.key", "pem");
        let ca = dir.file("my-ca.crt", "pem");
        let token = dir.file("token", "header.payload.sig");

        let access = resolve(
            &[
                ("SLIM_AUTH_TOKEN_FILE", &token),
                ("SLIM_TLS_CERT", &cert),
                ("SLIM_TLS_KEY", &key),
                ("SLIM_TLS_CA", &ca),
            ],
            None,
        )
        .expect("access");

        assert_eq!(access.identity, Some(ClientIdentity { cert, key }));
        assert_eq!(access.ca, Some(ca));
        assert!(!access.tls().include_system_ca_certs_pool);
    }

    #[test]
    fn an_unusable_token_file_is_refused() {
        let dir = Dir::new("bad-token");
        let missing = dir.0.join("missing");
        let empty = dir.file("empty", "");
        let newline = dir.file("newline", "header.payload.sig\n");

        let err = resolve(&[("SLIM_AUTH_TOKEN_FILE", &missing)], None).expect_err("missing");
        assert!(err.contains("cannot read SLIM_AUTH_TOKEN_FILE"), "{err}");
        let err = resolve(&[("SLIM_AUTH_TOKEN_FILE", &empty)], None).expect_err("empty");
        assert!(err.contains("is empty"), "{err}");
        let err = resolve(&[("SLIM_AUTH_TOKEN_FILE", &newline)], None).expect_err("newline");
        assert!(err.contains("trailing newline"), "{err}");
    }

    #[test]
    fn empty_variables_count_as_unset() {
        let dir = Dir::new("empty-vars");
        dir.tls("client.crt");
        dir.tls("client.key");
        dir.tls("ca.crt");
        let empty = Path::new("");

        let access = resolve(
            &[
                ("SHADI_TMP_DIR", &dir.0),
                ("SLIM_AUTH_TOKEN_FILE", empty),
                ("SLIM_TLS_CA", empty),
            ],
            None,
        )
        .expect("access");

        assert_eq!(access.token_file, None);
        assert_eq!(access.ca, Some(dir.0.join("shadi-slim-mtls/ca.crt")));
    }

    #[test]
    fn mtls_config_embeds_the_paths_and_no_auth() {
        let access = ClientAccess::mtls("/c".into(), "/k".into(), "/a".into());

        let config = access.client_config("https://node:1");

        assert_eq!(config.endpoint, "https://node:1");
        assert_eq!(config.tls.tls_version, "tls1.3");
        assert!(!config.tls.insecure && !config.tls.insecure_skip_verify);
        assert!(!config.tls.include_system_ca_certs_pool);
        match config.tls.source {
            TlsSource::File { cert, key } => {
                assert_eq!((cert.as_str(), key.as_str()), ("/c", "/k"))
            }
            other => panic!("unexpected TLS source: {other:?}"),
        }
        match config.tls.ca_source {
            CaSource::File { path } => assert_eq!(path, "/a"),
            other => panic!("unexpected CA source: {other:?}"),
        }
        assert!(config.auth.is_none());
    }

    #[test]
    fn tls_dir_is_under_the_tmp_dir() {
        assert_eq!(
            tls_dir(Some("/x".into())),
            Path::new("/x").join("shadi-slim-mtls")
        );
        assert!(tls_dir(None).ends_with(".tmp/shadi-slim-mtls"));
        assert!(slim_tls_dir().ends_with("shadi-slim-mtls"));
    }
}
