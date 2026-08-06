// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Everything onboarding has to produce before the app can join a room
//! (agntcy/shadi#123): a human identity, derived agent identities, and mTLS
//! material.
//!
//! Before this, the app only read that state from ~10 environment variables, so
//! a fresh install could not reach a working room without a shell script. The
//! identity lives here instead, and [`crate::commands::slim`] prefers it over
//! the environment.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use agent_secrets::{SecretPolicy, SecretStore};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Serialize};

/// Secret-store key holding the 32-byte agent-derivation root.
pub const SEED_SECRET_KEY: &str = "shadi-desktop/human-seed";

pub const DEFAULT_ENDPOINT: &str = "127.0.0.1:47610";

/// A GitHub account whose published SSH key we accept as a human identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedHuman {
    pub github_handle: String,
    pub human_did: String,
}

/// Onboarding's output. The seed itself is never in here — it goes to the
/// secret store, so this file can be read without exposing key material.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityConfig {
    pub human_did: String,
    pub github_handle: Option<String>,
    /// Agent ids derived from the human root, with their DIDs.
    pub agents: Vec<AgentEntry>,
    /// Which agent this app authenticates as.
    pub local_agent: String,
    pub endpoint: String,
    #[serde(default)]
    pub trusted: Vec<TrustedHuman>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentEntry {
    pub agent_id: String,
    pub did: String,
}

impl IdentityConfig {
    /// The allow-list passed to `build_did_auth`.
    ///
    /// Agent DIDs only. A trusted human's DID is not included: SLIM admission
    /// verifies the *agent* DID presented on the wire, and a human's agent DIDs
    /// derive from their private key, so they cannot be computed from the
    /// published public key. Trusting a handle records who we accept; admitting
    /// their agents still needs those agents' DIDs. See agntcy/shadi#141.
    pub fn member_dids(&self) -> String {
        self.agents
            .iter()
            .map(|a| a.did.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

pub fn config_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("identity.json")
}

pub fn load_config(path: &Path) -> Result<Option<IdentityConfig>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&data)
        .map(Some)
        .map_err(|e| format!("invalid identity config {}: {e}", path.display()))
}

pub fn save_config(path: &Path, config: &IdentityConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let data = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize identity config: {e}"))?;
    std::fs::write(path, data).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

pub fn store_seed(store: &dyn SecretStore, seed: &[u8]) -> Result<(), String> {
    store
        .put(SEED_SECRET_KEY, seed, SecretPolicy::default())
        .map_err(|e| format!("failed to store the derivation root: {e}"))
}

pub fn load_seed(store: &dyn SecretStore) -> Result<Vec<u8>, String> {
    let secret = store.get(SEED_SECRET_KEY).map_err(|err| match err {
        // Not stored yet is the first-run state, not a fault.
        agent_secrets::SecretError::InvalidInput => {
            "no derivation root stored — run onboarding first".to_string()
        }
        other => format!("could not read the derivation root: {other}"),
    })?;
    Ok(secret.expose(|bytes| bytes.to_vec()))
}

// --- mTLS --------------------------------------------------------------------

/// Files the SLIM transport expects under `<dir>/`.
fn material_paths(dir: &Path, client_names: &[String]) -> Vec<PathBuf> {
    let mut paths = vec![
        dir.join("ca.crt"),
        dir.join("server.crt"),
        dir.join("server.key"),
        dir.join("client.crt"),
        dir.join("client.key"),
    ];
    for name in client_names {
        paths.push(dir.join(format!("client-{name}.crt")));
        paths.push(dir.join(format!("client-{name}.key")));
    }
    paths
}

pub fn mtls_is_complete(dir: &Path, client_names: &[String]) -> bool {
    material_paths(dir, client_names)
        .iter()
        .all(|p| p.is_file())
}

/// Generate a CA plus a `localhost` server cert and one client cert per agent,
/// matching what `tools/generate_slim_mtls_certs.sh` produces.
///
/// Uses rcgen rather than shelling to `openssl`, which a clean Windows install
/// does not have. Existing files are left alone so re-running onboarding cannot
/// invalidate certs a peer already trusts.
pub fn ensure_mtls(dir: &Path, client_names: &[String]) -> Result<Vec<PathBuf>, String> {
    if mtls_is_complete(dir, client_names) {
        return Ok(Vec::new());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;

    let err = |e: rcgen::Error| format!("failed to generate mTLS material: {e}");

    let ca_key = KeyPair::generate().map_err(err)?;
    let mut ca_params = CertificateParams::new(vec![]).map_err(err)?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "SHADI SLIM CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).map_err(err)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let mut written = Vec::new();
    let mut write = |path: PathBuf, contents: String| -> Result<(), String> {
        std::fs::write(&path, contents)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
        written.push(path);
        Ok(())
    };

    write(dir.join("ca.crt"), ca_cert.pem())?;

    let server_key = KeyPair::generate().map_err(err)?;
    let mut server = CertificateParams::new(vec![]).map_err(err)?;
    server
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server.subject_alt_names = vec![
        SanType::DnsName(
            Ia5String::try_from("localhost".to_string())
                .map_err(|e| format!("invalid SAN: {e}"))?,
        ),
        SanType::IpAddress(IpAddr::from([127, 0, 0, 1])),
    ];
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server.signed_by(&server_key, &issuer).map_err(err)?;
    write(dir.join("server.crt"), server_cert.pem())?;
    write(dir.join("server.key"), server_key.serialize_pem())?;

    // A generic client pair, plus one per agent: the transport picks
    // `client-<SHADI_AGENT_ID>` when present and falls back to `client`.
    let mut clients: Vec<String> = vec!["client".to_string()];
    clients.extend(client_names.iter().map(|n| format!("client-{n}")));
    for stem in clients {
        let cn = stem.strip_prefix("client-").unwrap_or("client").to_string();
        let key = KeyPair::generate().map_err(err)?;
        let mut params = CertificateParams::new(vec![]).map_err(err)?;
        params.distinguished_name.push(DnType::CommonName, cn);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &issuer).map_err(err)?;
        write(dir.join(format!("{stem}.crt")), cert.pem())?;
        write(dir.join(format!("{stem}.key")), key.serialize_pem())?;
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shadi-bootstrap-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn generates_every_file_the_transport_looks_for() {
        let dir = tmp("mtls");
        let agents = vec!["avatar".to_string(), "codex".to_string()];
        let written = ensure_mtls(&dir, &agents).expect("generate");
        assert!(!written.is_empty());
        assert!(mtls_is_complete(&dir, &agents));
        for f in [
            "ca.crt",
            "server.crt",
            "server.key",
            "client.crt",
            "client.key",
            "client-avatar.crt",
            "client-avatar.key",
            "client-codex.crt",
            "client-codex.key",
        ] {
            let p = dir.join(f);
            let body = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing {f}"));
            let marker = if f.ends_with(".key") {
                "PRIVATE KEY"
            } else {
                "BEGIN CERTIFICATE"
            };
            assert!(body.contains(marker), "{f} is not PEM: {body:.40}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Re-running onboarding must not invalidate certs a peer already trusts.
    #[test]
    fn existing_material_is_left_alone() {
        let dir = tmp("idempotent");
        let agents = vec!["avatar".to_string()];
        ensure_mtls(&dir, &agents).expect("first");
        let before = std::fs::read_to_string(dir.join("ca.crt")).unwrap();

        let written = ensure_mtls(&dir, &agents).expect("second");
        assert!(written.is_empty(), "should not rewrite anything");
        assert_eq!(before, std::fs::read_to_string(dir.join("ca.crt")).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Adding an agent later must mint that agent's client cert.
    #[test]
    fn a_new_agent_gets_its_client_cert() {
        let dir = tmp("newagent");
        ensure_mtls(&dir, &["avatar".to_string()]).expect("first");
        assert!(!mtls_is_complete(
            &dir,
            &["avatar".to_string(), "codex".to_string()]
        ));

        ensure_mtls(&dir, &["avatar".to_string(), "codex".to_string()]).expect("second");
        assert!(dir.join("client-codex.crt").is_file());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_round_trips_without_the_seed() {
        let dir = tmp("config");
        let path = config_path(&dir);
        assert!(load_config(&path).expect("missing is fine").is_none());

        let config = IdentityConfig {
            human_did: "did:key:zHuman".to_string(),
            github_handle: Some("octocat".to_string()),
            agents: vec![
                AgentEntry { agent_id: "avatar".to_string(), did: "did:key:zA".to_string() },
                AgentEntry { agent_id: "codex".to_string(), did: "did:key:zB".to_string() },
            ],
            local_agent: "avatar".to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
            trusted: vec![TrustedHuman {
                github_handle: "alice".to_string(),
                human_did: "did:key:zAlice".to_string(),
            }],
        };
        save_config(&path, &config).expect("save");

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("seed"), "the seed must never be in the config");

        assert_eq!(load_config(&path).unwrap().as_ref(), Some(&config));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The allow-list is agent DIDs only — a trusted human's DID would never
    /// appear on the wire, so including it would be misleading (#141).
    #[test]
    fn member_dids_exclude_trusted_humans() {
        let config = IdentityConfig {
            human_did: "did:key:zHuman".to_string(),
            github_handle: None,
            agents: vec![
                AgentEntry { agent_id: "avatar".to_string(), did: "did:key:zA".to_string() },
                AgentEntry { agent_id: "codex".to_string(), did: "did:key:zB".to_string() },
            ],
            local_agent: "avatar".to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
            trusted: vec![TrustedHuman {
                github_handle: "alice".to_string(),
                human_did: "did:key:zAlice".to_string(),
            }],
        };
        assert_eq!(config.member_dids(), "did:key:zA,did:key:zB");
    }
}
