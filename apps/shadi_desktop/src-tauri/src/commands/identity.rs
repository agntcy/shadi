// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Identity and secrets (agntcy/shadi#117), and the SSH onboarding flow
//! (agntcy/shadi#123).
//!
//! Onboarding is deliberately one command: [`identity_bootstrap`] takes a local
//! SSH key and leaves the app able to join a room — human DID, derived agents,
//! mTLS material, and a stored derivation root. Nothing else has to be set by
//! hand, which is what the environment variables used to be for.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::bootstrap::{
    self, AgentEntry, IdentityConfig, TrustedHuman, DEFAULT_ENDPOINT,
};
use super::not_implemented;

const PANEL_ISSUE: u32 = 117;

/// Where human key material comes from. The CLI models this as two
/// mutually-exclusive `Option` flags (`--secret` xor `--in <file>`); a tagged
/// union is a cleaner IPC shape for the same choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HumanKeySource {
    /// Reference into the SHADI secret store.
    SecretRef { key: String },
    /// A GPG key file on disk.
    File { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub did: String,
    pub document_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_name: String,
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAgentIdentityResult {
    pub matches: bool,
    pub expected_did: String,
    pub stored_did: Option<String>,
    /// `None` if `require_human_binding` wasn't requested.
    pub human_binding_ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainEntry {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretBackend {
    Keychain,
    OnePassword { vault: String },
}

/// Create a `did:key` document from a GPG key (`did-from-gpg`).
#[tauri::command]
pub async fn identity_did_from_gpg(source: HumanKeySource) -> Result<DidDocument, String> {
    let _ = source;
    not_implemented(PANEL_ISSUE)
}

/// Create a `did:key` document from a GitHub user's GPG key (`did-from-github`).
#[tauri::command]
pub async fn identity_did_from_github(username: String) -> Result<DidDocument, String> {
    let _ = username;
    not_implemented(PANEL_ISSUE)
}

/// Derive one or more local agent identities from a human source
/// (`derive-agent-identity`).
#[tauri::command]
pub async fn identity_derive_agent(
    source: HumanKeySource,
    agent_names: Vec<String>,
    human_did_key: Option<String>,
) -> Result<Vec<AgentIdentity>, String> {
    let _ = (source, agent_names, human_did_key);
    not_implemented(PANEL_ISSUE)
}

/// Recompute the expected agent key/DID and compare to stored values
/// (`verify-agent-identity`).
#[tauri::command]
pub async fn identity_verify_agent(
    source: HumanKeySource,
    agent_name: String,
    require_human_binding: bool,
) -> Result<VerifyAgentIdentityResult, String> {
    let _ = (source, agent_name, require_human_binding);
    not_implemented(PANEL_ISSUE)
}

/// Read a secret from the SHADI secret store (`get-secret`). Returns the
/// secret value — the panel must not log or persist this outside memory.
#[tauri::command]
pub async fn secret_get(key: String) -> Result<String, String> {
    let _ = key;
    not_implemented(PANEL_ISSUE)
}

/// Store an OpenPGP key in the SHADI secret store (`put-key`).
#[tauri::command]
pub async fn secret_put_key(key: String, openpgp_key_path: String) -> Result<(), String> {
    let _ = (key, openpgp_key_path);
    not_implemented(PANEL_ISSUE)
}

/// List keys under a prefix (`--list-keychain` / `--list-prefix`). Returns
/// key names only — never values.
#[tauri::command]
pub async fn secret_list_keychain(prefix: Option<String>) -> Result<Vec<KeychainEntry>, String> {
    let _ = prefix;
    not_implemented(PANEL_ISSUE)
}

/// Which secret backend is active (`SHADI_SECRET_BACKEND`).
#[tauri::command]
pub async fn secret_backend_status() -> Result<SecretBackend, String> {
    not_implemented(PANEL_ISSUE)
}

// --- SSH onboarding (agntcy/shadi#123) ---------------------------------------

/// An Ed25519 SSH key found on this machine, offered as an identity root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyCandidate {
    pub path: String,
    /// Comment from the public key, usually an email or host label.
    pub comment: Option<String>,
    pub encrypted: bool,
    /// The human DID this key would produce. `None` when only the private key
    /// is present and encrypted, since the public half cannot be read yet.
    pub human_did: Option<String>,
}

/// Where the SSH private key comes from. Keys are not always files in
/// `~/.ssh`: many people keep them in 1Password and let its agent serve them,
/// so the source is the user's choice rather than a fixed location.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeySource {
    /// Any path — from `~/.ssh` discovery or a file picker.
    File { path: String },
    /// A 1Password SSH Key item, read through the `op` CLI.
    OnePassword {
        item: String,
        vault: Option<String>,
    },
}

impl KeySource {
    fn describe(&self) -> String {
        match self {
            KeySource::File { path } => path.clone(),
            KeySource::OnePassword { item, vault } => match vault {
                Some(v) => format!("1Password {v}/{item}"),
                None => format!("1Password item {item}"),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub source: KeySource,
    pub passphrase: Option<String>,
    /// Agent ids to derive, e.g. `["avatar", "claude-code", "codex"]`.
    pub agent_names: Vec<String>,
    /// Which of them this app authenticates as.
    pub local_agent: String,
    pub endpoint: Option<String>,
    /// Cross-check the key against this account's published keys.
    pub github_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapStatus {
    pub ready: bool,
    pub human_did: Option<String>,
    pub github_handle: Option<String>,
    pub agents: Vec<AgentIdentity>,
    pub local_agent: Option<String>,
    pub endpoint: String,
    pub mtls_ready: bool,
    pub trusted: Vec<TrustedHuman>,
    /// Whether the derivation root is present in the secret store.
    pub seed_stored: bool,
}

fn ssh_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ssh"))
}

/// Offer the Ed25519 keys already on this machine, so onboarding is a choice
/// from a list rather than a path to type.
#[tauri::command]
pub async fn identity_discover_ssh_keys() -> Result<Vec<SshKeyCandidate>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let Some(dir) = ssh_dir() else {
            return Ok(Vec::new());
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // No ~/.ssh at all is a normal first-run state, not an error.
            Err(_) => return Ok(Vec::new()),
        };

        let mut found = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            // Iterate public keys: they are safe to read and name their private
            // counterpart, so nothing probes private files speculatively.
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            let Ok(line) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !line.trim_start().starts_with(shadi_identity::ssh::SSH_ED25519) {
                continue;
            }
            let private = path.with_extension("");
            if !private.is_file() {
                continue;
            }
            let human_did = shadi_identity::ssh::verifying_key_from_openssh_public_key(&line)
                .ok()
                .map(|vk| shadi_identity::encode_did_key(&vk));
            let encrypted = std::fs::read_to_string(&private)
                .map(|body| body.contains("ENCRYPTED") || is_encrypted_openssh(&body))
                .unwrap_or(false);

            found.push(SshKeyCandidate {
                path: private.to_string_lossy().into_owned(),
                comment: line
                    .split_whitespace()
                    .nth(2)
                    .map(|c| c.to_string()),
                encrypted,
                human_did,
            });
        }
        found.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(found)
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// OpenSSH marks encryption in the container rather than the PEM header, so ask
/// the parser instead of pattern-matching the text.
fn is_encrypted_openssh(body: &str) -> bool {
    shadi_identity::ssh::seed_from_openssh_private_key(body.as_bytes(), None)
        .err()
        .map(|e| e.to_string().contains("passphrase is required"))
        .unwrap_or(false)
}

/// Everything a fresh install needs, in one step (agntcy/shadi#123).
#[tauri::command]
pub async fn identity_bootstrap(
    app: tauri::AppHandle,
    request: BootstrapRequest,
) -> Result<BootstrapStatus, String> {
    let paths = app_paths(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        if request.agent_names.is_empty() {
            return Err("choose at least one agent to derive".to_string());
        }
        if !request.agent_names.contains(&request.local_agent) {
            return Err(format!(
                "local agent '{}' is not among the derived agents",
                request.local_agent
            ));
        }

        let key_bytes = read_key_material(&request.source)?;
        let seed = shadi_identity::ssh::seed_from_openssh_private_key(
            &key_bytes,
            request.passphrase.as_deref(),
        )
        .map_err(|e| e.to_string())?;

        let human_vk = shadi_identity::ssh::verifying_key_from_openssh_private_key(
            &key_bytes,
            request.passphrase.as_deref(),
        )
        .map_err(|e| e.to_string())?;
        let human_did = shadi_identity::encode_did_key(&human_vk);

        // If a handle was given, the key must actually be published there —
        // otherwise the DID is not verifiable by anyone else and claiming the
        // handle would be misleading.
        if let Some(handle) = request.github_handle.as_deref() {
            let published = fetch_github_human_did(handle)?;
            if published != human_did {
                return Err(format!(
                    "{} is not the ssh-ed25519 key published by @{handle} \
                     (published {published}, this key {human_did})",
                    request.source.describe()
                ));
            }
        }

        let agents = request
            .agent_names
            .iter()
            .map(|name| {
                shadi_identity::AgentIdentity::derive(&seed, name)
                    .map(|id| AgentEntry { agent_id: name.clone(), did: id.did() })
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, String>>()?;

        let store = agent_secrets::default_store();
        bootstrap::store_seed(store.as_ref(), &seed)?;

        bootstrap::ensure_mtls(&paths.mtls_dir, &request.agent_names)?;

        let config = IdentityConfig {
            human_did,
            github_handle: request.github_handle,
            agents,
            local_agent: request.local_agent,
            endpoint: request
                .endpoint
                .filter(|e| !e.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string()),
            // Preserve anyone already trusted across a re-run.
            trusted: bootstrap::load_config(&paths.config)?
                .map(|c| c.trusted)
                .unwrap_or_default(),
        };
        bootstrap::save_config(&paths.config, &config)?;

        status_from(&paths, Some(config), store.as_ref())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

#[tauri::command]
pub async fn identity_status(app: tauri::AppHandle) -> Result<BootstrapStatus, String> {
    let paths = app_paths(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let config = bootstrap::load_config(&paths.config)?;
        let store = agent_secrets::default_store();
        status_from(&paths, config, store.as_ref())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// Trust a GitHub account by handle: read the `ssh-ed25519` key it publishes and
/// record the human DID that key produces.
///
/// This is the invite side of onboarding — naming a person instead of pasting a
/// DID. It records *who* we accept; it cannot admit their agents, whose DIDs
/// derive from their private key. See agntcy/shadi#141.
#[tauri::command]
pub async fn identity_trust_github_handle(
    app: tauri::AppHandle,
    handle: String,
) -> Result<Vec<TrustedHuman>, String> {
    let paths = app_paths(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let handle = handle.trim().trim_start_matches('@').to_string();
        if handle.is_empty() {
            return Err("give a GitHub handle".to_string());
        }
        let human_did = fetch_github_human_did(&handle)?;

        let mut config = bootstrap::load_config(&paths.config)?
            .ok_or_else(|| "run onboarding before trusting other accounts".to_string())?;
        let entry = TrustedHuman { github_handle: handle.clone(), human_did };
        match config.trusted.iter_mut().find(|t| t.github_handle == handle) {
            // Re-trusting refreshes the DID, so a rotated key is picked up.
            Some(existing) => *existing = entry,
            None => config.trusted.push(entry),
        }
        config.trusted.sort_by(|a, b| a.github_handle.cmp(&b.github_handle));
        bootstrap::save_config(&paths.config, &config)?;
        Ok(config.trusted)
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

#[tauri::command]
pub async fn identity_untrust_github_handle(
    app: tauri::AppHandle,
    handle: String,
) -> Result<Vec<TrustedHuman>, String> {
    let paths = app_paths(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut config = bootstrap::load_config(&paths.config)?
            .ok_or_else(|| "nothing is configured yet".to_string())?;
        config.trusted.retain(|t| t.github_handle != handle);
        bootstrap::save_config(&paths.config, &config)?;
        Ok(config.trusted)
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

pub(crate) struct AppPaths {
    pub(crate) config: PathBuf,
    pub(crate) mtls_dir: PathBuf,
}

pub(crate) fn app_paths(app: &tauri::AppHandle) -> Result<AppPaths, String> {
    use tauri::Manager;
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?;
    Ok(AppPaths {
        config: bootstrap::config_path(&dir),
        mtls_dir: dir.join("shadi-slim-mtls"),
    })
}

fn status_from(
    paths: &AppPaths,
    config: Option<IdentityConfig>,
    store: &dyn agent_secrets::SecretStore,
) -> Result<BootstrapStatus, String> {
    let seed_stored = bootstrap::load_seed(store).is_ok();
    let Some(config) = config else {
        return Ok(BootstrapStatus {
            ready: false,
            human_did: None,
            github_handle: None,
            agents: Vec::new(),
            local_agent: None,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            mtls_ready: false,
            trusted: Vec::new(),
            seed_stored,
        });
    };
    let agent_names: Vec<String> = config.agents.iter().map(|a| a.agent_id.clone()).collect();
    let mtls_ready = bootstrap::mtls_is_complete(&paths.mtls_dir, &agent_names);
    Ok(BootstrapStatus {
        ready: seed_stored && mtls_ready && !config.agents.is_empty(),
        human_did: Some(config.human_did.clone()),
        github_handle: config.github_handle.clone(),
        agents: config
            .agents
            .iter()
            .map(|a| AgentIdentity { agent_name: a.agent_id.clone(), did: a.did.clone() })
            .collect(),
        local_agent: Some(config.local_agent.clone()),
        endpoint: config.endpoint.clone(),
        mtls_ready,
        trusted: config.trusted.clone(),
        seed_stored,
    })
}

/// The human DID behind a GitHub account's published `ssh-ed25519` key.
///
/// `github.com/<handle>.keys` is public, so this needs no token.
fn fetch_github_human_did(handle: &str) -> Result<String, String> {
    let listing = github_published_keys(handle)?;
    let vk = shadi_identity::ssh::first_ed25519_in_authorized_keys(&listing)
        .map_err(|e| format!("@{handle}: {e}"))?;
    Ok(shadi_identity::encode_did_key(&vk))
}

#[cfg(not(test))]
fn github_published_keys(handle: &str) -> Result<String, String> {
    let url = format!("https://github.com/{handle}.keys");
    let response = reqwest::blocking::Client::builder()
        .user_agent("shadi-desktop")
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?
        .get(&url)
        .send()
        .map_err(|e| format!("failed to fetch {url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("GitHub returned {} for {url}", response.status()));
    }
    response
        .text()
        .map_err(|e| format!("failed to read {url}: {e}"))
}

#[cfg(test)]
fn github_published_keys(_handle: &str) -> Result<String, String> {
    test_support::published_keys()
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, OnceLock};

    static PAYLOAD: OnceLock<Mutex<Option<String>>> = OnceLock::new();

    fn slot() -> &'static Mutex<Option<String>> {
        PAYLOAD.get_or_init(|| Mutex::new(None))
    }

    pub(crate) fn set(payload: Option<String>) {
        *slot().lock().expect("payload lock") = payload;
    }

    pub(crate) fn published_keys() -> Result<String, String> {
        slot()
            .lock()
            .expect("payload lock")
            .clone()
            .ok_or_else(|| "no test payload set".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_line() -> (String, String) {
        let seed = [3u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = shadi_identity::encode_did_key(&signing.verifying_key());
        let mut blob = Vec::new();
        let algo = shadi_identity::ssh::SSH_ED25519;
        blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
        blob.extend_from_slice(algo.as_bytes());
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(signing.verifying_key().as_bytes());
        use base64::Engine as _;
        let line = format!(
            "{algo} {} someone@example",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        );
        (line, did)
    }

    /// `op` may hand back a multi-line field quoted and with escaped newlines.
    /// The PEM has to come back with real breaks or the parser rejects it.
    #[test]
    fn op_private_key_output_is_normalised() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n";

        // Already clean.
        assert_eq!(normalise_op_private_key(pem), pem);

        // Quoted with escaped newlines, as `--format json` style output gives.
        let escaped = format!("\"{}\"", pem.replace('\n', "\\n"));
        assert_eq!(normalise_op_private_key(&escaped), pem);

        // Missing trailing newline gets one, since OpenSSH PEM needs it.
        let no_trailing = pem.trim_end();
        assert!(normalise_op_private_key(no_trailing).ends_with('\n'));
    }

    /// A normalised 1Password field must parse as a real key, not merely look
    /// like one — this is the seam between `op` output and the SSH parser.
    #[test]
    fn a_normalised_op_field_parses_as_an_ssh_key() {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[9u8; 32]);
        let pem = ssh_key::PrivateKey::from(keypair)
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .to_string();
        let as_op_would_return = format!("\"{}\"", pem.replace('\n', "\\n"));

        let restored = normalise_op_private_key(&as_op_would_return);
        let seed = shadi_identity::ssh::seed_from_openssh_private_key(restored.as_bytes(), None)
            .expect("round-trips through the op quoting");
        let direct =
            shadi_identity::ssh::seed_from_openssh_private_key(pem.as_bytes(), None).unwrap();
        assert_eq!(seed, direct, "quoting must not change the derivation root");
    }

    /// Trusting a handle means reading the ed25519 key it publishes, skipping
    /// other algorithms rather than taking whatever is listed first.
    #[test]
    fn github_handle_resolves_to_the_published_ed25519_did() {
        let (line, expected) = ed25519_line();
        test_support::set(Some(format!(
            "ssh-rsa AAAAB3NzaC1yc2EAAAA other\n{line}\n"
        )));
        assert_eq!(fetch_github_human_did("octocat").unwrap(), expected);
    }

    #[test]
    fn a_handle_without_an_ed25519_key_names_the_account() {
        test_support::set(Some("ssh-rsa AAAAB3NzaC1yc2EAAAA only-rsa\n".to_string()));
        let err = fetch_github_human_did("octocat").expect_err("must reject");
        assert!(err.contains("@octocat"), "should name the account: {err}");
        assert!(err.contains("ssh-keygen -t ed25519"), "should say how to fix: {err}");
    }

    /// A key that parses but is the wrong type must not silently pass.
    #[test]
    fn an_empty_listing_is_rejected() {
        test_support::set(Some(String::new()));
        assert!(fetch_github_human_did("ghost").is_err());
    }
}

/// An SSH Key item in 1Password, offered as an identity root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnePasswordSshKey {
    pub item: String,
    pub vault: Option<String>,
    /// Computed from the item's *public* key, so listing never reads a private
    /// key. `None` when the field is absent or not Ed25519.
    pub human_did: Option<String>,
}

fn op_binary() -> String {
    std::env::var("SHADI_OP_BINARY").unwrap_or_else(|_| "op".to_string())
}

fn run_op(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new(op_binary())
        .args(args)
        .output()
        .map_err(|e| format!("failed to run `op`: {e}. Install the 1Password CLI to use this source"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        // Not being signed in is the common case and has a specific remedy.
        if stderr.contains("not signed in") || stderr.contains("no account") {
            return Err(
                "1Password CLI is not signed in — run `op signin`, or enable the CLI in \
                 1Password's Developer settings"
                    .to_string(),
            );
        }
        return Err(format!("`op` failed: {stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// SSH Key items visible to the signed-in `op` session.
#[tauri::command]
pub async fn identity_list_1password_ssh_keys() -> Result<Vec<OnePasswordSshKey>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let json = run_op(&["item", "list", "--categories", "SSH Key", "--format", "json"])?;
        let items: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| format!("unexpected `op` output: {e}"))?;
        let Some(array) = items.as_array() else {
            return Ok(Vec::new());
        };

        Ok(array
            .iter()
            .filter_map(|item| {
                let title = item.get("title")?.as_str()?.to_string();
                let vault = item
                    .get("vault")
                    .and_then(|v| v.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                // Read only the public field for the DID preview.
                let human_did = op_public_key_did(&title, vault.as_deref());
                Some(OnePasswordSshKey { item: title, vault, human_did })
            })
            .collect())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

fn op_public_key_did(item: &str, vault: Option<&str>) -> Option<String> {
    let mut args = vec!["item", "get", item, "--fields", "public key"];
    if let Some(vault) = vault {
        args.push("--vault");
        args.push(vault);
    }
    let line = run_op(&args).ok()?;
    shadi_identity::ssh::verifying_key_from_openssh_public_key(line.trim())
        .ok()
        .map(|vk| shadi_identity::encode_did_key(&vk))
}

/// The private key bytes for a source.
///
/// 1Password's own `SecretStore` backend cannot be used here: it expects
/// base64 in an item's `notesPlain`, which is SHADI's own storage format, not
/// how a native SSH Key item holds its key. So this reads the item's
/// `private key` field through `op` directly.
fn read_key_material(source: &KeySource) -> Result<Vec<u8>, String> {
    match source {
        KeySource::File { path } => {
            std::fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))
        }
        KeySource::OnePassword { item, vault } => {
            let mut args = vec!["item", "get", item.as_str(), "--fields", "private key", "--reveal"];
            if let Some(vault) = vault {
                args.push("--vault");
                args.push(vault);
            }
            let value = run_op(&args)?;
            let key = normalise_op_private_key(&value);
            if !key.contains("OPENSSH PRIVATE KEY") {
                return Err(format!(
                    "1Password item '{item}' has no OpenSSH private key in its 'private key' \
                     field. Only SSH Key items hold one, and the vault may forbid revealing it"
                ));
            }
            Ok(key.into_bytes())
        }
    }
}

/// `op` returns a multi-line field quoted, and may escape the newlines; the PEM
/// has to come back with real line breaks or the parser rejects it.
fn normalise_op_private_key(raw: &str) -> String {
    let trimmed = raw.trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed);
    let restored = unquoted.replace("\\n", "\n");
    if restored.ends_with('\n') {
        restored
    } else {
        format!("{restored}\n")
    }
}
