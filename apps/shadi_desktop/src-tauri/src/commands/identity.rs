// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Identity and secrets (agntcy/shadi#117) — replaces `shadictl`'s
//! `did-from-gpg`, `did-from-github`, `derive-agent-identity`,
//! `verify-agent-identity`, `get-secret`, `put-key`, `--list-keychain`.

use serde::{Deserialize, Serialize};

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
