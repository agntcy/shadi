// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Policy inspector and editor (agntcy/shadi#116) — replaces `shadictl
//! shell`'s `/policy query|patch|explain|diff` and the `--profile` presets.

use serde::{Deserialize, Serialize};

use super::not_implemented;

const PANEL_ISSUE: u32 = 116;

/// Serde-friendly mirror of `shadi_sandbox::SandboxPolicy` — the desktop app
/// doesn't link `shadi_sandbox` yet (that lands with #116's implementation),
/// so this is an independent shape with the same fields, not a re-export.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net_block: bool,
    pub net_allow: Vec<String>,
    /// "strict" | "balanced" | "connected", matching `shadictl --profile`.
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExplanation {
    pub effective: PolicyConfig,
    /// Human-readable provenance per field, e.g. "profile:strict", "cli:--allow /tmp".
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

/// Show the effective policy of the attached session (`/policy query`).
#[tauri::command]
pub async fn policy_query(socket_path: String) -> Result<PolicyConfig, String> {
    let _ = socket_path;
    not_implemented(PANEL_ISSUE)
}

/// Patch the policy of the attached session live (`/policy patch`).
#[tauri::command]
pub async fn policy_patch(socket_path: String, patch: PolicyConfig) -> Result<PolicyConfig, String> {
    let _ = (socket_path, patch);
    not_implemented(PANEL_ISSUE)
}

/// Resolved policy plus source inputs (`/policy explain`).
#[tauri::command]
pub async fn policy_explain(socket_path: String) -> Result<PolicyExplanation, String> {
    let _ = socket_path;
    not_implemented(PANEL_ISSUE)
}

/// Diff effective policy against a baseline profile (`/policy diff`).
#[tauri::command]
pub async fn policy_diff(socket_path: String, baseline_profile: String) -> Result<PolicyDiff, String> {
    let _ = (socket_path, baseline_profile);
    not_implemented(PANEL_ISSUE)
}

/// The named profile presets `shadictl --profile` accepts.
#[tauri::command]
pub async fn policy_profiles() -> Result<Vec<String>, String> {
    Ok(vec!["strict".into(), "balanced".into(), "connected".into()])
}
