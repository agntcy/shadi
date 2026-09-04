// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Policy inspector and editor (agntcy/shadi#116) — replaces `shadictl
//! shell`'s `/policy query|patch|explain|diff` and the `--profile` presets.
//!
//! `query` and `patch` reach a live session over its control socket, the
//! same client `shadi_sandbox::control` gives the sandbox panel. `explain`
//! and `diff` stay stubs: their shadictl equivalents resolve a policy file,
//! a named profile and CLI flags against shadictl's own `Cli` type
//! (`policy_helpers::resolve_policy`), which is private to that binary and
//! not yet factored into a form this app can call. That factoring is its
//! own piece of work, not something to rush alongside the live-session half.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use shadi_sandbox::{control, PolicyPatch, PolicyPatchResponse};

use super::not_implemented;

const PANEL_ISSUE: u32 = 116;

/// Blocking round trip to a session's control socket, off the async runtime
/// — same reasoning as the sandbox panel's commands: the client is blocking
/// socket I/O, so this must not tie up a Tauri async worker.
async fn blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|err| format!("policy task failed: {err}"))?
}

/// Mirrors the JSON `handle_query` sends over the control socket
/// (`crates/shadictl/src/policy_watch.rs`) — the live effective policy of an
/// attached session, not shadictl's own private `SandboxPolicy` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivePolicySnapshot {
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub net_allow: Vec<String>,
    pub net_blocked: bool,
    pub allow_command: Vec<String>,
    pub block_command: Vec<String>,
    /// Filesystem and command changes staged by a prior patch, pending the
    /// restart that applies them.
    pub staged_read: Vec<String>,
    pub staged_write: Vec<String>,
    pub staged_allow: Vec<String>,
    /// The live network allowlist, when the session's proxy applied a
    /// network patch immediately rather than staging it.
    pub net_allow_live: Option<Vec<String>>,
}

/// The policy a sandbox is launched with (`sandbox_launch`'s
/// `LaunchSandboxRequest`) — a config to build a fresh `SandboxPolicy` from,
/// not the live, already-resolved shape `LivePolicySnapshot` reads back.
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
pub async fn policy_query(socket_path: String) -> Result<LivePolicySnapshot, String> {
    blocking(move || {
        let value = control::query_policy(&PathBuf::from(socket_path))?;
        serde_json::from_value(value)
            .map_err(|err| format!("session returned an unexpected policy shape: {err}"))
    })
    .await
}

/// Patch the policy of the attached session live (`/policy patch`).
#[tauri::command]
pub async fn policy_patch(
    socket_path: String,
    patch: PolicyPatch,
) -> Result<PolicyPatchResponse, String> {
    blocking(move || control::send_patch(&PathBuf::from(socket_path), &patch)).await
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
