// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Sandbox session management (agntcy/shadi#115) — replaces `shadictl shell`'s
//! `/status`, `/attach`, `/detach`, `/kill`, `/sessions`.

use serde::{Deserialize, Serialize};

use super::not_implemented;
use super::policy::PolicyConfig;

const PANEL_ISSUE: u32 = 115;

/// A discovered or attached SHADI sandbox control socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSession {
    pub name: String,
    pub socket_path: String,
    pub pid: Option<u32>,
}

/// Live status of an attached session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxStatus {
    pub session: SandboxSession,
    pub running: bool,
    pub uptime_secs: Option<u64>,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchSandboxRequest {
    pub command: Vec<String>,
    pub policy: PolicyConfig,
    pub session_name: Option<String>,
}

/// Launch a new sandboxed process (mirrors `shadictl <flags> -- <command>`).
#[tauri::command]
pub async fn sandbox_launch(request: LaunchSandboxRequest) -> Result<SandboxSession, String> {
    let _ = request;
    not_implemented(PANEL_ISSUE)
}

/// Discover running SHADI sandbox control sockets (`/sessions`).
#[tauri::command]
pub async fn sandbox_list_sessions() -> Result<Vec<SandboxSession>, String> {
    not_implemented(PANEL_ISSUE)
}

/// Attach to a running session by name or socket path (`/attach`).
#[tauri::command]
pub async fn sandbox_attach(socket_path: String) -> Result<SandboxStatus, String> {
    let _ = socket_path;
    not_implemented(PANEL_ISSUE)
}

/// Detach from the current session without terminating it (`/detach`).
#[tauri::command]
pub async fn sandbox_detach(socket_path: String) -> Result<(), String> {
    let _ = socket_path;
    not_implemented(PANEL_ISSUE)
}

/// Terminate the attached sandboxed process (`/kill`).
#[tauri::command]
pub async fn sandbox_kill(socket_path: String) -> Result<(), String> {
    let _ = socket_path;
    not_implemented(PANEL_ISSUE)
}

/// Live status of an attached session (`/status`).
#[tauri::command]
pub async fn sandbox_status(socket_path: String) -> Result<SandboxStatus, String> {
    let _ = socket_path;
    not_implemented(PANEL_ISSUE)
}
