// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SLIM operations (agntcy/shadi#118) — replaces `shadictl shell`'s
//! `/slim start-node|create-group|invite|join|controller`.

use serde::{Deserialize, Serialize};

use super::not_implemented;

const PANEL_ISSUE: u32 = 118;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimNodeStatus {
    pub running: bool,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimGroupMember {
    pub name: String,
    pub did: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimGroupInfo {
    pub channel: String,
    /// "moderator" | "participant".
    pub role: String,
    pub members: Vec<SlimGroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimConnection {
    pub id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimRoute {
    pub destination: String,
    pub via: String,
}

/// Start a local native SLIM node with SHADI mTLS defaults (`/slim start-node`).
#[tauri::command]
pub async fn slim_node_start() -> Result<SlimNodeStatus, String> {
    not_implemented(PANEL_ISSUE)
}

#[tauri::command]
pub async fn slim_node_status() -> Result<SlimNodeStatus, String> {
    not_implemented(PANEL_ISSUE)
}

/// Create a group with members resolved from Agent Directory discovery
/// and/or named explicitly (`/slim create-group`, `member_specs` in the
/// `skill:<skill>` | `did:<did>` | `explicit:<name>=<did>[@<endpoint>]` shape
/// documented in `shadictl slim create-group --help`).
#[tauri::command]
pub async fn slim_group_create(
    channel: String,
    member_specs: Vec<String>,
    dir_server: String,
) -> Result<SlimGroupInfo, String> {
    let _ = (channel, member_specs, dir_server);
    not_implemented(PANEL_ISSUE)
}

/// Invite a participant into the active group session (`/slim invite`,
/// `/slim invite-from`).
#[tauri::command]
pub async fn slim_group_invite(channel: String, member_spec: String) -> Result<SlimGroupInfo, String> {
    let _ = (channel, member_spec);
    not_implemented(PANEL_ISSUE)
}

/// Join an already-running channel as a participant (`/slim join`).
#[tauri::command]
pub async fn slim_group_join(channel: String) -> Result<SlimGroupInfo, String> {
    let _ = channel;
    not_implemented(PANEL_ISSUE)
}

/// List connections known to a controller endpoint (`/slim controller
/// list-connections`).
#[tauri::command]
pub async fn slim_controller_list_connections(endpoint: String) -> Result<Vec<SlimConnection>, String> {
    let _ = endpoint;
    not_implemented(PANEL_ISSUE)
}

/// List routes known to a controller endpoint (`/slim controller
/// list-routes`).
#[tauri::command]
pub async fn slim_controller_list_routes(endpoint: String) -> Result<Vec<SlimRoute>, String> {
    let _ = endpoint;
    not_implemented(PANEL_ISSUE)
}
