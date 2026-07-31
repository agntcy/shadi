// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Agent Directory (agntcy/shadi#119) — replaces `shadictl dir
//! search|pull|info` and `agentbridge register --dir-publish`.

use serde::{Deserialize, Serialize};

use super::not_implemented;

const PANEL_ISSUE: u32 = 119;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirRecordSummary {
    pub cid: String,
    pub name: String,
    pub did: Option<String>,
    pub skills: Vec<String>,
}

/// Search the directory for agent records by skill (`shadictl dir search`).
#[tauri::command]
pub async fn dir_search(skill: String, dir_server: String, limit: usize) -> Result<Vec<DirRecordSummary>, String> {
    let _ = (skill, dir_server, limit);
    not_implemented(PANEL_ISSUE)
}

/// Fetch and cache an OASF agent record (`shadictl dir pull`).
#[tauri::command]
pub async fn dir_pull(cid: String, dir_server: String) -> Result<DirRecordSummary, String> {
    let _ = (cid, dir_server);
    not_implemented(PANEL_ISSUE)
}

/// Display metadata about a locally cached record (`shadictl dir info`).
#[tauri::command]
pub async fn dir_info(cid: String) -> Result<DirRecordSummary, String> {
    let _ = cid;
    not_implemented(PANEL_ISSUE)
}

/// Publish a real, connectable AgentCard to the directory
/// (`agentbridge register --dir-publish`). Returns the record's CID.
#[tauri::command]
pub async fn dir_register(agent_card_json: String, dir_server: String) -> Result<String, String> {
    let _ = (agent_card_json, dir_server);
    not_implemented(PANEL_ISSUE)
}
