// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! agentbridge control panel (agntcy/shadi#120) — replaces `agentbridge
//! list|handoff|delegate|coordinate`.

use serde::{Deserialize, Serialize};

use super::not_implemented;

const PANEL_ISSUE: u32 = 120;

/// Tauri event name `agentbridge_coordinate` emits a [`CoordinateRoundEvent`]
/// on, once per round, while a coordination run is in flight. The frontend
/// subscribes with `listen("coordinate:round", ...)` before invoking the
/// command — this is what makes round-by-round progress visible instead of
/// only a final result (the highest-value piece of this panel, per #120).
///
/// Unused until #120 wires a real `app.emit(...)` call — part of the
/// contract, not dead code left behind by accident.
#[allow(dead_code)]
pub const COORDINATE_ROUND_EVENT: &str = "coordinate:round";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub agent_id: String,
    pub tool: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPacketSummary {
    pub id: String,
    pub source_agent: String,
    pub conversation_messages: usize,
    pub artifacts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateResult {
    pub response: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinateRequest {
    pub goal: String,
    /// `claude-code` | `copilot` | `codex` | `cursor-agent` |
    /// `generic-stdio:<cmd>` | `slim:<agent-id>[@<host:port>]`, matching
    /// `agentbridge coordinate --agents`.
    pub agent_specs: Vec<String>,
    pub quorum: usize,
    pub max_rounds: u64,
    pub require_human: bool,
}

/// Emitted on [`COORDINATE_ROUND_EVENT`] as a coordination run progresses.
/// Unused until #120 wires a real `app.emit(...)` call.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinateRoundEvent {
    pub round: u64,
    pub agent: String,
    /// "proposal" | "vote".
    pub kind: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinateResult {
    pub winning_agent: String,
    pub artifact: String,
}

/// List registered adapters, via DIR discovery or the local SLIM node only
/// (`agentbridge list [--local]`).
#[tauri::command]
pub async fn agentbridge_list_adapters(local_only: bool) -> Result<Vec<AdapterInfo>, String> {
    let _ = local_only;
    not_implemented(PANEL_ISSUE)
}

/// Snapshot context from `from` and inject it into `to` (`agentbridge handoff`).
#[tauri::command]
pub async fn agentbridge_handoff(from: String, to: String) -> Result<ContextPacketSummary, String> {
    let _ = (from, to);
    not_implemented(PANEL_ISSUE)
}

/// Send a single prompt to a remote adapter over A2A/SLIM (`agentbridge delegate`).
#[tauri::command]
pub async fn agentbridge_delegate(
    prompt: String,
    to: String,
    agent_id: String,
    endpoint: String,
) -> Result<DelegateResult, String> {
    let _ = (prompt, to, agent_id, endpoint);
    not_implemented(PANEL_ISSUE)
}

/// Run `MasRuntime<DevelopmentEngine>` across a set of agents toward a goal
/// (`agentbridge coordinate`). Emits [`COORDINATE_ROUND_EVENT`] as rounds
/// complete; returns only the final winning artifact.
#[tauri::command]
pub async fn agentbridge_coordinate(
    app: tauri::AppHandle,
    request: CoordinateRequest,
) -> Result<CoordinateResult, String> {
    let _ = (app, request);
    not_implemented(PANEL_ISSUE)
}
