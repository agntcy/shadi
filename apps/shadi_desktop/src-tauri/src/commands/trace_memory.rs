// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Trace and memory viewer (agntcy/shadi#121) — replaces `shadictl trace
//! list|summary` and `shadictl memory get|search|list`.

use serde::{Deserialize, Serialize};

use super::not_implemented;

const PANEL_ISSUE: u32 = 121;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub name: String,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummaryEntry {
    pub span_name: String,
    pub count: usize,
    pub avg_duration_ms: f64,
}

/// Read-only view of a memory entry. `payload` is only populated by
/// [`memory_get`] — [`memory_search`]/[`memory_list`] return metadata only,
/// matching the CLI's own behavior, so listing entries doesn't require the
/// same secret-verification gate as reading one's actual content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub scope: String,
    pub entry_key: String,
    pub payload: Option<String>,
}

/// List recent trace log entries (`shadictl trace list`).
#[tauri::command]
pub async fn trace_list(
    limit: usize,
    name: Option<String>,
    command: Option<String>,
    exit_code: Option<i32>,
) -> Result<Vec<TraceEntry>, String> {
    let _ = (limit, name, command, exit_code);
    not_implemented(PANEL_ISSUE)
}

/// Summarize trace logs by span name (`shadictl trace summary`).
#[tauri::command]
pub async fn trace_summary(limit: usize) -> Result<Vec<TraceSummaryEntry>, String> {
    let _ = limit;
    not_implemented(PANEL_ISSUE)
}

/// Read one memory entry, gated behind the same secret-verification path the
/// CLI's `memory get` uses (`shadictl memory get`).
#[tauri::command]
pub async fn memory_get(scope: String, entry_key: String) -> Result<MemoryEntry, String> {
    let _ = (scope, entry_key);
    not_implemented(PANEL_ISSUE)
}

/// Search memory entries by query (`shadictl memory search`).
#[tauri::command]
pub async fn memory_search(scope: Option<String>, query: String, limit: usize) -> Result<Vec<MemoryEntry>, String> {
    let _ = (scope, query, limit);
    not_implemented(PANEL_ISSUE)
}

/// List memory entries (`shadictl memory list`).
#[tauri::command]
pub async fn memory_list(scope: Option<String>, limit: usize) -> Result<Vec<MemoryEntry>, String> {
    let _ = (scope, limit);
    not_implemented(PANEL_ISSUE)
}
