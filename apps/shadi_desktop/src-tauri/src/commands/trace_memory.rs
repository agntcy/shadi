// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Trace and memory viewer (agntcy/shadi#121) — replaces `shadictl trace
//! list|summary` and `shadictl memory get|search|list`.
//!
//! Memory is a SQLCipher database, so every read needs its key, taken where
//! `shadictl memory` takes it: `SHADI_MEMORY_KEY`, else the secret store's
//! `shadi/memory/sqlcipher_key`. Reading that is the gate; the Desktop has no
//! other way in.

use std::collections::{BTreeMap, VecDeque};
use std::io::BufRead as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use shadi_memory::SqlCipherStore;

const MEMORY_KEY_NAME: &str = "shadi/memory/sqlcipher_key";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub name: Option<String>,
    pub command: Option<String>,
    pub exit_code: Option<i64>,
    pub timestamp: Option<String>,
    /// The line as written.
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummaryEntry {
    pub span_name: String,
    pub count: usize,
}

/// A memory entry. `payload` is set only by [`memory_get`]; listing and
/// searching return what identifies an entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: i64,
    pub scope: String,
    pub entry_key: String,
    pub created_at: String,
    pub payload: Option<String>,
}

impl MemoryEntry {
    fn from(entry: shadi_memory::MemoryEntry, with_payload: bool) -> Self {
        Self {
            id: entry.id,
            scope: entry.scope,
            entry_key: entry.entry_key,
            created_at: entry.created_at,
            payload: with_payload.then_some(entry.payload),
        }
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("task failed: {e}"))?
}

// --- Traces ------------------------------------------------------------------

/// `file`, else `SHADI_OTEL_FILE`, as `shadictl trace` resolves it.
fn trace_file(file: Option<String>) -> Result<PathBuf, String> {
    file.filter(|f| !f.trim().is_empty())
        .or_else(|| {
            std::env::var("SHADI_OTEL_FILE")
                .ok()
                .filter(|f| !f.trim().is_empty())
        })
        .map(PathBuf::from)
        .ok_or_else(|| "give a trace file, or set SHADI_OTEL_FILE".to_string())
}

/// The last `limit` lines of `path`.
fn tail(path: &Path, limit: usize) -> Result<Vec<String>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = VecDeque::with_capacity(limit.min(10_000));
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
        if limit == 0 {
            continue;
        }
        lines.push_back(line);
        if lines.len() > limit {
            lines.pop_front();
        }
    }
    Ok(lines.into())
}

fn span_name(value: &Value) -> Option<String> {
    value
        .pointer("/span/name")
        .or_else(|| {
            value
                .get("spans")?
                .as_array()?
                .iter()
                .find_map(|s| s.get("name"))
        })
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn trace_entry(line: String) -> TraceEntry {
    let value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
    TraceEntry {
        name: span_name(&value),
        command: value
            .pointer("/fields/command")
            .and_then(Value::as_str)
            .map(str::to_string),
        exit_code: value.pointer("/fields/exit_code").and_then(Value::as_i64),
        timestamp: value
            .get("timestamp")
            .and_then(Value::as_str)
            .map(str::to_string),
        raw: line,
    }
}

fn matches(
    entry: &TraceEntry,
    name: Option<&str>,
    command: Option<&str>,
    exit_code: Option<i64>,
) -> bool {
    let contains = |have: &Option<String>, want: Option<&str>| {
        want.is_none_or(|want| have.as_deref().is_some_and(|have| have.contains(want)))
    };
    contains(&entry.name, name)
        && contains(&entry.command, command)
        && exit_code.is_none_or(|code| entry.exit_code == Some(code))
}

/// Recent trace lines, newest last, filtered like `shadictl trace list`.
#[tauri::command]
pub async fn trace_list(
    file: Option<String>,
    limit: usize,
    name: Option<String>,
    command: Option<String>,
    exit_code: Option<i64>,
) -> Result<Vec<TraceEntry>, String> {
    blocking(move || {
        let path = trace_file(file)?;
        Ok(tail(&path, limit)?
            .into_iter()
            .map(trace_entry)
            .filter(|e| matches(e, name.as_deref(), command.as_deref(), exit_code))
            .collect())
    })
    .await
}

/// How many of the recent lines each span name has (`shadictl trace summary`).
#[tauri::command]
pub async fn trace_summary(
    file: Option<String>,
    limit: usize,
) -> Result<Vec<TraceSummaryEntry>, String> {
    blocking(move || {
        let path = trace_file(file)?;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for entry in tail(&path, limit)?.into_iter().map(trace_entry) {
            if let Some(name) = entry.name {
                *counts.entry(name).or_default() += 1;
            }
        }
        Ok(counts
            .into_iter()
            .map(|(span_name, count)| TraceSummaryEntry { span_name, count })
            .collect())
    })
    .await
}

// --- Memory ------------------------------------------------------------------

/// Open `db` (or `SHADI_MEMORY_DB`) with the key `shadictl memory` uses.
fn open_memory(db: Option<String>) -> Result<SqlCipherStore, String> {
    let path = db
        .filter(|d| !d.trim().is_empty())
        .or_else(|| std::env::var("SHADI_MEMORY_DB").ok())
        .ok_or_else(|| "give a memory database, or set SHADI_MEMORY_DB".to_string())?;
    if !Path::new(&path).is_file() {
        return Err(format!("no memory database at {path}"));
    }
    let key = match std::env::var("SHADI_MEMORY_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            let secret = agent_secrets::default_store()
                .get(MEMORY_KEY_NAME)
                .map_err(|_| format!("missing SHADI key: {MEMORY_KEY_NAME}"))?;
            String::from_utf8(secret.expose(|bytes| bytes.to_vec()))
                .map_err(|_| "the memory key is not UTF-8".to_string())?
        }
    };
    SqlCipherStore::open(Path::new(&path), &key).map_err(|e| e.to_string())
}

/// Read one memory entry (`shadictl memory get`).
#[tauri::command]
pub async fn memory_get(
    db: Option<String>,
    scope: String,
    entry_key: String,
) -> Result<Option<MemoryEntry>, String> {
    blocking(move || {
        let entry = open_memory(db)?
            .get_latest(&scope, &entry_key)
            .map_err(|e| e.to_string())?;
        Ok(entry.map(|e| MemoryEntry::from(e, true)))
    })
    .await
}

/// Search memory entries (`shadictl memory search`), without their payloads.
#[tauri::command]
pub async fn memory_search(
    db: Option<String>,
    scope: Option<String>,
    query: String,
    limit: usize,
) -> Result<Vec<MemoryEntry>, String> {
    blocking(move || {
        let entries = open_memory(db)?
            .search(scope.as_deref(), &query, limit)
            .map_err(|e| e.to_string())?;
        Ok(entries
            .into_iter()
            .map(|e| MemoryEntry::from(e, false))
            .collect())
    })
    .await
}

/// List memory entries (`shadictl memory list`), without their payloads.
#[tauri::command]
pub async fn memory_list(
    db: Option<String>,
    scope: Option<String>,
    limit: usize,
) -> Result<Vec<MemoryEntry>, String> {
    blocking(move || {
        let entries = open_memory(db)?
            .list(scope.as_deref(), limit)
            .map_err(|e| e.to_string())?;
        Ok(entries
            .into_iter()
            .map(|e| MemoryEntry::from(e, false))
            .collect())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINES: &[&str] = &[
        r#"{"timestamp":"t1","fields":{"command":"claude","exit_code":0},"span":{"name":"shadi.sandbox.run"}}"#,
        r#"{"timestamp":"t2","fields":{"command":"codex","exit_code":1},"spans":[{"name":"shadi.sandbox.run"}]}"#,
        r#"{"timestamp":"t3","fields":{},"span":{"name":"shadi.memory.command"}}"#,
        "not json",
    ];

    #[test]
    fn trace_lines_parse_and_filter_like_the_cli() {
        let entries: Vec<TraceEntry> = LINES.iter().map(|l| trace_entry(l.to_string())).collect();
        assert_eq!(entries[1].name.as_deref(), Some("shadi.sandbox.run"));
        assert_eq!(entries[1].exit_code, Some(1));
        assert!(entries[3].name.is_none() && entries[3].raw == "not json");

        let kept = |name, command, code| {
            entries
                .iter()
                .filter(|e| matches(e, name, command, code))
                .count()
        };
        assert_eq!(kept(Some("sandbox"), None, None), 2);
        assert_eq!(kept(None, Some("codex"), None), 1);
        assert_eq!(kept(None, None, Some(0)), 1);
        assert_eq!(kept(None, None, None), 4);
    }

    #[test]
    fn tail_keeps_the_last_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traces.jsonl");
        std::fs::write(&path, LINES.join("\n")).unwrap();
        assert_eq!(tail(&path, 2).unwrap(), LINES[2..].to_vec());
        assert!(tail(&path, 0).unwrap().is_empty());
    }

    #[test]
    fn memory_lists_without_payloads_and_gets_with_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.db");
        let store = SqlCipherStore::open(&path, "test-key").unwrap();
        store.put("notes", "plan", "ship it").unwrap();
        let listed = MemoryEntry::from(store.list(None, 10).unwrap().remove(0), false);
        assert!(listed.payload.is_none());
        let got = MemoryEntry::from(store.get_latest("notes", "plan").unwrap().unwrap(), true);
        assert_eq!(got.payload.as_deref(), Some("ship it"));
    }
}
