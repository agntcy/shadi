// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Agent Directory (agntcy/shadi#119) — replaces `shadictl dir search|pull`
//! and `agentbridge register --dir-publish`, through `dirctl` as both do.

use agentbridge::dir_registry::{publish_record, wrap_agent_card};
use agentbridge::member_source::{pull_record_json, search_cids, DirLookupOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirRecordSummary {
    pub cid: String,
    pub name: String,
    /// The record's author: the agent's `did:key` for a SHADI agent.
    pub did: Option<String>,
    pub skills: Vec<String>,
    /// The record as pulled, for display.
    pub record_json: String,
}

fn options(dir_server: String, limit: usize) -> DirLookupOptions {
    DirLookupOptions {
        server_addr: dir_server,
        gh_token: std::env::var("GITHUB_TOKEN").ok(),
        limit,
    }
}

fn summarize(cid: String, record: &Value) -> DirRecordSummary {
    let skills = record
        .get("skills")
        .and_then(Value::as_array)
        .map(|skills| {
            skills
                .iter()
                .filter_map(|skill| skill.as_str().or_else(|| skill.get("name")?.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    DirRecordSummary {
        cid,
        name: record
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("(unnamed)")
            .to_string(),
        did: record
            .get("authors")
            .and_then(Value::as_array)
            .and_then(|authors| authors.first())
            .and_then(Value::as_str)
            .map(str::to_string),
        skills,
        record_json: serde_json::to_string_pretty(record).unwrap_or_default(),
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("task failed: {e}"))?
}

/// Search the directory by skill, or by author when `query` is a DID
/// (`shadictl dir search`). Records that fail to pull are skipped.
#[tauri::command]
pub async fn dir_search(
    query: String,
    dir_server: String,
    limit: usize,
) -> Result<Vec<DirRecordSummary>, String> {
    blocking(move || {
        let query = query.trim();
        let flag = if query.starts_with("did:") {
            "--author"
        } else {
            "--skill"
        };
        let options = options(dir_server, limit.max(1));
        let cids = search_cids(&[flag, query], &options)?;
        Ok(cids
            .into_iter()
            .filter_map(|cid| {
                let record = pull_record_json(&cid, &options).ok()?;
                Some(summarize(cid, &record))
            })
            .collect())
    })
    .await
}

/// Fetch one record (`shadictl dir pull`).
#[tauri::command]
pub async fn dir_pull(cid: String, dir_server: String) -> Result<DirRecordSummary, String> {
    blocking(move || {
        let record = pull_record_json(cid.trim(), &options(dir_server, 1))?;
        Ok(summarize(cid, &record))
    })
    .await
}

/// Publish an A2A AgentCard to the directory as `did`'s record
/// (`agentbridge register --dir-publish`). Returns the record's CID.
#[tauri::command]
pub async fn dir_register(
    agent_card_json: String,
    dir_server: String,
    did: Option<String>,
) -> Result<String, String> {
    blocking(move || {
        let card: Value =
            serde_json::from_str(&agent_card_json).map_err(|e| format!("not an AgentCard: {e}"))?;
        if let Some(did) = did.as_deref() {
            shadi_identity::parse_did_key(did).map_err(|e| e.to_string())?;
        }
        let record = wrap_agent_card(&card, did.as_deref());
        let token = std::env::var("GITHUB_TOKEN").ok();
        publish_record(&record, &dir_server, token.as_deref()).map_err(|e| e.to_string())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrapped_card_summarizes_to_its_name_did_and_skills() {
        let card = serde_json::json!({
            "name": "copilot",
            "skills": [{"id": "review", "name": "code review"}],
        });
        let record = wrap_agent_card(&card, Some("did:key:z6MkExample"));
        let summary = summarize("bafy".to_string(), &record);
        assert_eq!(summary.name, "copilot");
        assert_eq!(summary.did.as_deref(), Some("did:key:z6MkExample"));
        // The record names a skill by the card's skill id, which is what
        // `dirctl search --skill` matches.
        assert_eq!(summary.skills, vec!["review".to_string()]);
        assert!(summary.record_json.contains("integration/a2a"));
    }
}
