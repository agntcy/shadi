// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Pluggable resolution of SLIM group member candidates.
//!
//! A group moderator can build up who's trusted/invitable in more than one
//! way: by searching the Agent Directory for a skill, by looking up an
//! already-known DID, or by naming exact `{name, did, endpoint}` triples by
//! hand. [`MemberSource`] is the common abstraction — each technique is a
//! small, independent implementation, and a group's candidate pool can come
//! from any combination of them.

use std::process::Command;

use serde_json::Value;

use crate::dir_registry::dirctl_binary;

/// A directory-resolved (or manually-named) agent, ready to be admitted into
/// a group's DID trust set and/or invited into a live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateMember {
    pub name: String,
    pub did: String,
    pub slim_endpoint: Option<String>,
}

/// A technique for resolving a set of candidate group members.
pub trait MemberSource {
    fn resolve(&self) -> Result<Vec<CandidateMember>, String>;
}

/// Server/auth used by every Agent Directory-backed `MemberSource`.
#[derive(Debug, Clone)]
pub struct DirLookupOptions {
    pub server_addr: String,
    pub gh_token: Option<String>,
    pub limit: usize,
}

/// Discover candidates by capability: `dirctl search --skill <skill>`, then
/// pull each matching record for its real A2A card and DID.
pub struct SkillSearchSource {
    pub skill: String,
    pub dir: DirLookupOptions,
}

impl MemberSource for SkillSearchSource {
    fn resolve(&self) -> Result<Vec<CandidateMember>, String> {
        resolve_via_dirctl_query(&["--skill", &self.skill], &self.dir)
    }
}

/// Discover a candidate by an already-known DID: `dirctl search --author
/// <did>` resolves its current name/skills/SLIM endpoint from the Directory
/// without the moderator needing to know anything but the DID up front.
pub struct DidLookupSource {
    pub did: String,
    pub dir: DirLookupOptions,
}

impl MemberSource for DidLookupSource {
    fn resolve(&self) -> Result<Vec<CandidateMember>, String> {
        resolve_via_dirctl_query(&["--author", &self.did], &self.dir)
    }
}

/// The fully-manual technique: candidates named directly, no Directory
/// round-trip at all. Formalizes what a moderator could already do by hand
/// into the same abstraction as the discovery-based sources.
pub struct ExplicitListSource {
    pub entries: Vec<CandidateMember>,
}

impl MemberSource for ExplicitListSource {
    fn resolve(&self) -> Result<Vec<CandidateMember>, String> {
        Ok(self.entries.clone())
    }
}

// ---------------------------------------------------------------------------
// `--members <spec>` parsing — the CLI-facing surface shared by every call
// site that lets a moderator name member sources on the command line
// (`shadictl slim create-group --members ...`, `/slim invite-from <spec>`).
// ---------------------------------------------------------------------------

/// Parse one `--members`/`invite-from` spec into the `MemberSource` it names:
/// `skill:<skill>` → [`SkillSearchSource`], `did:<did>` → [`DidLookupSource`],
/// `explicit:<name>=<did>[@<endpoint>]` → [`ExplicitListSource`].
pub fn parse_member_spec(
    spec: &str,
    dir: &DirLookupOptions,
) -> Result<Box<dyn MemberSource>, String> {
    if let Some(skill) = spec.strip_prefix("skill:") {
        if skill.is_empty() {
            return Err(format!("invalid member spec '{spec}': skill: needs a skill name"));
        }
        return Ok(Box::new(SkillSearchSource { skill: skill.to_string(), dir: dir.clone() }));
    }

    if let Some(did) = spec.strip_prefix("did:") {
        if did.is_empty() {
            return Err(format!("invalid member spec '{spec}': did: needs a DID"));
        }
        return Ok(Box::new(DidLookupSource { did: did.to_string(), dir: dir.clone() }));
    }

    if let Some(rest) = spec.strip_prefix("explicit:") {
        let (name, did_and_endpoint) = rest.split_once('=').ok_or_else(|| {
            format!("invalid member spec '{spec}': expected explicit:<name>=<did>[@<endpoint>]")
        })?;
        if name.is_empty() {
            return Err(format!("invalid member spec '{spec}': explicit: needs a name"));
        }
        let (did, endpoint) = match did_and_endpoint.split_once('@') {
            Some((did, endpoint)) => (did, Some(endpoint.to_string())),
            None => (did_and_endpoint, None),
        };
        if did.is_empty() {
            return Err(format!("invalid member spec '{spec}': explicit: needs a DID"));
        }
        return Ok(Box::new(ExplicitListSource {
            entries: vec![CandidateMember {
                name: name.to_string(),
                did: did.to_string(),
                slim_endpoint: endpoint,
            }],
        }));
    }

    Err(format!(
        "invalid member spec '{spec}': expected skill:<skill>, did:<did>, or explicit:<name>=<did>[@<endpoint>]"
    ))
}

/// Resolve every `--members` spec and concatenate their candidates. Specs are
/// resolved independently, in order — a group's candidate pool can come from
/// any combination of techniques at once.
pub fn resolve_members(
    specs: &[String],
    dir: &DirLookupOptions,
) -> Result<Vec<CandidateMember>, String> {
    let mut resolved = Vec::new();
    for spec in specs {
        let source = parse_member_spec(spec, dir)?;
        resolved.extend(source.resolve()?);
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// dirctl-backed resolution
// ---------------------------------------------------------------------------

fn apply_dir_auth(cmd: &mut Command, dir: &DirLookupOptions) {
    if let Some(token) = &dir.gh_token {
        cmd.env("DIRECTORY_CLIENT_AUTH_MODE", "github")
            .env("DIRECTORY_CLIENT_GITHUB_TOKEN", token);
    }
}

/// Run `dirctl search <query_args> --output jsonl`, then pull and parse each
/// matching CID for a real `{name, did, slim_endpoint}` candidate.
fn resolve_via_dirctl_query(
    query_args: &[&str],
    dir: &DirLookupOptions,
) -> Result<Vec<CandidateMember>, String> {
    let cids = search_cids(query_args, dir)?;
    let mut members = Vec::with_capacity(cids.len());
    for cid in cids {
        match pull_record_json(&cid, dir) {
            Ok(record) => {
                if let Some(candidate) = extract_candidate(&record) {
                    members.push(candidate);
                } else {
                    eprintln!(
                        "[member_source] {cid}: no DID (authors) or integration/a2a card — skipped"
                    );
                }
            }
            Err(e) => eprintln!("[member_source] failed to pull {cid}: {e}"),
        }
    }
    Ok(members)
}

fn search_cids(query_args: &[&str], dir: &DirLookupOptions) -> Result<Vec<String>, String> {
    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("search");
    for arg in query_args {
        cmd.arg(arg);
    }
    cmd.arg("--limit")
        .arg(dir.limit.to_string())
        .arg("--server-addr")
        .arg(&dir.server_addr)
        .arg("--output")
        .arg("jsonl");
    apply_dir_auth(&mut cmd, dir);

    let output = match cmd.output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("dirctl not found in PATH".to_string());
        }
        Err(e) => return Err(format!("dirctl search failed: {e}")),
        Ok(o) => o,
    };
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<String>(l.trim()).ok())
        .collect())
}

fn pull_record_json(cid: &str, dir: &DirLookupOptions) -> Result<Value, String> {
    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("pull")
        .arg(cid)
        .arg("--server-addr")
        .arg(&dir.server_addr)
        .arg("--output")
        .arg("json");
    apply_dir_auth(&mut cmd, dir);

    let output = match cmd.output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("dirctl not found in PATH".to_string());
        }
        Err(e) => return Err(format!("dirctl pull failed: {e}")),
        Ok(o) => o,
    };
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }

    serde_json::from_slice(&output.stdout).map_err(|e| format!("parse pulled record: {e}"))
}

/// Extract `{name, did, slim_endpoint}` from a pulled OASF record: the DID is
/// the record's own `authors[0]`, the name/endpoint come from the
/// `integration/a2a` module's `card_data` (see [`crate::dir_registry::wrap_agent_card`]
/// for the shape this mirrors). Returns `None` if either is missing — a
/// record without a DID or without a real A2A card isn't a usable candidate.
fn extract_candidate(record: &Value) -> Option<CandidateMember> {
    let did = record
        .get("authors")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)?
        .to_string();

    let card = record
        .get("modules")
        .and_then(Value::as_array)?
        .iter()
        .find(|m| m.get("name").and_then(Value::as_str) == Some("integration/a2a"))
        .and_then(|m| m.get("data"))
        .and_then(|d| d.get("card_data"))?;

    let name = card
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("(unnamed)")
        .to_string();

    let slim_endpoint = card
        .get("supportedInterfaces")
        .and_then(Value::as_array)
        .and_then(|ifaces| {
            ifaces.iter().find_map(|iface| {
                let url = iface.get("url")?.as_str()?;
                let rest = url.strip_prefix("slim://")?;
                Some(rest.split('/').next().unwrap_or(rest).to_string())
            })
        });

    Some(CandidateMember { name, did, slim_endpoint })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a2a_record(name: &str, did: &str, endpoint: &str) -> Value {
        serde_json::json!({
            "authors": [did],
            "modules": [{
                "name": "integration/a2a",
                "data": {
                    "card_data": {
                        "name": name,
                        "supportedInterfaces": [{
                            "url": format!("slim://{endpoint}/agntcy/shadi/{name}-a2a"),
                            "protocolBinding": "SLIMRPC",
                            "protocolVersion": "0.3.0",
                        }],
                    },
                    "card_schema_version": "v1.0.0",
                },
            }],
        })
    }

    #[test]
    fn extract_candidate_reads_did_and_slim_endpoint_from_module() {
        let record = a2a_record("copilot", "did:key:z6Mk...", "127.0.0.1:47357");
        let candidate = extract_candidate(&record).expect("candidate");
        assert_eq!(candidate.name, "copilot");
        assert_eq!(candidate.did, "did:key:z6Mk...");
        assert_eq!(candidate.slim_endpoint.as_deref(), Some("127.0.0.1:47357"));
    }

    #[test]
    fn extract_candidate_returns_none_without_authors() {
        let mut record = a2a_record("copilot", "did:key:z6Mk...", "127.0.0.1:47357");
        record.as_object_mut().unwrap().remove("authors");
        assert!(extract_candidate(&record).is_none());
    }

    #[test]
    fn extract_candidate_returns_none_without_a2a_module() {
        let record = serde_json::json!({"authors": ["did:key:z6Mk..."], "modules": []});
        assert!(extract_candidate(&record).is_none());
    }

    fn test_dir() -> DirLookupOptions {
        DirLookupOptions { server_addr: "localhost:9999".to_string(), gh_token: None, limit: 10 }
    }

    #[test]
    #[cfg(unix)]
    fn parse_member_spec_skill_builds_a_working_skill_search_source() {
        let _guard = crate::dir_registry::dirctl_env_lock().lock().expect("lock");
        let record = a2a_record("copilot", "did:key:z6Mk...", "127.0.0.1:47357");
        let (script, _dir) = fake_dirctl_script("bafkreitest", &record.to_string());
        std::env::set_var("SHADI_DIRCTL_BINARY", &script);

        let source = parse_member_spec("skill:code_generation/implementation", &test_dir())
            .expect("parse");
        let candidates = source.resolve().expect("resolve");

        std::env::remove_var("SHADI_DIRCTL_BINARY");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "copilot");
    }

    #[test]
    #[cfg(unix)]
    fn parse_member_spec_did_builds_a_working_did_lookup_source() {
        let _guard = crate::dir_registry::dirctl_env_lock().lock().expect("lock");
        let record = a2a_record("claude-code", "did:key:z6Mkagent", "127.0.0.1:47560");
        let (script, _dir) = fake_dirctl_script("bafkreiagent", &record.to_string());
        std::env::set_var("SHADI_DIRCTL_BINARY", &script);

        let source = parse_member_spec("did:did:key:z6Mkagent", &test_dir()).expect("parse");
        let candidates = source.resolve().expect("resolve");

        std::env::remove_var("SHADI_DIRCTL_BINARY");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].did, "did:key:z6Mkagent");
    }

    #[test]
    fn parse_member_spec_explicit_with_endpoint() {
        let source = parse_member_spec("explicit:avatar=did:key:human@127.0.0.1:47560", &test_dir())
            .expect("parse");
        let candidates = source.resolve().expect("resolve");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "avatar");
        assert_eq!(candidates[0].did, "did:key:human");
        assert_eq!(candidates[0].slim_endpoint.as_deref(), Some("127.0.0.1:47560"));
    }

    #[test]
    fn parse_member_spec_explicit_without_endpoint() {
        let source =
            parse_member_spec("explicit:avatar=did:key:human", &test_dir()).expect("parse");
        let candidates = source.resolve().expect("resolve");
        assert_eq!(candidates[0].slim_endpoint, None);
    }

    #[test]
    fn parse_member_spec_rejects_unknown_prefix() {
        assert!(parse_member_spec("bogus:whatever", &test_dir()).is_err());
    }

    #[test]
    fn parse_member_spec_rejects_explicit_without_equals() {
        assert!(parse_member_spec("explicit:avatar", &test_dir()).is_err());
    }

    #[test]
    fn resolve_members_concatenates_multiple_specs() {
        let specs = vec![
            "explicit:avatar=did:key:human".to_string(),
            "explicit:claude-code=did:key:agent@127.0.0.1:47560".to_string(),
        ];
        let resolved = resolve_members(&specs, &test_dir()).expect("resolve");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "avatar");
        assert_eq!(resolved[1].name, "claude-code");
    }

    #[test]
    fn explicit_list_source_returns_configured_entries_verbatim() {
        let entries = vec![
            CandidateMember {
                name: "avatar".to_string(),
                did: "did:key:human".to_string(),
                slim_endpoint: None,
            },
            CandidateMember {
                name: "claude-code".to_string(),
                did: "did:key:agent".to_string(),
                slim_endpoint: Some("127.0.0.1:47560".to_string()),
            },
        ];
        let source = ExplicitListSource { entries: entries.clone() };
        assert_eq!(source.resolve().expect("resolve"), entries);
    }

    // ── dirctl-backed sources against a fake dirctl script ────────────────────
    //
    // These tests mutate the process-global SHADI_DIRCTL_BINARY env var, so
    // they share a crate-wide lock with dir_registry's own dirctl-faking tests
    // rather than a module-local one — two different locks guarding the same
    // global would race under parallel test execution.

    use crate::dir_registry::dirctl_env_lock as env_lock;

    /// A fake `dirctl` that responds to `search ... --output jsonl` with one
    /// CID and to `pull <cid> ... --output json` with a full a2a-module record,
    /// so `SkillSearchSource`/`DidLookupSource` can be exercised end to end
    /// without a real Directory server.
    #[cfg(unix)]
    fn fake_dirctl_script(cid: &str, record_json: &str) -> (std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fake_dirctl.sh");
        let script = format!(
            r#"#!/bin/sh
case "$1" in
  search) echo '"{cid}"' ;;
  pull) echo '{record_json}' ;;
  *) exit 1 ;;
esac
"#
        );
        std::fs::write(&path, script).expect("write script");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        (path, dir)
    }

    #[test]
    #[cfg(unix)]
    fn skill_search_source_resolves_candidate_via_search_then_pull() {
        let _guard = env_lock().lock().expect("lock");
        let record = a2a_record("copilot", "did:key:z6Mk...", "127.0.0.1:47357");
        let (script, _dir) = fake_dirctl_script("bafkreitest", &record.to_string());
        std::env::set_var("SHADI_DIRCTL_BINARY", &script);

        let source = SkillSearchSource {
            skill: "code_generation/implementation".to_string(),
            dir: DirLookupOptions {
                server_addr: "localhost:9999".to_string(),
                gh_token: None,
                limit: 10,
            },
        };
        let candidates = source.resolve().expect("resolve");

        std::env::remove_var("SHADI_DIRCTL_BINARY");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "copilot");
        assert_eq!(candidates[0].did, "did:key:z6Mk...");
    }

    #[test]
    #[cfg(unix)]
    fn did_lookup_source_resolves_candidate_via_author_search() {
        let _guard = env_lock().lock().expect("lock");
        let record = a2a_record("claude-code", "did:key:z6Mkagent", "127.0.0.1:47560");
        let (script, _dir) = fake_dirctl_script("bafkreiagent", &record.to_string());
        std::env::set_var("SHADI_DIRCTL_BINARY", &script);

        let source = DidLookupSource {
            did: "did:key:z6Mkagent".to_string(),
            dir: DirLookupOptions {
                server_addr: "localhost:9999".to_string(),
                gh_token: None,
                limit: 10,
            },
        };
        let candidates = source.resolve().expect("resolve");

        std::env::remove_var("SHADI_DIRCTL_BINARY");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "claude-code");
        assert_eq!(candidates[0].slim_endpoint.as_deref(), Some("127.0.0.1:47560"));
    }

    #[test]
    fn search_cids_returns_dirctl_not_found_when_missing() {
        let _guard = env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let result = search_cids(
            &["--skill", "x"],
            &DirLookupOptions { server_addr: "localhost:9999".to_string(), gh_token: None, limit: 10 },
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert!(result.is_err());
    }
}
