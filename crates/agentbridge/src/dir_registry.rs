use std::process::{Command, Stdio};

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// --- DIR publish / search via dirctl ----------------------------------------

/// Wrap an A2A `AgentCard` (as JSON) into the OASF record shape DIR expects.
///
/// An OASF record requires `schema_version`, `name`, `version`, `description`,
/// `authors`, `created_at`, and `skills` at its *top level* — the AgentCard
/// itself doesn't carry a DID or live at the record's top level, so this
/// hoists `name`/`version`/`description`/`skills` out of the card, adds the
/// agent's DID as the `authors` entry (no other AgentCard field carries a
/// DID) and a fresh `created_at`, and carries the full card verbatim in a
/// well-known `integration/a2a` module so `dirctl export --format=a2a` and
/// `dirctl search --author <did>` both work against it.
pub fn wrap_agent_card(card_json: &Value, did: Option<&str>) -> Value {
    let authors: Vec<&str> = did.into_iter().collect();
    let name = card_json.get("name").and_then(Value::as_str).unwrap_or("agent");
    let description = card_json.get("description").and_then(Value::as_str).unwrap_or("");
    let version = card_json.get("version").and_then(Value::as_str).unwrap_or("0.0.0");
    let skills: Vec<Value> = card_json
        .get("skills")
        .and_then(Value::as_array)
        .map(|skills| {
            skills
                .iter()
                .filter_map(|s| s.get("id").and_then(Value::as_str))
                .map(|id| serde_json::json!({"name": id}))
                .collect()
        })
        .unwrap_or_default();
    let created_at = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();

    serde_json::json!({
        "name": name,
        "schema_version": "1.0.0",
        "version": version,
        "description": description,
        "authors": authors,
        "created_at": created_at,
        "skills": skills,
        "modules": [{
            "name": "integration/a2a",
            "data": {
                "card_data": card_json,
                "card_schema_version": "v1.0.0",
            }
        }]
    })
}

const DIRCTL_HINT: &str =
    "Install dirctl:  brew tap agntcy/dir https://github.com/agntcy/dir/ && brew install dirctl";

/// Error type for DIR registry operations.
#[derive(Debug)]
pub enum DirError {
    DirctlNotFound,
    PublishFailed(String),
    Serialize(String),
}

impl std::fmt::Display for DirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirctlNotFound => write!(f, "dirctl not found in PATH. {DIRCTL_HINT}"),
            Self::PublishFailed(e) => write!(f, "dirctl publish failed: {e}"),
            Self::Serialize(e) => write!(f, "OASF serialization failed: {e}"),
        }
    }
}

/// Publish an OASF record (e.g. built via [`wrap_agent_card`]) to the agntcy
/// Agent Directory.
///
/// Writes the record to a temp file then calls `dirctl push <path>
/// --server-addr <addr> --output raw`. The CID printed by dirctl is returned
/// on success. `dirctl push` takes the record file as a positional argument
/// (there is no `--file` flag).
pub fn publish_record(
    record: &serde_json::Value,
    server_addr: &str,
    github_token: Option<&str>,
) -> Result<String, DirError> {
    let json = serde_json::to_vec_pretty(record).map_err(|e| DirError::Serialize(e.to_string()))?;

    // Write to a temp file — dirctl expects a file path.
    let tmp = tempfile_path();
    std::fs::write(&tmp, &json)
        .map_err(|e| DirError::PublishFailed(format!("write temp file: {e}")))?;

    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("push")
        .arg(&tmp)
        .arg("--server-addr")
        .arg(server_addr)
        .arg("--output")
        .arg("raw")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(token) = github_token {
        cmd.env("DIRECTORY_CLIENT_AUTH_MODE", "github")
           .env("DIRECTORY_CLIENT_GITHUB_TOKEN", token);
    }

    let output = match cmd.output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_file(&tmp);
            return Err(DirError::DirctlNotFound);
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(DirError::PublishFailed(e.to_string()));
        }
        Ok(o) => o,
    };
    let _ = std::fs::remove_file(&tmp);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(DirError::PublishFailed(stderr));
    }

    let cid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(cid)
}

// --- Helpers -----------------------------------------------------------------

pub(crate) fn dirctl_binary() -> String {
    std::env::var("SHADI_DIRCTL_BINARY").unwrap_or_else(|_| "dirctl".to_string())
}

/// Crate-wide lock serializing `SHADI_DIRCTL_BINARY` mutation across every
/// test module in this crate — `std::env::set_var` is process-global, so
/// tests in `dir_registry` and `member_source` that fake out `dirctl` must
/// not run concurrently with each other.
#[cfg(test)]
pub(crate) fn dirctl_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn tempfile_path() -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("agentbridge-oasf-{ts}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::dirctl_env_lock as env_lock;

    fn sample_card() -> serde_json::Value {
        serde_json::json!({
            "name": "claude-code",
            "description": "agentbridge adapter for 'claude-code'.",
            "version": "0.1.0",
            "skills": [
                {"id": "agent_orchestration/task_decomposition", "name": "agent_orchestration/task_decomposition"},
                {"id": "agent_orchestration/agent_coordination", "name": "agent_orchestration/agent_coordination"},
            ],
        })
    }

    #[test]
    fn wrap_agent_card_embeds_card_in_a2a_module_with_did_author() {
        let card = sample_card();
        let record = wrap_agent_card(&card, Some("did:key:z6Mk..."));
        assert_eq!(record["authors"], serde_json::json!(["did:key:z6Mk..."]));
        assert_eq!(record["modules"][0]["name"], "integration/a2a");
        assert_eq!(record["modules"][0]["data"]["card_schema_version"], "v1.0.0");
        assert_eq!(record["modules"][0]["data"]["card_data"], card);
    }

    #[test]
    fn wrap_agent_card_omits_authors_entry_without_a_did() {
        let card = sample_card();
        let record = wrap_agent_card(&card, None);
        assert_eq!(record["authors"], serde_json::json!([]));
    }

    #[test]
    fn wrap_agent_card_hoists_required_oasf_top_level_fields() {
        let card = sample_card();
        let record = wrap_agent_card(&card, Some("did:key:z6Mk..."));
        assert_eq!(record["name"], "claude-code");
        assert_eq!(record["schema_version"], "1.0.0");
        assert_eq!(record["version"], "0.1.0");
        assert_eq!(record["description"], "agentbridge adapter for 'claude-code'.");
        assert!(record["created_at"].as_str().unwrap().contains('T'));
        assert_eq!(
            record["skills"],
            serde_json::json!([
                {"name": "agent_orchestration/task_decomposition"},
                {"name": "agent_orchestration/agent_coordination"},
            ])
        );
    }

    #[test]
    fn wrap_agent_card_falls_back_on_missing_card_fields() {
        let record = wrap_agent_card(&serde_json::json!({}), None);
        assert_eq!(record["name"], "agent");
        assert_eq!(record["version"], "0.0.0");
        assert_eq!(record["description"], "");
        assert_eq!(record["skills"], serde_json::json!([]));
    }

    #[test]
    fn publish_record_returns_dirctl_not_found_when_missing() {
        let _g = env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/dirctl");
        let record = wrap_agent_card(&serde_json::json!({"name": "test"}), None);
        let result = publish_record(&record, "localhost:9999", None);
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert!(matches!(result, Err(DirError::DirctlNotFound)));
    }
}
