use std::process::{Command, Stdio};

// --- DIR publish / search via dirctl ----------------------------------------

/// Wrap an A2A `AgentCard` (as JSON) into the OASF record shape DIR expects:
/// a top-level `authors` list carrying the agent's DID, and a well-known
/// `integration/a2a` module carrying the card itself, so `dirctl export
/// --format=a2a` round-trips it and `dirctl search --author <did>` can find
/// it.
pub fn wrap_agent_card(card_json: &serde_json::Value, did: Option<&str>) -> serde_json::Value {
    let authors: Vec<&str> = did.into_iter().collect();
    serde_json::json!({
        "authors": authors,
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
    SearchFailed(String),
    Serialize(String),
}

impl std::fmt::Display for DirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirctlNotFound => write!(f, "dirctl not found in PATH. {DIRCTL_HINT}"),
            Self::PublishFailed(e) => write!(f, "dirctl publish failed: {e}"),
            Self::SearchFailed(e) => write!(f, "dirctl search failed: {e}"),
            Self::Serialize(e) => write!(f, "OASF serialization failed: {e}"),
        }
    }
}

/// Publish an OASF record (e.g. built via [`wrap_agent_card`]) to the agntcy
/// Agent Directory.
///
/// Writes the record to a temp file then calls `dirctl push --file <path>
/// --server-addr <addr>`. The CID printed by dirctl is returned on success.
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
        .arg("--file")
        .arg(&tmp)
        .arg("--server-addr")
        .arg(server_addr)
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

/// Search the Agent Directory for agentbridge adapters by skill.
///
/// Returns raw JSON output from `dirctl search` on success.
pub fn search_adapters(
    skill: &str,
    server_addr: &str,
    limit: usize,
    github_token: Option<&str>,
) -> Result<String, DirError> {
    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("search")
        .arg("--skill")
        .arg(skill)
        .arg("--limit")
        .arg(limit.to_string())
        .arg("--server-addr")
        .arg(server_addr)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(token) = github_token {
        cmd.env("DIRECTORY_CLIENT_AUTH_MODE", "github")
           .env("DIRECTORY_CLIENT_GITHUB_TOKEN", token);
    }

    let output = match cmd.output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DirError::DirctlNotFound);
        }
        Err(e) => return Err(DirError::SearchFailed(e.to_string())),
        Ok(o) => o,
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(DirError::SearchFailed(stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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

    #[test]
    fn wrap_agent_card_embeds_card_in_a2a_module_with_did_author() {
        let card = serde_json::json!({"name": "claude-code"});
        let record = wrap_agent_card(&card, Some("did:key:z6Mk..."));
        assert_eq!(record["authors"], serde_json::json!(["did:key:z6Mk..."]));
        assert_eq!(record["modules"][0]["name"], "integration/a2a");
        assert_eq!(record["modules"][0]["data"]["card_schema_version"], "v1.0.0");
        assert_eq!(record["modules"][0]["data"]["card_data"], card);
    }

    #[test]
    fn wrap_agent_card_omits_authors_entry_without_a_did() {
        let card = serde_json::json!({"name": "claude-code"});
        let record = wrap_agent_card(&card, None);
        assert_eq!(record["authors"], serde_json::json!([]));
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

    #[test]
    fn search_adapters_returns_dirctl_not_found_when_missing() {
        let _g = env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/dirctl");
        let result = search_adapters("code_generation", "localhost:9999", 10, None);
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert!(matches!(result, Err(DirError::DirctlNotFound)));
    }
}
