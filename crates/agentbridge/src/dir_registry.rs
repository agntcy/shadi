use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};

use crate::adapter::CliAdapter;

// --- OASF record builder ----------------------------------------------------

/// Minimal OASF record describing a agentbridge adapter as a DIR agent.
/// Published to agntcy/dir via `dirctl push`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterOasfRecord {
    pub name: String,
    pub description: String,
    pub version: String,
    pub schema_version: String,
    pub skills: Vec<OasfSkill>,
    pub locators: Vec<OasfLocator>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OasfSkill {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OasfLocator {
    #[serde(rename = "type")]
    pub locator_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl AdapterOasfRecord {
    /// Build an OASF record for any `CliAdapter`. The record describes the
    /// adapter's identity and advertises the standard agentbridge skills.
    pub fn for_adapter(adapter: &dyn CliAdapter, version: &str) -> Self {
        let id = adapter.agent_id();
        Self {
            name: id.0.clone(),
            description: format!(
                "agentbridge adapter for '{}'. Supports context handoff, \
                 task delegation, and autonomous code coordination.",
                id.0
            ),
            version: version.to_string(),
            schema_version: "1.0.0".to_string(),
            skills: vec![
                OasfSkill { name: "code_generation/implementation".to_string() },
                OasfSkill { name: "agent_orchestration/task_delegation".to_string() },
                OasfSkill { name: "agent_orchestration/context_handoff".to_string() },
            ],
            locators: vec![],
        }
    }

    /// Build an OASF record with a SLIM endpoint locator.
    pub fn with_slim_endpoint(mut self, endpoint: &str, agent_id: &str) -> Self {
        self.locators.push(OasfLocator {
            locator_type: "slim".to_string(),
            url: Some(format!("slim://{endpoint}/agntcy/shadi/{agent_id}-a2a")),
        });
        self
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }
}

// --- DIR publish / search via dirctl ----------------------------------------

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

/// Publish an `AdapterOasfRecord` to the agntcy Agent Directory.
///
/// Writes the record to a temp file then calls `dirctl push --file <path>
/// --server-addr <addr>`. The CID printed by dirctl is returned on success.
pub fn publish_adapter(
    record: &AdapterOasfRecord,
    server_addr: &str,
    github_token: Option<&str>,
) -> Result<String, DirError> {
    let json = record.to_json().map_err(|e| DirError::Serialize(e.to_string()))?;

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

fn dirctl_binary() -> String {
    std::env::var("SHADI_DIRCTL_BINARY").unwrap_or_else(|_| "dirctl".to_string())
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
    use crate::context::ContextPacket;
    use shadi_mas::AgentId;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn env_lock() -> &'static Mutex<()> {
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    struct StubAdapter(AgentId);
    impl crate::adapter::CliAdapter for StubAdapter {
        fn agent_id(&self) -> &AgentId { &self.0 }
        fn snapshot_context(&self) -> Result<ContextPacket, crate::adapter::CliAdapterError> {
            Ok(ContextPacket::new(self.0.0.clone()))
        }
        fn inject_context(&self, _: &ContextPacket) -> Result<(), crate::adapter::CliAdapterError> { Ok(()) }
        fn execute_prompt(&self, _: &str) -> Result<String, crate::adapter::CliAdapterError> { Ok(String::new()) }
    }

    #[test]
    fn oasf_record_for_adapter_has_correct_name_and_skills() {
        let adapter = StubAdapter(AgentId("claude-code".to_string()));
        let record = AdapterOasfRecord::for_adapter(&adapter, "0.1.0");
        assert_eq!(record.name, "claude-code");
        assert_eq!(record.version, "0.1.0");
        assert_eq!(record.skills.len(), 3);
        assert!(record.skills.iter().any(|s| s.name.contains("code_generation")));
        assert!(record.skills.iter().any(|s| s.name.contains("context_handoff")));
    }

    #[test]
    fn with_slim_endpoint_adds_locator() {
        let adapter = StubAdapter(AgentId("copilot".to_string()));
        let record = AdapterOasfRecord::for_adapter(&adapter, "0.1.0")
            .with_slim_endpoint("127.0.0.1:47357", "copilot");
        assert_eq!(record.locators.len(), 1);
        assert_eq!(record.locators[0].locator_type, "slim");
        assert!(record.locators[0].url.as_deref().unwrap().contains("47357"));
    }

    #[test]
    fn oasf_record_serializes_to_valid_json() {
        let adapter = StubAdapter(AgentId("codex".to_string()));
        let record = AdapterOasfRecord::for_adapter(&adapter, "1.0.0");
        let json = record.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed["name"], "codex");
        assert!(parsed["skills"].is_array());
    }

    #[test]
    fn publish_adapter_returns_dirctl_not_found_when_missing() {
        let _g = env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/dirctl");
        let adapter = StubAdapter(AgentId("test".to_string()));
        let record = AdapterOasfRecord::for_adapter(&adapter, "0.1.0");
        let result = publish_adapter(&record, "localhost:9999", None);
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
