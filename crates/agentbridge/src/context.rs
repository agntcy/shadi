use serde::{Deserialize, Serialize};

/// A portable snapshot of a coding-agent session: conversation history,
/// code context, and any generated artifacts. Used for handoff and relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPacket {
    /// Unique packet ID (UUID v4).
    pub id: String,
    /// Human-readable name of the agent that produced this snapshot.
    pub source_agent: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    pub conversation: Vec<ConversationMessage>,
    pub code_context: CodeContext,
    pub artifacts: Vec<ArtifactPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationMessage {
    /// "user", "assistant", or "system".
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeContext {
    pub files: Vec<FileSnapshot>,
    pub git_diff: Option<String>,
    /// Path of the file currently open / in focus.
    pub active_file: Option<String>,
    /// Absolute path of the project root.
    pub project_root: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: String,
    pub content: String,
}

/// A named text artifact (generated code, suggestion, patch, etc.).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPayload {
    pub name: String,
    pub content: String,
    /// MIME type, e.g. "text/x-rust", "text/plain".
    pub media_type: String,
}

impl ContextPacket {
    pub fn new(source_agent: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_agent: source_agent.into(),
            created_at: chrono_now(),
            conversation: Vec::new(),
            code_context: CodeContext::default(),
            artifacts: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

fn chrono_now() -> String {
    // Use std::time to avoid pulling in chrono/time as a required dep.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serialization() {
        let mut pkt = ContextPacket::new("claude-code");
        pkt.conversation.push(ConversationMessage {
            role: "user".to_string(),
            content: "write a parser".to_string(),
        });
        pkt.code_context.files.push(FileSnapshot {
            path: "src/lib.rs".to_string(),
            content: "fn main() {}".to_string(),
        });
        pkt.artifacts.push(ArtifactPayload {
            name: "parser.rs".to_string(),
            content: "fn parse() {}".to_string(),
            media_type: "text/x-rust".to_string(),
        });

        let bytes = pkt.to_bytes().unwrap();
        let restored = ContextPacket::from_bytes(&bytes).unwrap();
        assert_eq!(pkt, restored);
    }
}
