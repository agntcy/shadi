use serde::{Deserialize, Serialize};

use crate::types::{Epoch, PatternKind};

/// Provider-specific tool or skill invocation surface used by the MAS runtime.
///
/// `AgentSkills` refers to skills defined and packaged through the AgentSkills
/// framework, not to a remote transport layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolProvider {
    Mcp,
    AgentSkills,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub task_id: String,
    pub pattern: PatternKind,
    pub epoch: Epoch,
    pub correlation_id: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub provider: ToolProvider,
    pub tool_name: String,
    pub arguments: Vec<u8>,
    /// Optional provider-specific selector such as an MCP server binding or an
    /// AgentSkills skill identifier.
    pub target: Option<String>,
    pub correlation_id: Option<String>,
    pub epoch: Epoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    pub provider: ToolProvider,
    pub tool_name: String,
    pub payload: Vec<u8>,
    /// Mirrors the provider-specific selector used for the call, when one was
    /// required.
    pub target: Option<String>,
    pub correlation_id: Option<String>,
    pub epoch: Epoch,
}

pub trait MessagingAdapter: Send + Sync {
    fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), String>;
}

pub trait TaskAdapter: Send + Sync {
    fn dispatch(&self, task: TaskEnvelope) -> Result<(), String>;
}

pub trait ToolAdapter: Send + Sync {
    fn provider(&self) -> ToolProvider;
    fn call(&self, request: ToolCall) -> Result<ToolResult, String>;
}
