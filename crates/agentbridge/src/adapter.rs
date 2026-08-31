use shadi_mas::{
    AgentId, Epoch, ToolAdapter, ToolCall, ToolProvider, ToolResult,
};
use std::sync::Arc;
use thiserror::Error;

use crate::context::ContextPacket;

#[derive(Debug, Error)]
pub enum CliAdapterError {
    #[error("subprocess error: {0}")]
    Subprocess(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Abstracts a single coding CLI tool (Claude Code, Copilot, Codex, etc.)
/// as a first-class agentbridge participant.
///
/// Implementations are responsible for spawning and communicating with the
/// underlying CLI process. The blanket [`CliToolAdapter`] wrapper bridges
/// any `CliAdapter` into the `shadi_mas::ToolAdapter` trait so it can
/// participate in `MasRuntime<DevelopmentEngine>` coordination rounds.
pub trait CliAdapter: Send + Sync {
    /// Stable identifier for this adapter, e.g. `"claude-code"`.
    fn agent_id(&self) -> &AgentId;

    /// Capture the current session state from the CLI tool.
    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError>;

    /// Inject a context snapshot into the CLI tool, starting or continuing
    /// a session with the given history and code state.
    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError>;

    /// Send a free-form prompt to the CLI tool and return its text response.
    /// Used by `CliToolAdapter` to drive the development coordination loop.
    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError>;

    /// Best-effort: terminate whatever child process this adapter's most
    /// recent `execute_prompt` call spawned, if it's still running. Called
    /// during listener shutdown so an in-flight message doesn't leave an
    /// orphaned process behind after the listener itself has exited.
    /// Default no-op — adapters that don't track a live child don't need
    /// to implement this.
    fn kill_in_flight(&self) {}
}

/// Wraps any [`CliAdapter`] as a `shadi_mas::ToolAdapter` so it can be
/// plugged directly into `MasRuntime<DevelopmentEngine>`.
///
/// Tool call semantics:
/// - `tool_name` is ignored; `arguments` is decoded as a UTF-8 prompt.
/// - The CLI's text response is returned as `payload` bytes.
pub struct CliToolAdapter<A: CliAdapter> {
    inner: Arc<A>,
}

impl<A: CliAdapter> CliToolAdapter<A> {
    pub fn new(adapter: Arc<A>) -> Self {
        Self { inner: adapter }
    }
}

impl<A: CliAdapter> ToolAdapter for CliToolAdapter<A> {
    fn provider(&self) -> ToolProvider {
        ToolProvider::AgentSkills
    }

    fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
        let prompt =
            String::from_utf8(request.arguments).map_err(|e| e.to_string())?;

        let response = self
            .inner
            .execute_prompt(&prompt)
            .map_err(|e| e.to_string())?;

        Ok(ToolResult {
            provider: ToolProvider::AgentSkills,
            tool_name: request.tool_name,
            payload: response.into_bytes(),
            target: request.target,
            correlation_id: request.correlation_id,
            epoch: request.epoch,
        })
    }
}

/// Helper: build a `ToolCall` carrying a text prompt for a given epoch.
pub fn prompt_tool_call(prompt: impl Into<String>, epoch: Epoch) -> ToolCall {
    ToolCall {
        provider: ToolProvider::AgentSkills,
        tool_name: "execute_prompt".to_string(),
        arguments: prompt.into().into_bytes(),
        target: None,
        correlation_id: None,
        epoch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ContextPacket;
    use std::sync::Arc;

    // --- Mock adapter -------------------------------------------------------

    struct MockAdapter {
        id: AgentId,
        response: String,
    }

    impl CliAdapter for MockAdapter {
        fn agent_id(&self) -> &AgentId {
            &self.id
        }
        fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
            Ok(ContextPacket::new(self.id.0.clone()))
        }
        fn inject_context(&self, _: &ContextPacket) -> Result<(), CliAdapterError> {
            Ok(())
        }
        fn execute_prompt(&self, _: &str) -> Result<String, CliAdapterError> {
            Ok(self.response.clone())
        }
    }

    struct FailingAdapter {
        id: AgentId,
    }

    impl CliAdapter for FailingAdapter {
        fn agent_id(&self) -> &AgentId {
            &self.id
        }
        fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
            Err(CliAdapterError::Subprocess("fail".to_string()))
        }
        fn inject_context(&self, _: &ContextPacket) -> Result<(), CliAdapterError> {
            Err(CliAdapterError::Subprocess("fail".to_string()))
        }
        fn execute_prompt(&self, _: &str) -> Result<String, CliAdapterError> {
            Err(CliAdapterError::Subprocess("fail".to_string()))
        }
    }

    fn make_call(args: Vec<u8>) -> ToolCall {
        ToolCall {
            provider: ToolProvider::AgentSkills,
            tool_name: "test_tool".to_string(),
            arguments: args,
            target: None,
            correlation_id: None,
            epoch: Epoch(0),
        }
    }

    // --- Tests --------------------------------------------------------------

    #[test]
    fn mock_adapter_all_methods_callable() {
        let adapter = MockAdapter {
            id: AgentId("test-id".to_string()),
            response: "hello".to_string(),
        };
        assert_eq!(adapter.agent_id().0, "test-id");
        let ctx = adapter.snapshot_context().unwrap();
        assert_eq!(ctx.source_agent, "test-id");
        assert!(adapter.inject_context(&ctx).is_ok());
    }

    #[test]
    fn failing_adapter_all_methods_return_error() {
        let adapter = FailingAdapter {
            id: AgentId("fail-id".to_string()),
        };
        assert_eq!(adapter.agent_id().0, "fail-id");
        assert!(adapter.snapshot_context().is_err());
        let ctx = ContextPacket::new("src");
        assert!(adapter.inject_context(&ctx).is_err());
    }

    #[test]
    fn new_wraps_adapter_and_provider_is_agent_skills() {
        let inner = Arc::new(MockAdapter {
            id: AgentId("mock".to_string()),
            response: String::new(),
        });
        let ta = CliToolAdapter::new(Arc::clone(&inner));
        assert_eq!(ta.provider(), ToolProvider::AgentSkills);
    }

    #[test]
    fn call_success_returns_response_as_payload() {
        let inner = Arc::new(MockAdapter {
            id: AgentId("mock".to_string()),
            response: "fn answer() {}".to_string(),
        });
        let ta = CliToolAdapter::new(inner);
        let result = ta.call(make_call(b"write a function".to_vec()));
        assert!(result.is_ok());
        let tr = result.unwrap();
        assert_eq!(tr.payload, b"fn answer() {}");
        assert_eq!(tr.provider, ToolProvider::AgentSkills);
        assert_eq!(tr.tool_name, "test_tool");
        assert_eq!(tr.epoch, Epoch(0));
        assert!(tr.target.is_none());
        assert!(tr.correlation_id.is_none());
    }

    #[test]
    fn call_with_invalid_utf8_returns_error() {
        let inner = Arc::new(MockAdapter {
            id: AgentId("mock".to_string()),
            response: String::new(),
        });
        let ta = CliToolAdapter::new(inner);
        let result = ta.call(make_call(vec![0xFF, 0xFE])); // invalid UTF-8
        assert!(result.is_err());
    }

    #[test]
    fn call_propagates_adapter_error() {
        let inner = Arc::new(FailingAdapter {
            id: AgentId("fail".to_string()),
        });
        let ta = CliToolAdapter::new(inner);
        let result = ta.call(make_call(b"any prompt".to_vec()));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("fail"));
    }

    #[test]
    fn prompt_tool_call_sets_all_fields_correctly() {
        let call = prompt_tool_call("implement a parser", Epoch(7));
        assert_eq!(call.provider, ToolProvider::AgentSkills);
        assert_eq!(call.tool_name, "execute_prompt");
        assert_eq!(call.arguments, b"implement a parser");
        assert_eq!(call.epoch, Epoch(7));
        assert!(call.target.is_none());
        assert!(call.correlation_id.is_none());
    }
}
