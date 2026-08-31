use serde::Deserialize;
use shadi_mas::AgentId;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::Mutex,
};

use crate::{
    adapter::{CliAdapter, CliAdapterError},
    context::{ArtifactPayload, ConversationMessage, ContextPacket},
    subprocess::TrackedSubprocess,
};

// --- Claude CLI output schema -----------------------------------------------

/// JSON output from `claude --print --output-format json`.
#[derive(Deserialize)]
struct ClaudeJsonOutput {
    #[serde(rename = "result")]
    pub result: Option<String>,
    #[serde(rename = "session_id")]
    pub session_id: Option<String>,
    #[serde(rename = "is_error", default)]
    pub is_error: bool,
}

// --- Adapter -----------------------------------------------------------------

/// State shared across calls.
struct State {
    /// Session ID from the last successful `claude --print` call.
    /// Passed as `--session-id` to maintain conversation continuity.
    session_id: Option<String>,
}

/// Adapter for the Claude Code CLI (`claude`).
///
/// Requires the `claude` binary (Claude Code CLI) to be in PATH.
/// All calls use `--print` mode; interactive sessions are not started.
///
/// Context handoff uses `--system-prompt` to inject a serialized
/// `ContextPacket` as a structured preamble to the new session.
pub struct ClaudeCodeAdapter {
    id: AgentId,
    work_dir: PathBuf,
    state: Mutex<State>,
    subprocess: TrackedSubprocess,
}

impl ClaudeCodeAdapter {
    /// Create an adapter. `work_dir` is passed as `--add-dir` so Claude Code
    /// has tool access to that directory tree.
    pub fn new(id: impl Into<String>, work_dir: impl Into<PathBuf>) -> Self {
        Self {
            id: AgentId(id.into()),
            work_dir: work_dir.into(),
            state: Mutex::new(State { session_id: None }),
            subprocess: TrackedSubprocess::new(),
        }
    }

    /// Create an adapter for the current working directory.
    pub fn for_cwd(id: impl Into<String>) -> Self {
        Self::new(id, std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    fn run_print(
        &self,
        prompt: &str,
        system_prompt: Option<&str>,
        session_id: Option<&str>,
        add_work_dir: bool,
    ) -> Result<ClaudeJsonOutput, CliAdapterError> {
        let mut cmd = Command::new("claude");
        cmd.arg("--print")
            .arg("--output-format")
            .arg("json")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        // Only add the project directory for snapshot/inject where filesystem
        // context is needed. For plain execute_prompt calls (coordinate loop),
        // skipping --add-dir avoids the expensive project-scan startup.
        if add_work_dir {
            cmd.arg("--add-dir").arg(&self.work_dir);
        }

        // If the combined prompt is large, move the bulk into --system-prompt
        // and keep the user-facing arg short. This avoids CLI-arg length issues
        // with claude's argument parser and reduces model confusion.
        const MAX_INLINE_BYTES: usize = 512;
        let (effective_system, effective_prompt) = if prompt.len() > MAX_INLINE_BYTES
            && system_prompt.is_none()
        {
            // Split at the last blank line within the first 512 bytes.
            let split_at = prompt[..MAX_INLINE_BYTES]
                .rfind("\n\n")
                .unwrap_or(MAX_INLINE_BYTES);
            let context_part = &prompt[..split_at];
            let question_part = prompt[split_at..].trim();
            (Some(context_part.to_string()), question_part.to_string())
        } else {
            (system_prompt.map(str::to_string), prompt.to_string())
        };

        if let Some(sp) = &effective_system {
            cmd.arg("--system-prompt").arg(sp);
        }
        if let Some(sid) = session_id {
            cmd.arg("--session-id").arg(sid);
        }
        cmd.arg(&effective_prompt);

        let output = self
            .subprocess
            .output(&mut cmd)
            .map_err(|e| CliAdapterError::Subprocess(format!("failed to run claude: {e}")))?;

        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CliAdapterError::Subprocess(format!(
                "claude exited with {}: {stderr}",
                output.status
            )));
        }

        let parsed: ClaudeJsonOutput = serde_json::from_slice(&output.stdout)
            .map_err(|e| CliAdapterError::Protocol(format!("unexpected claude output: {e}")))?;

        if parsed.is_error {
            return Err(CliAdapterError::Subprocess(
                parsed
                    .result
                    .unwrap_or_else(|| "claude reported an error".to_string()),
            ));
        }

        Ok(parsed)
    }
}

impl CliAdapter for ClaudeCodeAdapter {
    fn agent_id(&self) -> &AgentId {
        &self.id
    }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        let session_id = self
            .state
            .lock()
            .map_err(|_| CliAdapterError::Subprocess("lock poisoned".to_string()))?
            .session_id
            .clone();

        let out = self.run_print(
            "Summarize this session for handoff. Include: \
             (1) the current goal, \
             (2) key decisions made, \
             (3) files created or modified with their content, \
             (4) what remains to be done. \
             Be concise but complete.",
            None,
            session_id.as_deref(),
            true, // filesystem context needed for accurate snapshot
        )?;

        let summary = out.result.unwrap_or_default();
        let new_session_id = out.session_id.clone();

        // Store updated session ID.
        if let Ok(mut state) = self.state.lock() {
            if new_session_id.is_some() {
                state.session_id = new_session_id;
            }
        }

        let mut pkt = ContextPacket::new(self.id.0.clone());
        pkt.conversation.push(ConversationMessage {
            role: "assistant".to_string(),
            content: summary.clone(),
        });
        pkt.code_context.project_root = Some(self.work_dir.to_string_lossy().into_owned());
        pkt.artifacts.push(ArtifactPayload {
            name: "session_summary.md".to_string(),
            content: summary,
            media_type: "text/markdown".to_string(),
        });

        Ok(pkt)
    }

    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError> {
        // Build a structured system prompt from the ContextPacket.
        let mut system = format!(
            "You are continuing a coding session originally started in {}.\n\n",
            ctx.source_agent
        );

        if !ctx.conversation.is_empty() {
            system.push_str("## Prior conversation\n");
            for msg in &ctx.conversation {
                system.push_str(&format!("[{}]: {}\n\n", msg.role, msg.content));
            }
        }

        if !ctx.code_context.files.is_empty() {
            system.push_str("## Files from prior session\n");
            for f in &ctx.code_context.files {
                system.push_str(&format!("### {}\n```\n{}\n```\n\n", f.path, f.content));
            }
        }

        if let Some(diff) = &ctx.code_context.git_diff {
            system.push_str(&format!("## Git diff\n```diff\n{diff}\n```\n\n"));
        }

        if !ctx.artifacts.is_empty() {
            system.push_str("## Generated artifacts\n");
            for art in &ctx.artifacts {
                system.push_str(&format!("### {}\n```\n{}\n```\n\n", art.name, art.content));
            }
        }

        let out = self.run_print(
            "Acknowledge you have received the handoff context and are ready to continue.",
            Some(&system),
            None,  // new session
            false, // context comes from the system prompt, not filesystem scan
        )?;

        if let Ok(mut state) = self.state.lock() {
            state.session_id = out.session_id;
        }

        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        let session_id = self
            .state
            .lock()
            .map_err(|_| CliAdapterError::Subprocess("lock poisoned".to_string()))?
            .session_id
            .clone();

        let out = self.run_print(prompt, None, session_id.as_deref(), false)?;

        if let Ok(mut state) = self.state.lock() {
            if out.session_id.is_some() {
                state.session_id = out.session_id.clone();
            }
        }

        Ok(out.result.unwrap_or_default())
    }

    fn kill_in_flight(&self) {
        self.subprocess.kill();
    }
}

// --- Helpers -----------------------------------------------------------------

/// Check whether the `claude` CLI binary is available in PATH.
pub fn claude_available() -> bool {
    Command::new("claude")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_constructs_with_id_and_dir() {
        let adapter = ClaudeCodeAdapter::new("claude-code", "/tmp");
        assert_eq!(adapter.agent_id().0, "claude-code");
    }

    #[test]
    fn for_cwd_uses_current_directory() {
        let adapter = ClaudeCodeAdapter::for_cwd("claude");
        assert_eq!(adapter.agent_id().0, "claude");
    }

    #[test]
    fn claude_json_output_parses_success() {
        let json = r#"{"result":"fn parse() {}","session_id":"abc123","is_error":false}"#;
        let out: ClaudeJsonOutput = serde_json::from_str(json).unwrap();
        assert_eq!(out.result.as_deref(), Some("fn parse() {}"));
        assert_eq!(out.session_id.as_deref(), Some("abc123"));
        assert!(!out.is_error);
    }

    #[test]
    fn claude_json_output_parses_error() {
        let json = r#"{"result":"rate limit exceeded","is_error":true}"#;
        let out: ClaudeJsonOutput = serde_json::from_str(json).unwrap();
        assert!(out.is_error);
        assert!(out.session_id.is_none());
    }

    #[test]
    fn execute_prompt_fails_gracefully_when_claude_not_available() {
        // If claude is not in PATH this returns a Subprocess error, not a panic.
        if claude_available() {
            return; // skip — would make a real API call
        }
        let adapter = ClaudeCodeAdapter::for_cwd("test");
        let result = adapter.execute_prompt("hello");
        assert!(result.is_err());
        assert!(matches!(result, Err(CliAdapterError::Subprocess(_))));
    }
}
