use shadi_mas::AgentId;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::{
    adapter::{CliAdapter, CliAdapterError},
    context::{ArtifactPayload, ConversationMessage, ContextPacket},
    subprocess::TrackedSubprocess,
};

/// Adapter for the Cursor Agent CLI (`cursor-agent`).
///
/// Uses `cursor-agent --print --output-format text "prompt"` for non-interactive
/// prompting. Session continuity is available via `--session-id` (same UUID format
/// as Claude Code).
pub struct CursorAgentAdapter {
    id: AgentId,
    work_dir: PathBuf,
    session_id: std::sync::Mutex<Option<String>>,
    subprocess: TrackedSubprocess,
}

impl CursorAgentAdapter {
    pub fn new(id: impl Into<String>, work_dir: impl Into<PathBuf>) -> Self {
        Self {
            id: AgentId(id.into()),
            work_dir: work_dir.into(),
            session_id: std::sync::Mutex::new(None),
            subprocess: TrackedSubprocess::new(),
        }
    }

    pub fn for_cwd(id: impl Into<String>) -> Self {
        Self::new(
            id,
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        )
    }

    fn run_print(&self, prompt: &str, system_prompt: Option<&str>) -> Result<String, CliAdapterError> {
        let mut cmd = Command::new("cursor-agent");
        cmd.arg("--print")
            .arg("--output-format")
            .arg("text")
            .current_dir(&self.work_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        if let Some(sp) = system_prompt {
            cmd.arg("--system-prompt").arg(sp);
        }

        if let Ok(guard) = self.session_id.lock() {
            if let Some(sid) = guard.as_deref() {
                cmd.arg("--session-id").arg(sid);
            }
        }

        cmd.arg(prompt);

        let output = self
            .subprocess
            .output(&mut cmd)
            .map_err(|e| CliAdapterError::Subprocess(format!("failed to run cursor-agent: {e}")))?;

        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CliAdapterError::Subprocess(format!(
                "cursor-agent exited with {}: {stderr}",
                output.status
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

impl CliAdapter for CursorAgentAdapter {
    fn agent_id(&self) -> &AgentId {
        &self.id
    }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        let summary = self.run_print(
            "Summarize this session for handoff: current goal, key decisions, files changed, what remains.",
            None,
        )?;

        let mut pkt = ContextPacket::new(self.id.0.clone());
        pkt.conversation.push(ConversationMessage {
            role: "assistant".to_string(),
            content: summary.clone(),
        });
        pkt.artifacts.push(ArtifactPayload {
            name: "session_summary.md".to_string(),
            content: summary,
            media_type: "text/markdown".to_string(),
        });
        Ok(pkt)
    }

    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError> {
        let mut system = format!(
            "You are continuing a coding session from {}.\n\n",
            ctx.source_agent
        );
        for msg in &ctx.conversation {
            system.push_str(&format!("[{}]: {}\n", msg.role, msg.content));
        }
        for art in &ctx.artifacts {
            system.push_str(&format!("\n## {}\n{}\n", art.name, art.content));
        }
        self.run_print(
            "Acknowledge you have received the handoff context.",
            Some(&system),
        )?;
        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        self.run_print(prompt, None)
    }

    fn kill_in_flight(&self) {
        self.subprocess.kill();
    }
}

/// Check whether the `cursor-agent` binary is available in PATH.
pub fn cursor_agent_available() -> bool {
    Command::new("cursor-agent")
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
    fn adapter_constructs_correctly() {
        let a = CursorAgentAdapter::new("cursor", "/tmp");
        assert_eq!(a.agent_id().0, "cursor");
    }

    #[test]
    fn execute_prompt_fails_gracefully_when_not_available() {
        if cursor_agent_available() {
            return; // skip — would make a real API call
        }
        let a = CursorAgentAdapter::for_cwd("cursor");
        assert!(a.execute_prompt("hello").is_err());
    }
}
