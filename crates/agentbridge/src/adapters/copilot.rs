use shadi_mas::AgentId;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::{
    adapter::{CliAdapter, CliAdapterError},
    context::{ArtifactPayload, ConversationMessage, ContextPacket},
};

/// Adapter for the GitHub Copilot CLI (`copilot`).
///
/// Uses `copilot --prompt "..." --allow-all-tools` for non-interactive use.
/// The `--output-format text` flag keeps output clean; the trailing "Changes"
/// stats line is stripped.
pub struct CopilotAdapter {
    id: AgentId,
    work_dir: PathBuf,
}

impl CopilotAdapter {
    pub fn new(id: impl Into<String>, work_dir: impl Into<PathBuf>) -> Self {
        Self {
            id: AgentId(id.into()),
            work_dir: work_dir.into(),
        }
    }

    pub fn for_cwd(id: impl Into<String>) -> Self {
        Self::new(
            id,
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        )
    }

    fn run_prompt(&self, prompt: &str, system_prompt: Option<&str>) -> Result<String, CliAdapterError> {
        let mut cmd = Command::new("copilot");
        cmd.arg("--prompt")
            .arg(prompt)
            .arg("--allow-all-tools")
            .current_dir(&self.work_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        if let Some(sp) = system_prompt {
            cmd.arg("--system-prompt").arg(sp);
        }

        let output = cmd
            .output()
            .map_err(|e| CliAdapterError::Subprocess(format!("failed to run copilot: {e}")))?;

        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CliAdapterError::Subprocess(format!(
                "copilot exited with {}: {stderr}",
                output.status
            )));
        }

        let raw = String::from_utf8_lossy(&output.stdout).into_owned();
        // Strip the trailing "Changes  +N -N" stats line that copilot appends.
        let cleaned = strip_copilot_stats(&raw);
        Ok(cleaned.trim().to_string())
    }
}

/// Remove the trailing stats block that `copilot -p` appends:
///   "\n\nChanges    +0 -0\n"
fn strip_copilot_stats(output: &str) -> &str {
    let lines: Vec<&str> = output.lines().collect();
    // Walk backwards to find where the stats block starts.
    let mut end = lines.len();
    for (i, line) in lines.iter().enumerate().rev() {
        let t = line.trim();
        if t.starts_with("Changes") || t.is_empty() {
            end = i;
        } else {
            break;
        }
    }
    // Reconstruct up to `end`.
    let trimmed = lines[..end].join("\n");
    // Return the original slice up to the same byte offset.
    let byte_end = output
        .char_indices()
        .nth(trimmed.chars().count())
        .map(|(i, _)| i)
        .unwrap_or(output.len());
    &output[..byte_end]
}

impl CliAdapter for CopilotAdapter {
    fn agent_id(&self) -> &AgentId {
        &self.id
    }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        let summary = self.run_prompt(
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
        self.run_prompt(
            "Acknowledge you have received the handoff context.",
            Some(&system),
        )?;
        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        self.run_prompt(prompt, None)
    }
}

/// Check whether the `copilot` binary is available in PATH.
pub fn copilot_available() -> bool {
    Command::new("copilot")
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
        let a = CopilotAdapter::new("copilot", "/tmp");
        assert_eq!(a.agent_id().0, "copilot");
    }

    #[test]
    fn strip_copilot_stats_removes_trailing_changes_line() {
        let output = "fn parse() {}\n\n\nChanges    +1 -0\n";
        assert_eq!(strip_copilot_stats(output).trim(), "fn parse() {}");
    }

    #[test]
    fn strip_copilot_stats_leaves_clean_output_intact() {
        let output = "fn parse() {}";
        assert_eq!(strip_copilot_stats(output), "fn parse() {}");
    }

    #[test]
    fn strip_copilot_stats_handles_empty() {
        assert_eq!(strip_copilot_stats(""), "");
    }

    #[test]
    fn execute_prompt_fails_gracefully_when_not_available() {
        if copilot_available() {
            return;
        }
        let a = CopilotAdapter::for_cwd("copilot");
        assert!(a.execute_prompt("hello").is_err());
    }
}
