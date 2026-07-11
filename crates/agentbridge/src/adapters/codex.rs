use shadi_mas::AgentId;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::{
    adapter::{CliAdapter, CliAdapterError},
    context::{ArtifactPayload, ConversationMessage, ContextPacket},
};

/// Adapter for the OpenAI Codex CLI (`codex`).
///
/// Uses `codex exec "<prompt>" --full-auto` for non-interactive use.
/// `--full-auto` skips all approval prompts without the broader sandbox bypass.
///
/// If `--full-auto` is not sufficient, the user can set the env var
/// `CODEX_ARGS=--dangerously-bypass-approvals-and-sandbox` and run the
/// coordinate command directly in the terminal with `!`.
pub struct CodexAdapter {
    id: AgentId,
    work_dir: PathBuf,
    extra_args: Vec<String>,
}

impl CodexAdapter {
    pub fn new(id: impl Into<String>, work_dir: impl Into<PathBuf>) -> Self {
        // Read optional extra args from env so users can add
        // --dangerously-bypass-approvals-and-sandbox themselves.
        let extra_args = std::env::var("CODEX_ARGS")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        Self {
            id: AgentId(id.into()),
            work_dir: work_dir.into(),
            extra_args,
        }
    }

    pub fn for_cwd(id: impl Into<String>) -> Self {
        Self::new(
            id,
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        )
    }

    fn run_exec(&self, prompt: &str) -> Result<String, CliAdapterError> {
        let mut cmd = Command::new("codex");
        cmd.arg("exec")
            .arg(prompt)
            .arg("--full-auto")
            .args(&self.extra_args)
            .current_dir(&self.work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let output = cmd
            .output()
            .map_err(|e| CliAdapterError::Subprocess(format!("failed to run codex: {e}")))?;

        if output.stdout.is_empty() && !output.status.success() {
            return Err(CliAdapterError::Subprocess(format!(
                "codex exec exited with {}",
                output.status
            )));
        }

        // Strip the codex header lines ("Reading additional input...", model info, etc.)
        let raw = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok(strip_codex_header(&raw).trim().to_string())
    }
}

/// Remove the preamble that `codex exec` emits before the actual response:
///   "Reading additional input from stdin..."
///   "OpenAI Codex v0.133.0"
///   "--------"
///   "workdir: ..."
///   "model: ..."
fn strip_codex_header(output: &str) -> &str {
    let separator = "--------";
    // Find the second occurrence of "--------" (end of header block).
    let mut found = 0usize;
    let mut byte_pos = 0usize;
    for line in output.lines() {
        if line.trim() == separator {
            found += 1;
            if found == 1 {
                // Skip past this line.
                byte_pos += line.len() + 1;
                break;
            }
        }
        byte_pos += line.len() + 1;
    }
    if found > 0 && byte_pos <= output.len() {
        &output[byte_pos..]
    } else {
        output
    }
}

impl CliAdapter for CodexAdapter {
    fn agent_id(&self) -> &AgentId {
        &self.id
    }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        let summary = self.run_exec(
            "Summarize this session for handoff: current goal, key decisions, files changed, what remains.",
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
        let mut prompt = format!(
            "Continuing a coding session from {}. Context:\n",
            ctx.source_agent
        );
        for msg in &ctx.conversation {
            prompt.push_str(&format!("[{}]: {}\n", msg.role, msg.content));
        }
        prompt.push_str("Acknowledge you have received the handoff context.");
        self.run_exec(&prompt)?;
        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        self.run_exec(prompt)
    }
}

/// Check whether the `codex` CLI is available in PATH.
pub fn codex_available() -> bool {
    Command::new("codex")
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
        let a = CodexAdapter::new("codex", "/tmp");
        assert_eq!(a.agent_id().0, "codex");
    }

    #[test]
    fn strip_codex_header_removes_preamble() {
        let raw = "Reading additional input from stdin...\nOpenAI Codex v0.133.0\n--------\nworkdir: /tmp\nmodel: gpt-5\n--------\nactual output here";
        // Should return everything after the first "--------" line.
        let stripped = strip_codex_header(raw).trim();
        assert_eq!(stripped, "workdir: /tmp\nmodel: gpt-5\n--------\nactual output here");
    }

    #[test]
    fn strip_codex_header_leaves_clean_output_intact() {
        let raw = "fn fibonacci() {}";
        assert_eq!(strip_codex_header(raw), "fn fibonacci() {}");
    }
}
