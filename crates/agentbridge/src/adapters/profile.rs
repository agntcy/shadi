// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Profile-driven [`CliAdapter`]: argv/env come from JSON, not a new `*.rs`.

use serde::Deserialize;
use shadi_mas::AgentId;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
};

use crate::{
    adapter::{CliAdapter, CliAdapterError},
    context::{ArtifactPayload, ContextPacket, ConversationMessage},
    subprocess::TrackedSubprocess,
};

use super::workdir::pin_tmpdir;

const BUNDLED_CLAUDE: &str = include_str!("../../profiles/claude-code.json");
const BUNDLED_COPILOT: &str = include_str!("../../profiles/copilot.json");
const BUNDLED_CODEX: &str = include_str!("../../profiles/codex.json");
const BUNDLED_CURSOR: &str = include_str!("../../profiles/cursor-agent.json");

/// IDs shipped under `crates/agentbridge/profiles/`.
pub fn bundled_profile_ids() -> &'static [&'static str] {
    &["claude-code", "copilot", "codex", "cursor-agent"]
}

fn bundled_json(id: &str) -> Option<&'static str> {
    match id {
        "claude-code" => Some(BUNDLED_CLAUDE),
        "copilot" => Some(BUNDLED_COPILOT),
        "codex" => Some(BUNDLED_CODEX),
        "cursor-agent" => Some(BUNDLED_CURSOR),
        _ => None,
    }
}

/// Load `{id}.json` from `AGENTBRIDGE_PROFILES_DIR`, then a bundled profile.
pub fn load_profile(id: &str) -> Result<Option<CliProfile>, CliAdapterError> {
    if id == "generic-stdio" {
        return Ok(None);
    }
    if let Ok(dir) = std::env::var("AGENTBRIDGE_PROFILES_DIR") {
        if let Some(profile) = load_profile_file(&Path::new(&dir).join(format!("{id}.json")))? {
            return Ok(Some(profile));
        }
    }
    match bundled_json(id) {
        Some(raw) => Ok(Some(parse_profile(raw)?)),
        None => Ok(None),
    }
}

fn load_profile_file(path: &Path) -> Result<Option<CliProfile>, CliAdapterError> {
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(parse_profile(&std::fs::read_to_string(path)?)?))
}

fn parse_profile(raw: &str) -> Result<CliProfile, CliAdapterError> {
    serde_json::from_str(raw).map_err(CliAdapterError::from)
}

/// `{id}` or `{id}:{workdir}` → [`ProfileAdapter`] when a profile exists.
pub fn open_profile_adapter(
    spec: &str,
) -> Result<Option<(String, ProfileAdapter)>, CliAdapterError> {
    let (id, work_dir) = match spec.split_once(':') {
        Some((id, rest)) if !id.is_empty() && id != "generic-stdio" && id != "slim" => {
            (id, PathBuf::from(rest))
        }
        None if !spec.is_empty() && spec != "generic-stdio" => (
            spec,
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ),
        _ => return Ok(None),
    };
    match load_profile(id)? {
        Some(profile) => {
            let label = profile.id.clone();
            Ok(Some((label, ProfileAdapter::new(profile, work_dir))))
        }
        None => Ok(None),
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct CliProfile {
    pub id: String,
    pub bin: String,
    #[serde(default)]
    pub pin_tmpdir: bool,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub workdir_flags: Vec<String>,
    #[serde(default = "default_true")]
    pub workdir_flags_on_execute: bool,
    #[serde(default = "default_true")]
    pub workdir_flags_on_snapshot: bool,
    #[serde(default = "default_true")]
    pub workdir_flags_on_inject: bool,
    #[serde(default = "default_true")]
    pub current_dir_workdir: bool,
    #[serde(default)]
    pub system_flag: Option<String>,
    /// Claude-only: move a long execute prompt into `--system-prompt`.
    /// Copilot/cursor treat that flag as missing or as a file path.
    #[serde(default)]
    pub split_large_prompt: bool,
    #[serde(default)]
    pub extra_args_env: Option<String>,
    #[serde(default)]
    pub stdin_null: bool,
    pub execute: ExecuteSpec,
    #[serde(default)]
    pub session: Option<SessionSpec>,
    #[serde(default)]
    pub result: ResultSpec,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteSpec {
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionSpec {
    pub json_field: String,
    pub flag: String,
    #[serde(default)]
    pub retry_stderr_contains: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResultSpec {
    pub kind: ResultKind,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub line: Option<String>,
}

impl Default for ResultSpec {
    fn default() -> Self {
        Self {
            kind: ResultKind::Stdout,
            field: None,
            prefix: None,
            line: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultKind {
    #[default]
    Stdout,
    JsonField,
    StripSuffix,
    StripAfterFirstLine,
}

struct State {
    session_id: Option<String>,
}

/// [`CliAdapter`] driven by a [`CliProfile`].
pub struct ProfileAdapter {
    id: AgentId,
    work_dir: PathBuf,
    profile: CliProfile,
    state: Mutex<State>,
    subprocess: TrackedSubprocess,
}

impl ProfileAdapter {
    pub fn new(profile: CliProfile, work_dir: impl Into<PathBuf>) -> Self {
        let work_dir = work_dir.into();
        Self {
            id: AgentId(profile.id.clone()),
            work_dir,
            profile,
            state: Mutex::new(State { session_id: None }),
            subprocess: TrackedSubprocess::new(),
        }
    }

    fn session_id(&self) -> Result<Option<String>, CliAdapterError> {
        self.state
            .lock()
            .map(|s| s.session_id.clone())
            .map_err(|_| CliAdapterError::Subprocess("lock poisoned".to_string()))
    }

    fn store_session(&self, session_id: Option<String>) {
        if let Ok(mut state) = self.state.lock() {
            if session_id.is_some() {
                state.session_id = session_id;
            }
        }
    }

    fn clear_session(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.session_id = None;
        }
    }

    fn run(
        &self,
        prompt: &str,
        system: Option<&str>,
        include_workdir_flags: bool,
        use_session: bool,
    ) -> Result<String, CliAdapterError> {
        let session = if use_session {
            self.session_id()?
        } else {
            None
        };
        let (effective_system, effective_prompt) = split_large_prompt(
            prompt,
            system,
            self.profile.split_large_prompt && self.profile.system_flag.is_some(),
        );
        let argv = render_argv(
            &self.profile,
            &self.work_dir.to_string_lossy(),
            &effective_prompt,
            effective_system.as_deref().or(system),
            session.as_deref(),
            include_workdir_flags,
        );

        let mut cmd = Command::new(&self.profile.bin);
        if self.profile.pin_tmpdir {
            pin_tmpdir(&mut cmd, &self.work_dir);
        }
        let workdir = self.work_dir.to_string_lossy();
        for (key, value) in &self.profile.env {
            cmd.env(key, value.replace("{workdir}", workdir.as_ref()));
        }
        if self.profile.current_dir_workdir {
            cmd.current_dir(&self.work_dir);
        }
        cmd.args(&argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if self.profile.stdin_null {
            cmd.stdin(Stdio::null());
        }

        let output = self.subprocess.output(&mut cmd).map_err(|e| {
            CliAdapterError::Subprocess(format!("failed to run {}: {e}", self.profile.bin))
        })?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if !output.status.success() && stdout.is_empty() {
            return Err(CliAdapterError::Subprocess(format!(
                "{} exited with {}: {stderr}",
                self.profile.bin, output.status
            )));
        }

        if let Some(spec) = &self.profile.session {
            if let Some(needle) = &spec.retry_stderr_contains {
                if session.is_some() && (stderr.contains(needle) || stdout.contains(needle)) {
                    return Err(CliAdapterError::Subprocess(needle.clone()));
                }
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(sid) = value.get(&spec.json_field).and_then(|v| v.as_str()) {
                    self.store_session(Some(sid.to_string()));
                }
            }
        }

        extract_result(&self.profile, &stdout)
    }
}

const MAX_INLINE_BYTES: usize = 512;

fn split_large_prompt(
    prompt: &str,
    system: Option<&str>,
    can_use_system: bool,
) -> (Option<String>, String) {
    if system.is_some() || !can_use_system || prompt.len() <= MAX_INLINE_BYTES {
        return (system.map(str::to_string), prompt.to_string());
    }
    let split_at = prompt[..MAX_INLINE_BYTES]
        .rfind("\n\n")
        .unwrap_or(MAX_INLINE_BYTES);
    let context_part = prompt[..split_at].to_string();
    let question_part = prompt[split_at..].trim().to_string();
    (Some(context_part), question_part)
}

/// Render argv from a profile. `{prompt}` / `{workdir}` / `{system}` /
/// `{session}` / `{workdir_flags}` / `{extra_args}` are expanded.
pub fn render_argv(
    profile: &CliProfile,
    workdir: &str,
    prompt: &str,
    system: Option<&str>,
    session_id: Option<&str>,
    include_workdir_flags: bool,
) -> Vec<String> {
    let extra: Vec<String> = profile
        .extra_args_env
        .as_deref()
        .and_then(|key| std::env::var(key).ok())
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    let mut out = Vec::new();
    for token in &profile.execute.args {
        match token.as_str() {
            "{workdir_flags}" => {
                if include_workdir_flags {
                    for flag in &profile.workdir_flags {
                        out.push(flag.replace("{workdir}", workdir));
                    }
                }
            }
            "{system}" => {
                if let (Some(flag), Some(sp)) = (profile.system_flag.as_deref(), system) {
                    out.push(flag.to_string());
                    out.push(sp.to_string());
                }
            }
            "{session}" => {
                if let (Some(spec), Some(sid)) = (&profile.session, session_id) {
                    out.push(spec.flag.clone());
                    out.push(sid.to_string());
                }
            }
            "{extra_args}" => out.extend(extra.iter().cloned()),
            "{prompt}" => out.push(prompt.to_string()),
            other => out.push(
                other
                    .replace("{workdir}", workdir)
                    .replace("{prompt}", prompt),
            ),
        }
    }
    out
}

fn extract_result(profile: &CliProfile, stdout: &str) -> Result<String, CliAdapterError> {
    match profile.result.kind {
        ResultKind::Stdout => Ok(stdout.trim().to_string()),
        ResultKind::JsonField => {
            let field = profile.result.field.as_deref().ok_or_else(|| {
                CliAdapterError::Protocol("json_field result missing field".into())
            })?;
            let value: serde_json::Value = serde_json::from_str(stdout)
                .map_err(|e| CliAdapterError::Protocol(format!("unexpected json output: {e}")))?;
            if value
                .get("is_error")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                let msg = value
                    .get(field)
                    .and_then(|v| v.as_str())
                    .unwrap_or("cli reported an error")
                    .to_string();
                return Err(CliAdapterError::Subprocess(msg));
            }
            Ok(value
                .get(field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string())
        }
        ResultKind::StripSuffix => {
            let prefix = profile.result.prefix.as_deref().unwrap_or("Changes");
            Ok(strip_trailing_prefix_lines(stdout, prefix))
        }
        ResultKind::StripAfterFirstLine => {
            let line = profile.result.line.as_deref().unwrap_or("--------");
            Ok(strip_after_first_line(stdout, line).trim().to_string())
        }
    }
}

fn strip_trailing_prefix_lines(output: &str, prefix: &str) -> String {
    let mut lines: Vec<&str> = output.lines().collect();
    while let Some(last) = lines.last() {
        let t = last.trim();
        if t.is_empty() || t.starts_with(prefix) {
            lines.pop();
        } else {
            break;
        }
    }
    lines.join("\n")
}

fn strip_after_first_line<'a>(output: &'a str, separator: &str) -> &'a str {
    let mut found = false;
    let mut byte_pos = 0usize;
    for line in output.lines() {
        if line.trim() == separator {
            found = true;
            byte_pos += line.len() + 1;
            break;
        }
        byte_pos += line.len() + 1;
    }
    if found && byte_pos <= output.len() {
        &output[byte_pos..]
    } else {
        output
    }
}

fn snapshot_prompt() -> &'static str {
    "Summarize this session for handoff: current goal, key decisions, files changed, what remains."
}

fn inject_system(ctx: &ContextPacket) -> String {
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
    system
}

impl CliAdapter for ProfileAdapter {
    fn agent_id(&self) -> &AgentId {
        &self.id
    }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        let summary = self.run(
            snapshot_prompt(),
            None,
            self.profile.workdir_flags_on_snapshot,
            true,
        )?;
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
        if self.profile.system_flag.is_some() {
            self.run(
                "Acknowledge you have received the handoff context and are ready to continue.",
                Some(&inject_system(ctx)),
                self.profile.workdir_flags_on_inject,
                false,
            )?;
        } else {
            let mut prompt = inject_system(ctx);
            prompt.push_str("Acknowledge you have received the handoff context.");
            self.run(&prompt, None, self.profile.workdir_flags_on_inject, false)?;
        }
        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        let session = self.session_id()?;
        match self.run(prompt, None, self.profile.workdir_flags_on_execute, true) {
            Err(err)
                if session.is_some()
                    && self
                        .profile
                        .session
                        .as_ref()
                        .and_then(|s| s.retry_stderr_contains.as_deref())
                        .is_some_and(|needle| err.to_string().contains(needle)) =>
            {
                self.clear_session();
                self.run(prompt, None, self.profile.workdir_flags_on_execute, false)
            }
            other => other,
        }
    }

    fn kill_in_flight(&self) {
        self.subprocess.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `load_profile` / `render_argv` read process env. Parallel tests must
    /// not interleave `set_var` with those lookups.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn load_bundled(id: &str) -> CliProfile {
        load_profile(id)
            .expect("profile parse")
            .unwrap_or_else(|| panic!("missing bundled profile {id}"))
    }

    #[test]
    fn bundled_profiles_parse() {
        for id in bundled_profile_ids() {
            let p = load_bundled(id);
            assert_eq!(p.id, *id);
            assert!(!p.bin.is_empty());
            assert!(!p.execute.args.is_empty());
        }
    }

    #[test]
    fn claude_argv_matches_native_order() {
        let p = load_bundled("claude-code");
        let argv = render_argv(
            &p,
            "/var/workspace",
            "hello",
            Some("sys"),
            Some("sid-1"),
            true,
        );
        assert_eq!(
            argv,
            vec![
                "--print",
                "--output-format",
                "json",
                "--add-dir",
                "/var/workspace",
                "--system-prompt",
                "sys",
                "--session-id",
                "sid-1",
                "hello",
            ]
        );
    }

    #[test]
    fn claude_inject_omits_add_dir() {
        let p = load_bundled("claude-code");
        let argv = render_argv(&p, "/var/workspace", "ack", Some("sys"), None, false);
        assert!(!argv.iter().any(|a| a == "--add-dir"));
        assert_eq!(argv.last().map(String::as_str), Some("ack"));
    }

    #[test]
    fn only_claude_splits_large_execute_prompts() {
        assert!(load_bundled("claude-code").split_large_prompt);
        assert!(!load_bundled("copilot").split_large_prompt);
        assert!(!load_bundled("cursor-agent").split_large_prompt);
        let long = "x".repeat(600);
        assert!(split_large_prompt(&long, None, false).0.is_none());
        assert!(split_large_prompt(&long, None, true).0.is_some());
    }

    #[test]
    fn copilot_argv_places_prompt_before_workdir() {
        let p = load_bundled("copilot");
        let argv = render_argv(&p, "/ws", "do it", None, None, true);
        assert_eq!(
            argv,
            vec![
                "--prompt",
                "do it",
                "--allow-all-tools",
                "-C",
                "/ws",
                "--add-dir",
                "/ws",
            ]
        );
    }

    #[test]
    fn codex_argv_includes_exec_flags() {
        let p = load_bundled("codex");
        let argv = render_argv(&p, "/ws", "implement fifo", None, None, true);
        assert_eq!(
            argv,
            vec![
                "exec",
                "implement fifo",
                "--dangerously-bypass-approvals-and-sandbox",
                "--skip-git-repo-check",
                "--ephemeral",
            ]
        );
    }

    #[test]
    fn cursor_argv_sets_workspace_and_trust() {
        let p = load_bundled("cursor-agent");
        let argv = render_argv(&p, "/ws", "hi", None, None, true);
        assert_eq!(
            argv,
            vec![
                "--print",
                "--output-format",
                "text",
                "--workspace",
                "/ws",
                "--trust",
                "--sandbox",
                "disabled",
                "hi",
            ]
        );
    }

    #[test]
    fn extract_json_field_and_error() {
        let p = load_bundled("claude-code");
        let ok = extract_result(
            &p,
            r#"{"result":"fn x() {}","session_id":"abc","is_error":false}"#,
        )
        .unwrap();
        assert_eq!(ok, "fn x() {}");
        let err = extract_result(&p, r#"{"result":"rate limit","is_error":true}"#);
        assert!(err.is_err());
    }

    #[test]
    fn extract_copilot_strip_and_codex_header() {
        let copilot = load_bundled("copilot");
        assert_eq!(
            extract_result(&copilot, "hello\n\nChanges    +1 -0\n").unwrap(),
            "hello"
        );
        let codex = load_bundled("codex");
        let raw = "Reading extra\n--------\nworkdir: /ws\nmodel: x\nfn ok() {}\n";
        assert!(extract_result(&codex, raw).unwrap().contains("fn ok() {}"));
    }

    #[test]
    fn load_profile_skips_generic_stdio() {
        let _guard = ENV_LOCK.lock().unwrap();
        assert!(load_profile("generic-stdio").unwrap().is_none());
        assert!(load_profile("no-such-profile").unwrap().is_none());
    }

    #[test]
    fn open_profile_adapter_reads_id_and_workdir() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (id, adapter) = open_profile_adapter("claude-code:/var/ws")
            .unwrap()
            .expect("bundled");
        assert_eq!(id, "claude-code");
        assert_eq!(adapter.agent_id().0, "claude-code");
        assert!(open_profile_adapter("generic-stdio:echo")
            .unwrap()
            .is_none());
        assert!(open_profile_adapter("slim:peer").unwrap().is_none());
        assert!(open_profile_adapter("no-such-profile").unwrap().is_none());
    }

    #[test]
    fn load_profile_file_reads_override_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gemini.json");
        std::fs::write(
            &path,
            r#"{
              "id": "gemini",
              "bin": "gemini",
              "execute": { "args": ["{prompt}"] }
            }"#,
        )
        .unwrap();
        let loaded = load_profile_file(&path).unwrap().expect("override profile");
        assert_eq!(loaded.id, "gemini");
        assert_eq!(loaded.bin, "gemini");
        assert_eq!(
            render_argv(&loaded, "/ws", "hi", None, None, true),
            vec!["hi"]
        );
    }

    #[test]
    fn profile_adapter_constructs() {
        let adapter = ProfileAdapter::new(load_bundled("claude-code"), "/tmp");
        assert_eq!(adapter.agent_id().0, "claude-code");
    }

    fn echo_profile(extra: &str) -> CliProfile {
        parse_profile(&format!(
            r#"{{
              "id": "echo",
              "bin": "echo",
              "current_dir_workdir": false,
              "execute": {{ "args": ["{{prompt}}"] }},
              "result": {{ "kind": "stdout" }}
              {extra}
            }}"#
        ))
        .unwrap()
    }

    fn write_session_retry_bin() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        {
            let path = dir.path().join("retry.cmd");
            std::fs::write(
                &path,
                r#"@echo off
echo %* | findstr /C:"--session-id" >nul
if not errorlevel 1 (
  echo already in use 1>&2
  exit /b 1
)
echo {"result":"ok","session_id":"sid-9"}
"#,
            )
            .unwrap();
            (dir, path)
        }
        #[cfg(not(windows))]
        {
            let path = dir.path().join("retry.sh");
            std::fs::write(
                &path,
                r#"#!/bin/sh
has_session=0
for a in "$@"; do
  [ "$a" = "--session-id" ] && has_session=1
done
if [ "$has_session" = 1 ]; then
  echo "already in use" >&2
  exit 1
fi
echo '{"result":"ok","session_id":"sid-9"}'
"#,
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
            (dir, path)
        }
    }

    #[test]
    fn profile_execute_prompt_runs_echo() {
        let adapter = ProfileAdapter::new(echo_profile(""), std::env::temp_dir());
        let out = adapter.execute_prompt("hello-profile").unwrap();
        assert!(
            out.contains("hello-profile"),
            "execute output should echo the prompt"
        );
        adapter.kill_in_flight();
    }

    #[test]
    fn snapshot_and_inject_drive_run() {
        let adapter = ProfileAdapter::new(
            echo_profile(r#", "system_flag": "--system-prompt""#),
            std::env::temp_dir(),
        );
        let snap = adapter.snapshot_context().unwrap();
        assert_eq!(snap.source_agent, "echo");
        assert!(!snap.artifacts.is_empty());
        assert!(snap.code_context.project_root.is_some());

        let mut ctx = ContextPacket::new("peer");
        ctx.conversation.push(ConversationMessage {
            role: "user".to_string(),
            content: "hi".to_string(),
        });
        ctx.code_context.files.push(crate::context::FileSnapshot {
            path: "src/lib.rs".to_string(),
            content: "fn x() {}".to_string(),
        });
        ctx.code_context.git_diff = Some("-a\n+b".to_string());
        ctx.artifacts.push(ArtifactPayload {
            name: "note.md".to_string(),
            content: "n".to_string(),
            media_type: "text/markdown".to_string(),
        });
        adapter.inject_context(&ctx).unwrap();
    }

    #[test]
    fn inject_without_system_flag_prepends_context() {
        let adapter = ProfileAdapter::new(echo_profile(""), std::env::temp_dir());
        let ctx = ContextPacket::new("peer");
        adapter.inject_context(&ctx).unwrap();
    }

    #[test]
    fn run_pins_tmpdir_and_nulls_stdin() {
        let profile = parse_profile(
            r#"{
              "id": "echo",
              "bin": "echo",
              "pin_tmpdir": true,
              "stdin_null": true,
              "current_dir_workdir": true,
              "env": { "AGENTBRIDGE_TEST_TMP": "{workdir}" },
              "workdir_flags": ["-n"],
              "execute": { "args": ["{workdir_flags}", "{prompt}"] },
              "result": { "kind": "stdout" }
            }"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let adapter = ProfileAdapter::new(profile, dir.path());
        let out = adapter.execute_prompt("pinned").unwrap();
        assert!(out.contains("pinned"), "execute output should echo the prompt");
    }

    #[test]
    fn execute_missing_bin_is_subprocess_error() {
        let profile = parse_profile(
            r#"{
              "id": "missing",
              "bin": "agentbridge-profile-bin-does-not-exist",
              "execute": { "args": ["{prompt}"] }
            }"#,
        )
        .unwrap();
        let adapter = ProfileAdapter::new(profile, std::env::temp_dir());
        assert!(adapter.execute_prompt("x").is_err());
    }

    #[test]
    fn execute_failed_command_with_empty_stdout_errors() {
        let profile = parse_profile(
            r#"{
              "id": "false",
              "bin": "false",
              "execute": { "args": [] }
            }"#,
        )
        .unwrap();
        let adapter = ProfileAdapter::new(profile, std::env::temp_dir());
        let err = adapter.execute_prompt("x").unwrap_err();
        assert!(err.to_string().contains("exited"), "{err}");
    }

    #[test]
    fn session_is_stored_and_retried_on_stderr_needle() {
        let (_dir, script) = write_session_retry_bin();
        let profile = parse_profile(
            &serde_json::json!({
                "id": "session",
                "bin": script.to_string_lossy(),
                "current_dir_workdir": false,
                "execute": { "args": ["{session}", "{prompt}"] },
                "session": {
                    "json_field": "session_id",
                    "flag": "--session-id",
                    "retry_stderr_contains": "already in use"
                },
                "result": { "kind": "json_field", "field": "result" }
            })
            .to_string(),
        )
        .unwrap();
        let adapter = ProfileAdapter::new(profile, std::env::temp_dir());
        assert_eq!(adapter.execute_prompt("one").unwrap(), "ok");
        assert_eq!(adapter.session_id().unwrap().as_deref(), Some("sid-9"));
        assert_eq!(adapter.execute_prompt("two").unwrap(), "ok");
        adapter.clear_session();
        assert!(adapter.session_id().unwrap().is_none());
    }

    #[test]
    fn execute_splits_large_prompt_when_profile_allows() {
        let profile = parse_profile(
            r#"{
              "id": "echo",
              "bin": "echo",
              "current_dir_workdir": false,
              "split_large_prompt": true,
              "system_flag": "--system-prompt",
              "execute": { "args": ["{system}", "{prompt}"] },
              "result": { "kind": "stdout" }
            }"#,
        )
        .unwrap();
        let adapter = ProfileAdapter::new(profile, std::env::temp_dir());
        let prompt = format!("context\n\n{}", "q".repeat(600));
        let out = adapter.execute_prompt(&prompt).unwrap();
        assert!(out.contains('q'), "split execute should keep the question");
    }

    #[test]
    fn extract_result_edge_cases() {
        let mut p = load_bundled("claude-code");
        p.result.field = None;
        assert!(extract_result(&p, r#"{"result":"x"}"#).is_err());
        p.result.field = Some("result".to_string());
        assert!(extract_result(&p, "not-json").is_err());
        let err = extract_result(&p, r#"{"is_error":true}"#).unwrap_err();
        assert!(err.to_string().contains("cli reported an error"));
        assert_eq!(extract_result(&p, r#"{}"#).unwrap(), "");

        let mut copilot = load_bundled("copilot");
        copilot.result.prefix = None;
        assert_eq!(
            extract_result(&copilot, "keep\nChanges 1\n").unwrap(),
            "keep"
        );

        let mut codex = load_bundled("codex");
        codex.result.line = None;
        assert_eq!(extract_result(&codex, "only body").unwrap(), "only body");
        assert!(extract_result(&codex, "head\n--------\ntail")
            .unwrap()
            .contains("tail"));
    }

    #[test]
    fn split_large_prompt_uses_blank_line_and_keeps_system() {
        let prompt = format!("{}\n\n{}", "c".repeat(200), "q".repeat(400));
        let (sys, rest) = split_large_prompt(&prompt, None, true);
        assert!(sys.unwrap().contains('c'));
        assert!(rest.contains('q'));
        let (sys, rest) = split_large_prompt("short", Some("keep"), true);
        assert_eq!(sys.as_deref(), Some("keep"));
        assert_eq!(rest, "short");
    }

    #[test]
    fn render_argv_expands_extra_args_and_inline_prompt() {
        let p = parse_profile(
            r#"{
              "id": "x",
              "bin": "x",
              "extra_args_env": "AGENTBRIDGE_TEST_EXTRA_ARGS",
              "execute": { "args": ["pre-{prompt}", "{extra_args}", "{prompt}"] }
            }"#,
        )
        .unwrap();
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AGENTBRIDGE_TEST_EXTRA_ARGS", "--flag value");
        let argv = render_argv(&p, "/ws", "hi", None, None, true);
        std::env::remove_var("AGENTBRIDGE_TEST_EXTRA_ARGS");
        assert_eq!(argv, vec!["pre-hi", "--flag", "value", "hi"]);
    }

    #[test]
    fn load_profile_reads_override_dir() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("override-probe.json"),
            r#"{"id":"override-probe","bin":"probe","execute":{"args":["{prompt}"]}}"#,
        )
        .unwrap();
        let prev = std::env::var("AGENTBRIDGE_PROFILES_DIR").ok();
        std::env::set_var("AGENTBRIDGE_PROFILES_DIR", dir.path());
        let loaded = load_profile("override-probe").unwrap().expect("override");
        match prev {
            Some(v) => std::env::set_var("AGENTBRIDGE_PROFILES_DIR", v),
            None => std::env::remove_var("AGENTBRIDGE_PROFILES_DIR"),
        }
        assert_eq!(loaded.id, "override-probe");
        assert!(load_profile_file(&dir.path().join("missing.json"))
            .unwrap()
            .is_none());
        assert!(parse_profile("{").is_err());
        assert!(open_profile_adapter("").unwrap().is_none());
        assert!(open_profile_adapter("generic-stdio").unwrap().is_none());
    }

    #[test]
    fn result_spec_and_kind_defaults() {
        assert!(matches!(ResultSpec::default().kind, ResultKind::Stdout));
        let stdout = parse_profile(r#"{"id":"t","bin":"t","execute":{"args":[]}}"#).unwrap();
        assert!(matches!(stdout.result.kind, ResultKind::Stdout));
    }
}
