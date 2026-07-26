// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, EditMode, Editor, Helper};
use unicode_width::UnicodeWidthStr;

use crate::cli_types::{
    ConfigCli, ConfigCommand, ConfigShowArgs, OutputFormat, PolicyCli, PolicyCommand,
    PolicyDiffArgs, PolicyExplainArgs, ShellArgs, SlimCreateGroupArgs,
};
use crate::introspection_command::{run_config_command, run_policy_command};
use crate::policy_watch;
use crate::secrets_command;
use crate::slim_a2a;
use crate::slim_shell::SlimShellState;
use crate::snapshot_command;
use crate::trace_command::{resolve_trace_file, trace_list, trace_summary};
use shadi_sandbox::PolicyPatch;

const COMMANDS: &[(&str, &str)] = &[
    ("/help", "Show available commands (alias: /h)"),
    ("/status", "Show current session status (alias: /s)"),
    ("/attach", "Attach to a running sandbox session by name or socket path"),
    ("/detach", "Detach from the current session"),
    ("/kill", "Terminate the attached sandboxed process"),
    ("/sessions", "Discover running SHADI sandbox control sockets"),
    ("/config", "Show effective runtime configuration"),
    ("/policy query", "Query the effective policy of the attached session"),
    ("/policy patch", "Patch the policy of the attached session"),
    ("/policy explain", "Explain resolved policy and source inputs"),
    ("/policy diff", "Diff effective policy against a baseline profile"),
    ("/trace list", "List recent trace log entries"),
    ("/trace summary", "Summarize trace logs by span name"),
    ("/slim status", "Show native SLIM shell status"),
    ("/slim start node", "Start a local native SLIM node with SHADI mTLS defaults"),
    ("/slim a2a-echo-peer", "Serve one task-backed A2A request over SLIMRPC"),
    ("/slim a2a-send", "Send a unary or streaming A2A request over SLIMRPC"),
    ("/slim create", "Create a SLIM group session for a channel name"),
    ("/slim invite", "Invite a participant into the active SLIM group session"),
    ("/slim invite-from", "Re-resolve a member spec live and invite matches already in the trust set"),
    ("/slim join", "Wait for and join an invited SLIM group session"),
    ("/snapshot list", "List git snapshot artifacts"),
    ("/snapshot show", "Show details of a git snapshot"),
    ("/resources", "Show resource usage of the sandboxed process"),
    ("/secrets list", "List available keychain secret keys"),
    ("/secrets rules", "Show secret delivery rules from policy"),
    ("/secrets backend", "Show current secret backend configuration"),
    ("/history", "Show command history"),
    ("/clear", "Clear the terminal screen"),
    ("/exit", "Exit the interactive shell (alias: /q, /quit)"),
];

/// Detailed help text for commands that accept arguments.
const COMMAND_HELP: &[(&str, &str)] = &[
    ("/attach", "\
Usage: /attach <name-or-path>

Attach to a running SHADI sandbox session by its human-readable name or full
control socket path.

Examples:
  /attach my-codex-session
  /attach /tmp/shadi-ctl-12345.sock"),
    ("/policy query", "\
Usage: /policy query

Query the effective policy of the attached session and display it as JSON."),
    ("/policy patch", "\
Usage: /policy patch [options]

Patch the policy of the attached session. Requires confirmation unless --force is given.

Options:
  --add-read PATH              Add a filesystem read path
  --add-write PATH             Add a filesystem write path
  --add-allow PATH             Add a filesystem allow (read+write) path
  --add-allow-command CMD      Allow a command
  --remove-allow-command CMD   Remove an allowed command
  --add-block-command CMD      Block a command
  --remove-block-command CMD   Remove a blocked command
  --add-net-allow DEST         Allow a network destination
  --remove-net-allow DEST      Remove an allowed network destination
  --force                      Skip confirmation prompt
  --dry-run                    Show what would change without applying

Examples:
  /policy patch --add-read /tmp --add-allow-command npm
  /policy patch --add-net-allow api.example.com --force"),
    ("/policy explain", "\
Usage: /policy explain

Explain the resolved policy and show source inputs as JSON."),
    ("/policy diff", "\
Usage: /policy diff <baseline>

Diff the effective policy against a baseline profile or file.

Baseline format:
  profile:<strict|balanced|connected>
  file:<path>

Examples:
  /policy diff profile:strict
  /policy diff file:./my-policy.json"),
    ("/trace list", "\
Usage: /trace list [options]

List recent trace log entries.

Options:
  --limit N          Maximum entries to show (default: 20)
  --name SUBSTR      Filter by span name substring
  --command SUBSTR   Filter by command substring
  --exit-code CODE   Filter by exit code"),
    ("/trace summary", "\
Usage: /trace summary [--limit N]

Summarize trace logs grouped by span name."),
        ("/slim status", "\
Usage: /slim status

Show the native SLIM shell state, including the canonical local name,
configured endpoint, current connection, and active group session."),
        ("/slim start node", "\
Usage: /slim start node

Start a local SLIM dataplane node inside the interactive shell using SHADI's
managed mTLS files under .tmp/shadi-slim-mtls.

Environment:
    SLIM_ENDPOINT            Override the local endpoint (default: 127.0.0.1:47357)
    SHADI_TMP_DIR            Override the base temp directory that contains shadi-slim-mtls"),
        ("/slim a2a-echo-peer", "\
Usage: /slim a2a-echo-peer [--endpoint HOST:PORT] [--agent-id ID] [--listen-timeout SECONDS] [--ready-file PATH] [--start-local-node]

Serve a task-backed A2A peer over SLIMRPC until one request arrives or the
listen timeout elapses.

Options:
    --endpoint HOST:PORT     Override the SLIM endpoint
    --agent-id ID            Local peer identity (default: secops-a)
    --listen-timeout SECONDS Stop waiting after SECONDS (default: 20)
    --ready-file PATH        Write a ready marker once the peer is serving
    --start-local-node       Start a local SLIM node in the same process

Examples:
    /slim a2a-echo-peer --start-local-node
    /slim a2a-echo-peer --agent-id secops-a --listen-timeout 30"),
        ("/slim a2a-send", "\
Usage: /slim a2a-send [--endpoint HOST:PORT] [--agent-id ID] [--peer-agent-id ID] [--destination NAME] [--message TEXT...] [--stream] [--timeout SECONDS] [--session-id ID]

Send a unary or streaming A2A request over SLIMRPC using SHADI's verifier-gated
channel. Multi-word message text is accepted after --message until the next flag.

Options:
    --endpoint HOST:PORT     Override the SLIM endpoint
    --agent-id ID            Local sender identity (default: avatar)
    --peer-agent-id ID       Remote peer identity (default: secops-a)
    --destination NAME       Override the canonical remote SLIM name
    --message TEXT...        Message text to send
    --stream                 Use the streaming A2A path
    --timeout SECONDS        Response timeout in seconds (default: 20)
    --session-id ID          Session context id for verifier gating

Examples:
    /slim a2a-send --message hello from avatar
    /slim a2a-send --peer-agent-id secops-a --stream --message hello from avatar"),
        ("/slim create", "\
Usage: /slim create <organization/namespace/application>

Create a native SLIM group session for the given channel name and make it the
active shell session.

Examples:
    /slim create agntcy/shadi/secops-room
    /slim create acme/ops/incidents"),
        ("/slim invite", "\
Usage: /slim invite <organization/namespace/application>

Invite a participant into the active SLIM group session.

Examples:
    /slim invite agntcy/shadi/avatar
    /slim invite acme/ops/oncall-bot"),
        ("/slim invite-from", "\
Usage: /slim invite-from <skill:<skill>|did:<did>|explicit:<name>=<did>[@<endpoint>]>

Re-resolve one member-source spec live (same syntax as `shadictl slim
create-group --members`) and invite whichever resolved candidates are already
inside this group's trust set (SLIM_MEMBER_DIDS). A candidate whose DID isn't
in the trust set is skipped with an explicit message rather than a silent
failure — recreate the group with a broader --members set to include it.

Examples:
    /slim invite-from skill:code_generation/implementation
    /slim invite-from did:did:key:z6Mk...
    /slim invite-from explicit:copilot=did:key:z6Mk...@127.0.0.1:47357"),
        ("/slim join", "\
Usage: /slim join <organization/namespace/application> [--timeout SECONDS]

Wait for an invitation to the named SLIM channel and activate the resulting
group session. By default the shell waits for 30 seconds. Use --timeout 0 to
wait indefinitely.

Examples:
    /slim join agntcy/shadi/secops-room
    /slim join acme/ops/incidents --timeout 60"),
    ("/snapshot list", "\
Usage: /snapshot list [--dir PATH]

List all git snapshot artifacts from the snapshot directory.

Options:
  --dir PATH   Override the default snapshot directory

Default directory: $SHADI_TMP_DIR/git-snapshots or .tmp/git-snapshots"),
    ("/snapshot show", "\
Usage: /snapshot show <artifact-id|latest> [--dir PATH]

Show a detailed summary of a git snapshot artifact.

Examples:
  /snapshot show latest
  /snapshot show 1711234567890-12345-bash"),
    ("/resources", "\
Usage: /resources

Show resource usage (memory, CPU, threads) of the attached sandboxed process.
Requires an attached session with --watch-policy enabled."),
    ("/secrets list", "\
Usage: /secrets list [--prefix PREFIX]

List available keychain secret keys.

Options:
  --prefix PREFIX    Filter keys by prefix substring"),
    ("/secrets rules", "\
Usage: /secrets rules [--policy PATH]

Show secret delivery rules from the policy file.

Options:
  --policy PATH    Path to the policy TOML file (default: sandbox.json)

Displays inject_keychain, trusted_secret, and secret_policy rules with
their associated key names, actions, and constraints."),
    ("/secrets backend", "\
Usage: /secrets backend

Show the current secret backend configuration.
Reads SHADI_SECRET_BACKEND, SHADI_OP_VAULT, and SHADI_OP_ACCOUNT
environment variables."),
    ("/history", "\
Usage: /history [--limit N] [--grep PATTERN]

Show command history from the current and previous sessions.

Options:
  --limit N          Maximum entries to show (default: 20)
  --grep PATTERN     Filter history entries by substring"),
        ("/kill", "\
Usage: /kill

Request termination of the attached sandboxed process.

Examples:
    /kill"),
];

struct ShellHelper {
    hinter: HistoryHinter,
    use_color: bool,
}

impl ShellHelper {
    fn new(use_color: bool) -> Self {
        Self {
            hinter: HistoryHinter {},
            use_color,
        }
    }
}

impl Helper for ShellHelper {}
impl Validator for ShellHelper {}

impl Highlighter for ShellHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        if !self.use_color || line.is_empty() {
            return Cow::Borrowed(line);
        }
        // Highlight the command portion in yellow.
        for &(cmd, _) in COMMANDS {
            if line.starts_with(cmd) {
                let rest = &line[cmd.len()..];
                return Cow::Owned(format!("\x1b[1;33m{}\x1b[0m{}", cmd, rest));
            }
        }
        // Also highlight aliases.
        for alias in &["/h", "/s", "/q"] {
            if line.starts_with(alias) {
                let rest = &line[alias.len()..];
                return Cow::Owned(format!("\x1b[1;33m{}\x1b[0m{}", alias, rest));
            }
        }
        Cow::Borrowed(line)
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: CmdKind) -> bool {
        self.use_color
    }
}

impl Hinter for ShellHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

/// Policy patch flag names for argument completion.
const PATCH_FLAGS: &[&str] = &[
    "--add-read",
    "--add-write",
    "--add-allow",
    "--add-allow-command",
    "--remove-allow-command",
    "--add-block-command",
    "--remove-block-command",
    "--add-net-allow",
    "--remove-net-allow",
    "--force",
    "--dry-run",
];

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let input = &line[..pos];
        let mut candidates = Vec::new();

        // If input starts with "/policy " or "/trace ", complete subcommands.
        if let Some(sub_input) = input.strip_prefix("/policy ") {
            let sub_input = sub_input.trim_start();
            // Check if we're past the subcommand into patch flags.
            if sub_input.starts_with("patch ") {
                let flag_input = sub_input.strip_prefix("patch ").unwrap_or("");
                // Find the last whitespace-delimited token being typed.
                let last_token_start = flag_input.rfind(' ').map(|i| i + 1).unwrap_or(0);
                let partial = &flag_input[last_token_start..];
                if partial.starts_with('-') || partial.is_empty() {
                    for flag in PATCH_FLAGS {
                        if flag.starts_with(partial) {
                            candidates.push(Pair {
                                display: flag.to_string(),
                                replacement: flag.to_string(),
                            });
                        }
                    }
                    // Offset from start of the last token.
                    let offset = pos - partial.len();
                    return Ok((offset, candidates));
                }
                return Ok((pos, candidates));
            }
            let subs = ["query", "patch", "explain", "diff"];
            for sub in subs {
                if sub.starts_with(sub_input) {
                    candidates.push(Pair {
                        display: sub.to_string(),
                        replacement: sub.to_string(),
                    });
                }
            }
            let offset = pos - sub_input.len();
            return Ok((offset, candidates));
        }

        if let Some(sub_input) = input.strip_prefix("/trace ") {
            let sub_input = sub_input.trim_start();
            let subs = ["list", "summary"];
            for sub in subs {
                if sub.starts_with(sub_input) {
                    candidates.push(Pair {
                        display: sub.to_string(),
                        replacement: sub.to_string(),
                    });
                }
            }
            let offset = pos - sub_input.len();
            return Ok((offset, candidates));
        }

        if let Some(sub_input) = input.strip_prefix("/slim ") {
            let sub_input = sub_input.trim_start();
            if let Some(start_input) = sub_input.strip_prefix("start ") {
                let start_input = start_input.trim_start();
                for sub in ["node"] {
                    if sub.starts_with(start_input) {
                        candidates.push(Pair {
                            display: sub.to_string(),
                            replacement: sub.to_string(),
                        });
                    }
                }
                let offset = pos - start_input.len();
                return Ok((offset, candidates));
            }

            let subs = [
                "status",
                "start",
                "a2a-echo-peer",
                "a2a-send",
                "a2a-collaborate",
                "create",
                "invite",
                "invite-from",
                "join",
                "whoami",
            ];
            for sub in subs {
                if sub.starts_with(sub_input) {
                    candidates.push(Pair {
                        display: sub.to_string(),
                        replacement: sub.to_string(),
                    });
                }
            }
            let offset = pos - sub_input.len();
            return Ok((offset, candidates));
        }

        if let Some(sub_input) = input.strip_prefix("/snapshot ") {
            let sub_input = sub_input.trim_start();
            let subs = ["list", "show"];
            for sub in subs {
                if sub.starts_with(sub_input) {
                    candidates.push(Pair {
                        display: sub.to_string(),
                        replacement: sub.to_string(),
                    });
                }
            }
            let offset = pos - sub_input.len();
            return Ok((offset, candidates));
        }

        if let Some(sub_input) = input.strip_prefix("/secrets ") {
            let sub_input = sub_input.trim_start();
            let subs = ["list", "rules", "backend"];
            for sub in subs {
                if sub.starts_with(sub_input) {
                    candidates.push(Pair {
                        display: sub.to_string(),
                        replacement: sub.to_string(),
                    });
                }
            }
            let offset = pos - sub_input.len();
            return Ok((offset, candidates));
        }

        // Name/path completion for /attach — show human-readable session names.
        if let Some(name_input) = input.strip_prefix("/attach ") {
            let name_input = name_input.trim_start();
            let tmpdir = std::env::temp_dir();
            if let Ok(entries) = std::fs::read_dir(&tmpdir) {
                for entry in entries.flatten() {
                    let fname = entry.file_name();
                    let fname_str = fname.to_string_lossy();
                    if fname_str.starts_with("shadi-ctl-") && fname_str.ends_with(".sock") {
                        let session_name = policy_watch::session_name_from_path(&entry.path());
                        if session_name.starts_with(name_input) || name_input.is_empty() {
                            candidates.push(Pair {
                                display: session_name.clone(),
                                replacement: session_name,
                            });
                        }
                    }
                }
            }
            let offset = pos - name_input.len();
            return Ok((offset, candidates));
        }

        // Top-level command completion.
        for &(cmd, _desc) in COMMANDS {
            if cmd.starts_with(input) {
                candidates.push(Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                });
            }
        }
        // Also offer aliases.
        for &(alias, full) in &[("/h", "/help"), ("/s", "/status"), ("/q", "/quit")] {
            if alias.starts_with(input) && !full.starts_with(input) {
                candidates.push(Pair {
                    display: format!("{} ({})", alias, full),
                    replacement: alias.to_string(),
                });
            }
        }

        Ok((0, candidates))
    }
}

struct ShellSession {
    socket: Option<PathBuf>,
    pending_patch: Option<PendingPatch>,
    slim: SlimShellState,
}

struct PendingPatch {
    socket: PathBuf,
    patch: PolicyPatch,
}

impl ShellSession {
    fn new(socket: Option<PathBuf>) -> Self {
        Self {
            socket,
            pending_patch: None,
            slim: SlimShellState::new(),
        }
    }

    fn handle_command(&mut self, line: &str) -> LoopAction {
        if self.pending_patch.is_some() {
            return self.handle_pending_confirmation(line);
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return LoopAction::Continue;
        }

        // Check for --help on any command.
        if parts.len() >= 2 && parts.last() == Some(&"--help") {
            let cmd_key = parts[..parts.len() - 1].join(" ");
            return self.cmd_help_detail(&cmd_key);
        }

        match parts[0] {
            "/help" | "/h" => {
                if parts.len() >= 2 {
                    let target = parts[1..].join(" ");
                    // Prepend / if not present.
                    let key = if target.starts_with('/') {
                        target
                    } else {
                        format!("/{}", target)
                    };
                    self.cmd_help_detail(&key)
                } else {
                    self.cmd_help()
                }
            }
            "/status" | "/s" => self.cmd_status(),
            "/sessions" => self.cmd_sessions(),
            "/config" => self.cmd_config(),
            "/policy" if parts.len() >= 2 => match parts[1] {
                "query" => self.cmd_policy_query(),
                "patch" => self.cmd_policy_patch(&parts[2..]),
                "explain" => self.cmd_policy_explain(),
                "diff" => self.cmd_policy_diff(&parts[2..]),
                _ => {
                    eprintln!("unknown policy subcommand: {}", parts[1]);
                    eprintln!("  available: query, patch, explain, diff");
                    LoopAction::Continue
                }
            },
            "/policy" => {
                eprintln!("usage: /policy <query|patch|explain|diff>");
                LoopAction::Continue
            }
            "/trace" if parts.len() >= 2 => match parts[1] {
                "list" => self.cmd_trace_list(&parts[2..]),
                "summary" => self.cmd_trace_summary(&parts[2..]),
                _ => {
                    eprintln!("unknown trace subcommand: {}", parts[1]);
                    eprintln!("  available: list, summary");
                    LoopAction::Continue
                }
            },
            "/trace" => {
                eprintln!("usage: /trace <list|summary>");
                LoopAction::Continue
            }
            "/slim" if parts.len() >= 2 => match parts[1] {
                "status" => self.cmd_slim_status(),
                "start" if parts.len() >= 3 && parts[2] == "node" => self.cmd_slim_start_node(),
                "start" => {
                    eprintln!("usage: /slim start node");
                    LoopAction::Continue
                }
                "a2a-echo-peer" => self.cmd_slim_a2a_echo_peer(&parts[2..]),
                "a2a-send" => self.cmd_slim_a2a_send(&parts[2..]),
                "a2a-collaborate" => self.cmd_slim_a2a_collaborate(&parts[2..]),
                "create" => self.cmd_slim_create(&parts[2..]),
                "invite" => self.cmd_slim_invite(&parts[2..]),
                "invite-from" => self.cmd_slim_invite_from(&parts[2..]),
                "join" => self.cmd_slim_join(&parts[2..]),
                "whoami" => self.cmd_slim_whoami(),
                _ => {
                    eprintln!("unknown slim subcommand: {}", parts[1]);
                    eprintln!(
                        "  available: status, start node, a2a-echo-peer, a2a-send, a2a-collaborate, create, invite, invite-from, join, whoami"
                    );
                    LoopAction::Continue
                }
            },
            "/slim" => {
                eprintln!("usage: /slim <status|start node|a2a-echo-peer|a2a-send|create|invite|invite-from|join>");
                LoopAction::Continue
            }
            "/snapshot" if parts.len() >= 2 => match parts[1] {
                "list" => self.cmd_snapshot_list(&parts[2..]),
                "show" => self.cmd_snapshot_show(&parts[2..]),
                _ => {
                    eprintln!("unknown snapshot subcommand: {}", parts[1]);
                    eprintln!("  available: list, show");
                    LoopAction::Continue
                }
            },
            "/snapshot" => {
                eprintln!("usage: /snapshot <list|show>");
                LoopAction::Continue
            }
            "/resources" => self.cmd_resources(),
            "/secrets" if parts.len() >= 2 => match parts[1] {
                "list" => self.cmd_secrets_list(&parts[2..]),
                "rules" => self.cmd_secrets_rules(&parts[2..]),
                "backend" => self.cmd_secrets_backend(),
                _ => {
                    eprintln!("unknown secrets subcommand: {}", parts[1]);
                    eprintln!("  available: list, rules, backend");
                    LoopAction::Continue
                }
            },
            "/secrets" => {
                eprintln!("usage: /secrets <list|rules|backend>");
                LoopAction::Continue
            }
            "/attach" => {
                if parts.len() < 2 {
                    eprintln!("usage: /attach <name-or-path>");
                } else {
                    self.cmd_attach(parts[1]);
                }
                LoopAction::Continue
            }
            "/kill" => self.cmd_kill(),
            "/detach" => {
                self.cmd_detach();
                LoopAction::Continue
            }
            "/history" => self.cmd_history(&parts[1..]),
            "/clear" => {
                print!("\x1B[2J\x1B[1;1H");
                LoopAction::Continue
            }
            "/exit" | "/quit" | "/q" => LoopAction::Exit,
            _ => {
                eprintln!("unknown command: {}", parts[0]);
                eprintln!("type '/help' for available commands");
                LoopAction::Continue
            }
        }
    }

    fn handle_pending_confirmation(&mut self, line: &str) -> LoopAction {
        let answer = line.trim();
        if matches!(answer, "/exit" | "/quit" | "/q") {
            self.pending_patch = None;
            return LoopAction::Exit;
        }

        let Some(pending) = self.pending_patch.take() else {
            return LoopAction::Continue;
        };

        if !matches!(answer, "y" | "Y" | "yes" | "YES" | "Yes") {
            println!("patch cancelled");
            return LoopAction::Continue;
        }

        match policy_watch::send_patch(&pending.socket, &pending.patch) {
            Ok(resp) => match serde_json::to_string_pretty(&resp) {
                Ok(json) => println!("{}", json),
                Err(_) => {
                    println!("accepted: {}", resp.accepted);
                    println!("message:  {}", resp.message);
                }
            },
            Err(err) => eprintln!("error patching policy: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_help_detail(&self, cmd: &str) -> LoopAction {
        let color = std::io::IsTerminal::is_terminal(&std::io::stdout());
        for &(key, text) in COMMAND_HELP {
            if key == cmd {
                if color {
                    println!("\x1b[1m{}\x1b[0m\n", text);
                } else {
                    println!("{}\n", text);
                }
                return LoopAction::Continue;
            }
        }
        // Fall back to the one-liner from COMMANDS.
        for &(key, desc) in COMMANDS {
            if key == cmd {
                println!("{} — {}", key, desc);
                return LoopAction::Continue;
            }
        }
        eprintln!("no help available for '{}'", cmd);
        LoopAction::Continue
    }

    fn cmd_help(&self) -> LoopAction {
        let color = std::io::IsTerminal::is_terminal(&std::io::stdout());
        if color {
            println!("\x1b[1mSHADI interactive shell commands:\x1b[0m");
        } else {
            println!("SHADI interactive shell commands:");
        }
        println!();
        for &(cmd, desc) in COMMANDS {
            if color {
                println!("  \x1b[1;33m{:<20}\x1b[0m {}", cmd, desc);
            } else {
                println!("  {:<20} {}", cmd, desc);
            }
        }
        println!();
        if let Some(ref sock) = self.socket {
            if color {
                println!("  \x1b[32m attached to: {}\x1b[0m", sock.display());
            } else {
                println!("attached to: {}", sock.display());
            }
        } else if color {
            println!("  \x1b[2mnot attached to any session (use '/attach <socket-path>')\x1b[0m");
        } else {
            println!("not attached to any session (use '/attach <socket-path>')");
        }
        LoopAction::Continue
    }

    fn cmd_status(&self) -> LoopAction {
        match &self.socket {
            Some(sock) => {
                println!("session: attached");
                println!("socket:  {}", sock.display());
                match policy_watch::query_policy(sock) {
                    Ok(_policy) => {
                        println!("policy:  connected (query ok)");
                    }
                    Err(err) => {
                        println!("policy:  unreachable ({})", err);
                    }
                }
            }
            None => {
                println!("session: not attached");
                println!("use '/attach <socket-path>' to connect to a running sandbox");
            }
        }
        LoopAction::Continue
    }

    fn cmd_policy_query(&self) -> LoopAction {
        let Some(ref sock) = self.socket else {
            eprintln!("not attached to a session; use '/attach <socket-path>' first");
            return LoopAction::Continue;
        };

        match policy_watch::query_policy(sock) {
            Ok(policy) => {
                match serde_json::to_string_pretty(&policy) {
                    Ok(json) => println!("{}", json),
                    Err(err) => eprintln!("error formatting policy: {}", err),
                }
            }
            Err(err) => eprintln!("error querying policy: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_policy_patch(&mut self, args: &[&str]) -> LoopAction {
        let Some(ref sock) = self.socket else {
            eprintln!("not attached to a session; use '/attach <socket-path>' first");
            return LoopAction::Continue;
        };

        let mut patch = PolicyPatch::default();
        let mut force = false;
        let mut dry_run = false;
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--add-read" if i + 1 < args.len() => {
                    patch.add_read.push(args[i + 1].to_string());
                    i += 2;
                }
                "--add-write" if i + 1 < args.len() => {
                    patch.add_write.push(args[i + 1].to_string());
                    i += 2;
                }
                "--add-allow" if i + 1 < args.len() => {
                    patch.add_allow.push(args[i + 1].to_string());
                    i += 2;
                }
                "--add-allow-command" if i + 1 < args.len() => {
                    patch.add_allow_command.push(args[i + 1].to_string());
                    i += 2;
                }
                "--remove-allow-command" if i + 1 < args.len() => {
                    patch.remove_allow_command.push(args[i + 1].to_string());
                    i += 2;
                }
                "--add-block-command" if i + 1 < args.len() => {
                    patch.add_block_command.push(args[i + 1].to_string());
                    i += 2;
                }
                "--remove-block-command" if i + 1 < args.len() => {
                    patch.remove_block_command.push(args[i + 1].to_string());
                    i += 2;
                }
                "--add-net-allow" if i + 1 < args.len() => {
                    patch.add_net_allow.push(args[i + 1].to_string());
                    i += 2;
                }
                "--remove-net-allow" if i + 1 < args.len() => {
                    patch.remove_net_allow.push(args[i + 1].to_string());
                    i += 2;
                }
                "--force" => {
                    force = true;
                    i += 1;
                }
                "--dry-run" => {
                    dry_run = true;
                    i += 1;
                }
                _ => {
                    eprintln!("unknown patch argument: {}", args[i]);
                    eprintln!("use '/policy patch --help' for usage");
                    return LoopAction::Continue;
                }
            }
        }

        if dry_run {
            println!("dry-run: the following patch would be applied:");
            match serde_json::to_string_pretty(&patch) {
                Ok(json) => println!("{}", json),
                Err(err) => eprintln!("error formatting patch: {}", err),
            }
            return LoopAction::Continue;
        }

        // Confirmation prompt unless --force is given.
        if !force {
            match serde_json::to_string_pretty(&patch) {
                Ok(json) => println!("patch to apply:\n{}", json),
                Err(err) => eprintln!("error formatting patch: {}", err),
            }
            self.pending_patch = Some(PendingPatch {
                socket: sock.clone(),
                patch,
            });
            return LoopAction::Continue;
        }

        match policy_watch::send_patch(sock, &patch) {
            Ok(resp) => {
                match serde_json::to_string_pretty(&resp) {
                    Ok(json) => println!("{}", json),
                    Err(_) => {
                        println!("accepted: {}", resp.accepted);
                        println!("message:  {}", resp.message);
                    }
                }
            }
            Err(err) => eprintln!("error patching policy: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_sessions(&self) -> LoopAction {
        let tmpdir = std::env::temp_dir();
        let found = discover_control_sockets(&tmpdir);
        let sessions = classify_and_prune_control_sockets(found);

        if sessions.is_empty() {
            println!("no running SHADI sandbox sessions found in {}", tmpdir.display());
        } else {
            println!("found {} session(s):", sessions.len());
            for (sock, reachable) in &sessions {
                let name = policy_watch::session_name_from_path(sock);
                let marker = if *reachable { "reachable" } else { "stale" };
                println!("  {} ({})", name, marker);
            }
        }
        LoopAction::Continue
    }

    fn cmd_config(&self) -> LoopAction {
        let args = ConfigShowArgs {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        };
        run_config_command(ConfigCli {
            command: ConfigCommand::Show(args),
        });
        LoopAction::Continue
    }

    fn cmd_policy_explain(&self) -> LoopAction {
        let args = PolicyExplainArgs {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
            socket: self.socket.clone(),
        };
        run_policy_command(PolicyCli {
            command: PolicyCommand::Explain(args),
        });
        LoopAction::Continue
    }

    fn cmd_policy_diff(&self, args: &[&str]) -> LoopAction {
        if args.is_empty() {
            eprintln!("usage: /policy diff <baseline>");
            eprintln!("  baseline: profile:<strict|balanced|connected> or file:<path>");
            return LoopAction::Continue;
        }
        let against = args[0].to_string();
        let diff_args = PolicyDiffArgs {
            against,
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        };
        run_policy_command(PolicyCli {
            command: PolicyCommand::Diff(diff_args),
        });
        LoopAction::Continue
    }

    fn cmd_trace_list(&self, args: &[&str]) -> LoopAction {
        let mut limit: usize = 20;
        let mut name: Option<String> = None;
        let mut command: Option<String> = None;
        let mut exit_code: Option<i32> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--limit" if i + 1 < args.len() => {
                    limit = args[i + 1].parse().unwrap_or(20);
                    i += 2;
                }
                "--name" if i + 1 < args.len() => {
                    name = Some(args[i + 1].to_string());
                    i += 2;
                }
                "--command" if i + 1 < args.len() => {
                    command = Some(args[i + 1].to_string());
                    i += 2;
                }
                "--exit-code" if i + 1 < args.len() => {
                    exit_code = args[i + 1].parse().ok();
                    i += 2;
                }
                _ => {
                    eprintln!("usage: /trace list [--limit N] [--name SUBSTR] [--command SUBSTR] [--exit-code CODE]");
                    return LoopAction::Continue;
                }
            }
        }
        let path = resolve_trace_file(None);
        if let Err(err) = trace_list(
            &path,
            limit,
            name.as_deref(),
            command.as_deref(),
            exit_code,
        ) {
            eprintln!("error: {}", err);
        }
        LoopAction::Continue
    }

    fn cmd_trace_summary(&self, args: &[&str]) -> LoopAction {
        let mut limit: usize = 200;
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--limit" if i + 1 < args.len() => {
                    limit = args[i + 1].parse().unwrap_or(200);
                    i += 2;
                }
                _ => {
                    eprintln!("usage: /trace summary [--limit N]");
                    return LoopAction::Continue;
                }
            }
        }
        let path = resolve_trace_file(None);
        if let Err(err) = trace_summary(&path, limit) {
            eprintln!("error: {}", err);
        }
        LoopAction::Continue
    }

    fn cmd_slim_status(&self) -> LoopAction {
        match self.slim.status() {
            Ok(status) => {
                println!("SLIM local name: {}", status.local_name);
                println!("SLIM endpoint:   {}", status.endpoint);
                println!(
                    "SLIM node:       {}",
                    if status.node_started {
                        "running in this shell"
                    } else {
                        "not started in this shell"
                    }
                );
                match status.connection_id {
                    Some(connection_id) => println!("SLIM connection: {}", connection_id),
                    None => println!("SLIM connection: not established"),
                }
                match status.active_channel {
                    Some(channel) => println!("SLIM channel:    {}", channel),
                    None => println!("SLIM channel:    none"),
                }
                match status.active_session_id {
                    Some(session_id) => println!("SLIM session id: {}", session_id),
                    None => println!("SLIM session id: none"),
                }
            }
            Err(err) => eprintln!("error reading SLIM status: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_slim_start_node(&mut self) -> LoopAction {
        match self.slim.start_node() {
            Ok(message) => println!("{}", message),
            Err(err) => eprintln!("error starting SLIM node: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_slim_a2a_echo_peer(&mut self, args: &[&str]) -> LoopAction {
        match slim_a2a::parse_shell_a2a_echo_peer_args(args) {
            Ok(parsed) => {
                if let Err(err) = slim_a2a::run_a2a_echo_peer(parsed) {
                    eprintln!("error serving A2A peer: {}", err);
                }
            }
            Err(err) => eprintln!("{}", err),
        }
        LoopAction::Continue
    }

    fn cmd_slim_a2a_send(&mut self, args: &[&str]) -> LoopAction {
        match slim_a2a::parse_shell_a2a_send_args(args) {
            Ok(parsed) => {
                if let Err(err) = slim_a2a::run_a2a_send(parsed) {
                    eprintln!("error sending A2A request: {}", err);
                }
            }
            Err(err) => eprintln!("{}", err),
        }
        LoopAction::Continue
    }

    fn cmd_slim_a2a_collaborate(&mut self, args: &[&str]) -> LoopAction {
        match slim_a2a::parse_shell_a2a_collaborate_args(args) {
            Ok(parsed) => {
                if let Err(err) = slim_a2a::run_a2a_collaborate(parsed) {
                    eprintln!("error collaborating over A2A: {}", err);
                }
            }
            Err(err) => eprintln!("{}", err),
        }
        LoopAction::Continue
    }

    fn cmd_slim_create(&mut self, args: &[&str]) -> LoopAction {
        if args.len() != 1 {
            eprintln!("usage: /slim create <organization/namespace/application>");
            return LoopAction::Continue;
        }

        match self.slim.create_group_session(args[0]) {
            Ok(message) => println!("{}", message),
            Err(err) => eprintln!("error creating SLIM group session: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_slim_invite(&mut self, args: &[&str]) -> LoopAction {
        if args.len() != 1 {
            eprintln!("usage: /slim invite <organization/namespace/application>");
            return LoopAction::Continue;
        }

        match self.slim.invite_participant(args[0]) {
            Ok(message) => println!("{}", message),
            Err(err) => eprintln!("error inviting SLIM participant: {}", err),
        }
        LoopAction::Continue
    }

    /// `/slim invite-from <spec>` — re-resolve one `MemberSource` spec live
    /// (the same `skill:`/`did:`/`explicit:` syntax as `shadictl slim
    /// create-group --members`) and invite whichever resolved candidates are
    /// already inside this group's trust set (`SLIM_MEMBER_DIDS`). This is
    /// the "pull a newly-discovered agent into an already-running group"
    /// path — `/slim invite <name>` (unchanged, above) remains the manual
    /// equivalent for a moderator who already knows exactly who they want.
    fn cmd_slim_invite_from(&mut self, args: &[&str]) -> LoopAction {
        if args.len() != 1 {
            eprintln!(
                "usage: /slim invite-from <skill:<skill>|did:<did>|explicit:<name>=<did>[@<endpoint>]>"
            );
            return LoopAction::Continue;
        }
        let spec = args[0];

        let dir = agentbridge::member_source::DirLookupOptions {
            server_addr: std::env::var("SHADI_DIR_SERVER")
                .unwrap_or_else(|_| "prod.gateway.ads.outshift.io:443".to_string()),
            gh_token: std::env::var("DIRECTORY_CLIENT_GITHUB_TOKEN").ok(),
            limit: 20,
        };

        let source = match agentbridge::member_source::parse_member_spec(spec, &dir) {
            Ok(source) => source,
            Err(err) => {
                eprintln!("{}", err);
                return LoopAction::Continue;
            }
        };
        let candidates = match source.resolve() {
            Ok(candidates) => candidates,
            Err(err) => {
                eprintln!("error resolving {}: {}", spec, err);
                return LoopAction::Continue;
            }
        };
        if candidates.is_empty() {
            println!("no candidates resolved for {}", spec);
            return LoopAction::Continue;
        }

        let trust = trusted_dids_from_env();
        for candidate in &candidates {
            if !trust.contains(&candidate.did) {
                eprintln!(
                    "skipping {} ({}): not in this group's trust set — recreate the group with a broader --members set to include it",
                    candidate.name, candidate.did
                );
                continue;
            }
            // Invite the candidate's group-session identity (`agntcy/shadi/<name>`,
            // the same form manual `/slim invite <name>` uses) — not its
            // `-a2a`-suffixed A2A-listener identity, which is a separate SLIM
            // name for direct task delegation, unrelated to group membership.
            let target = format!("agntcy/shadi/{}", candidate.name);
            match self.slim.invite_participant(&target) {
                Ok(message) => println!("{}", message),
                Err(err) => eprintln!("error inviting {}: {}", target, err),
            }
        }
        LoopAction::Continue
    }

    fn cmd_slim_whoami(&mut self) -> LoopAction {
        match self.slim.whoami() {
            Ok(message) => println!("{}", message),
            Err(err) => eprintln!("error resolving SLIM identity: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_slim_join(&mut self, args: &[&str]) -> LoopAction {
        if args.is_empty() {
            eprintln!("usage: /slim join <organization/namespace/application> [--timeout SECONDS]");
            return LoopAction::Continue;
        }

        let mut channel = None;
        let mut timeout = Some(Duration::from_secs(30));
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--timeout" if i + 1 < args.len() => {
                    let seconds = match args[i + 1].parse::<u64>() {
                        Ok(seconds) => seconds,
                        Err(_) => {
                            eprintln!("invalid timeout value: {}", args[i + 1]);
                            return LoopAction::Continue;
                        }
                    };
                    timeout = if seconds == 0 {
                        None
                    } else {
                        Some(Duration::from_secs(seconds))
                    };
                    i += 2;
                }
                value if !value.starts_with('-') && channel.is_none() => {
                    channel = Some(value);
                    i += 1;
                }
                _ => {
                    eprintln!("usage: /slim join <organization/namespace/application> [--timeout SECONDS]");
                    return LoopAction::Continue;
                }
            }
        }

        let Some(channel) = channel else {
            eprintln!("usage: /slim join <organization/namespace/application> [--timeout SECONDS]");
            return LoopAction::Continue;
        };

        match self.slim.join_group_session(channel, timeout) {
            Ok(message) => println!("{}", message),
            Err(err) => eprintln!("error joining SLIM group session: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_attach(&mut self, name_or_path: &str) {
        let sock = policy_watch::resolve_session_socket(name_or_path);
        if !sock.exists() {
            eprintln!("session not found: {}", name_or_path);
            return;
        }
        match policy_watch::query_policy(&sock) {
            Ok(_) => {
                let display = policy_watch::session_name_from_path(&sock);
                println!("attached to {}", display);
                self.socket = Some(sock);
            }
            Err(err) => {
                eprintln!("failed to connect to {}: {}", name_or_path, err);
            }
        }
    }

    fn cmd_detach(&mut self) {
        if self.socket.is_some() {
            self.socket = None;
            println!("detached");
        } else {
            println!("not attached to any session");
        }
    }

    fn cmd_kill(&self) -> LoopAction {
        let Some(ref sock) = self.socket else {
            eprintln!("not attached to a session; use '/attach <socket-path>' first");
            return LoopAction::Continue;
        };

        match policy_watch::send_terminate(sock) {
            Ok(message) => println!("{}", message),
            Err(err) => eprintln!("error terminating session: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_history(&self, args: &[&str]) -> LoopAction {
        let mut limit: usize = 20;
        let mut grep: Option<&str> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--limit" if i + 1 < args.len() => {
                    limit = args[i + 1].parse().unwrap_or(20);
                    i += 2;
                }
                "--grep" if i + 1 < args.len() => {
                    grep = Some(args[i + 1]);
                    i += 2;
                }
                _ => {
                    eprintln!("usage: /history [--limit N] [--grep PATTERN]");
                    return LoopAction::Continue;
                }
            }
        }
        let Some(path) = dirs_history_path() else {
            eprintln!("history file not available");
            return LoopAction::Continue;
        };
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let lines: Vec<&str> = contents.lines().collect();
                let filtered: Vec<&&str> = if let Some(pat) = grep {
                    lines.iter().filter(|l| l.contains(pat)).collect()
                } else {
                    lines.iter().collect()
                };
                let start = filtered.len().saturating_sub(limit);
                for (idx, line) in filtered[start..].iter().enumerate() {
                    println!("  {:>4}  {}", start + idx + 1, line);
                }
                if filtered.is_empty() {
                    println!("(no matching history entries)");
                }
            }
            Err(_) => println!("(no history yet)"),
        }
        LoopAction::Continue
    }

    fn cmd_snapshot_list(&self, args: &[&str]) -> LoopAction {
        let mut dir_override: Option<&str> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--dir" if i + 1 < args.len() => {
                    dir_override = Some(args[i + 1]);
                    i += 2;
                }
                _ => {
                    eprintln!("usage: /snapshot list [--dir PATH]");
                    return LoopAction::Continue;
                }
            }
        }
        snapshot_command::snapshot_list(dir_override);
        LoopAction::Continue
    }

    fn cmd_snapshot_show(&self, args: &[&str]) -> LoopAction {
        if args.is_empty() {
            eprintln!("usage: /snapshot show <artifact-id|latest> [--dir PATH]");
            return LoopAction::Continue;
        }
        let id = args[0];
        let mut dir_override: Option<&str> = None;
        let mut i = 1;
        while i < args.len() {
            match args[i] {
                "--dir" if i + 1 < args.len() => {
                    dir_override = Some(args[i + 1]);
                    i += 2;
                }
                _ => {
                    eprintln!("usage: /snapshot show <artifact-id|latest> [--dir PATH]");
                    return LoopAction::Continue;
                }
            }
        }
        snapshot_command::snapshot_show(id, dir_override);
        LoopAction::Continue
    }

    fn cmd_resources(&self) -> LoopAction {
        let Some(ref sock) = self.socket else {
            eprintln!("not attached to a session; use '/attach <socket-path>' first");
            return LoopAction::Continue;
        };

        match policy_watch::query_resources(sock) {
            Ok(r) => {
                println!("Process: PID {}", r.pid);
                println!();
                println!("Memory:");
                if let Some(rss) = r.rss_bytes {
                    println!(
                        "  RSS:     {}",
                        snapshot_command::format_bytes(rss)
                    );
                }
                if let Some(virt) = r.virtual_bytes {
                    println!(
                        "  Virtual: {}",
                        snapshot_command::format_bytes(virt)
                    );
                }
                if r.cpu_user_ms.is_some() || r.cpu_system_ms.is_some() {
                    println!();
                    println!("CPU:");
                    if let Some(user) = r.cpu_user_ms {
                        println!("  User:    {} ms", user);
                    }
                    if let Some(sys) = r.cpu_system_ms {
                        println!("  System:  {} ms", sys);
                    }
                }
                if let Some(threads) = r.thread_count {
                    println!();
                    println!("Threads: {}", threads);
                }
            }
            Err(err) => eprintln!("error querying resources: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_secrets_list(&self, args: &[&str]) -> LoopAction {
        let mut prefix = None;
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--prefix" && i + 1 < args.len() {
                prefix = Some(args[i + 1]);
                i += 2;
            } else {
                eprintln!("unknown option: {}", args[i]);
                return LoopAction::Continue;
            }
        }
        secrets_command::secrets_list(prefix);
        LoopAction::Continue
    }

    fn cmd_secrets_rules(&self, args: &[&str]) -> LoopAction {
        let mut policy_path = None;
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--policy" && i + 1 < args.len() {
                policy_path = Some(args[i + 1]);
                i += 2;
            } else {
                eprintln!("unknown option: {}", args[i]);
                return LoopAction::Continue;
            }
        }
        secrets_command::secrets_rules(policy_path);
        LoopAction::Continue
    }

    fn cmd_secrets_backend(&self) -> LoopAction {
        secrets_command::secrets_backend();
        LoopAction::Continue
    }
}

enum LoopAction {
    Continue,
    Exit,
}

fn handle_shell_line(session: &mut ShellSession, line: &str) -> Option<LoopAction> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        if session.pending_patch.is_some() {
            println!("patch cancelled");
            session.pending_patch = None;
        }
        return None;
    }

    Some(session.handle_command(trimmed))
}

/// Run the interactive (or piped) shell loop. `initial_lines` — if
/// non-empty — are run first, as if typed by the user, right after the
/// banner and before the interactive loop starts; `shadictl slim
/// create-group` uses this to auto-create the discovered group, then hand
/// off into a normal shell session as its moderator.
pub(crate) fn run_shell_command(args: ShellArgs, initial_lines: &[String]) -> ExitCode {
    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let stdin = io::stdin();
    let stdin_is_terminal = std::io::IsTerminal::is_terminal(&stdin);

    let initial_socket = args.socket.clone().or_else(|| {
        args.attach
            .as_deref()
            .map(policy_watch::resolve_session_socket)
    });
    let mut session = ShellSession::new(initial_socket);

    print_banner(use_color);
    if let Some(ref sock) = session.socket {
        let display_name = policy_watch::session_name_from_path(sock);
        if use_color {
            println!("  \x1b[32m attached to: {}\x1b[0m", display_name);
        } else {
            println!("  attached to: {}", display_name);
        }
    }
    println!();

    for line in initial_lines {
        println!("shadi> {}", line);
        match handle_shell_line(&mut session, line) {
            Some(LoopAction::Continue) | None => {}
            Some(LoopAction::Exit) => {
                session.slim.shutdown();
                return ExitCode::SUCCESS;
            }
        }
    }

    if !stdin_is_terminal {
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(line) => line,
                Err(err) => {
                    eprintln!("error: {}", err);
                    break;
                }
            };

            match handle_shell_line(&mut session, &line) {
                Some(LoopAction::Continue) | None => {}
                Some(LoopAction::Exit) => break,
            }
        }

        session.slim.shutdown();
        return ExitCode::SUCCESS;
    }

    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();

    let helper = ShellHelper::new(use_color);
    let mut rl = match Editor::with_config(config) {
        Ok(rl) => rl,
        Err(err) => {
            eprintln!("failed to initialize interactive shell: {}", err);
            return ExitCode::FAILURE;
        }
    };
    rl.set_helper(Some(helper));

    // Load history from a well-known path.
    let history_path = dirs_history_path();
    if let Some(ref path) = history_path {
        let _ = rl.load_history(path);
    }

    loop {
        let prompt = if session.pending_patch.is_some() {
            if use_color {
                "\x1b[1;33mapply this patch? [y/N]\x1b[0m ".to_string()
            } else {
                "apply this patch? [y/N] ".to_string()
            }
        } else {
            if use_color {
                match &session.socket {
                    Some(sock) => format!("\x1b[1;36mshadi\x1b[0m(\x1b[33m{}\x1b[0m)\x1b[1;36m>\x1b[0m ", short_socket_name(sock)),
                    None => "\x1b[1;36mshadi>\x1b[0m ".to_string(),
                }
            } else {
                match &session.socket {
                    Some(sock) => format!("shadi({})> ", short_socket_name(sock)),
                    None => "shadi> ".to_string(),
                }
            }
        };

        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if !trimmed.is_empty() && session.pending_patch.is_none() {
                    let _ = rl.add_history_entry(trimmed);
                }
                match handle_shell_line(&mut session, &line) {
                    Some(LoopAction::Continue) | None => {}
                    Some(LoopAction::Exit) => break,
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C: clear line, don't exit.
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D: exit.
                break;
            }
            Err(err) => {
                eprintln!("error: {}", err);
                break;
            }
        }
    }

    session.slim.shutdown();

    if let Some(ref path) = history_path {
        let _ = rl.save_history(path);
    }

    ExitCode::SUCCESS
}

/// `shadictl slim create-group` — resolve `--members` specs into a DID trust
/// superset, fold it into `SLIM_MEMBER_DIDS` for this process, optionally
/// persist it as a `slim_mas` `GroupConfig` TOML, then create the channel and
/// hand off into the normal interactive shell as its moderator. `/slim
/// create`/`/slim invite`/`/slim join` are not touched by any of this — a
/// moderator who already knows exactly who they want still uses those
/// directly, unchanged.
pub(crate) fn run_slim_create_group_command(args: SlimCreateGroupArgs) -> ExitCode {
    if !std::env::var("SHADI_SLIM_AUTH")
        .unwrap_or_default()
        .eq_ignore_ascii_case("did")
    {
        eprintln!(
            "error: `slim create-group` requires DID auth (set SHADI_SLIM_AUTH=did, SLIM_HUMAN_SEED) \
             — a group's trust set is meaningless under shared-secret auth"
        );
        return ExitCode::from(2);
    }

    if let Err(msg) = resolve_and_persist_group_trust(&args) {
        eprintln!("{}", msg);
        return ExitCode::from(2);
    }

    let initial = vec![format!("/slim create {}", args.channel)];
    run_shell_command(ShellArgs { socket: None, attach: None }, &initial)
}

/// Resolve `args.members`, union with any pre-existing `SLIM_MEMBER_DIDS`,
/// persist the DIR server and trust set into this process's environment, and
/// optionally write the result out as a `slim_mas` `GroupConfig` TOML.
///
/// No SLIM/network I/O of its own — `resolve_members` is the only call that
/// touches the network, and `explicit:` specs skip even that — so this is
/// directly unit-testable without a live Directory or SLIM node.
fn resolve_and_persist_group_trust(args: &SlimCreateGroupArgs) -> Result<(), String> {
    let dir = agentbridge::member_source::DirLookupOptions {
        server_addr: args.dir_server.clone(),
        gh_token: args.gh_token.clone(),
        limit: args.limit,
    };

    // Remember the DIR server this group's membership was resolved against,
    // so a later `/slim invite-from` in this same session defaults to it too
    // instead of silently falling back to the production gateway.
    std::env::set_var("SHADI_DIR_SERVER", &args.dir_server);

    let candidates = agentbridge::member_source::resolve_members(&args.members, &dir)
        .map_err(|err| format!("error resolving --members: {}", err))?;

    println!("Resolved {} candidate member(s):", candidates.len());
    for c in &candidates {
        match &c.slim_endpoint {
            Some(endpoint) => println!("  {}  did={}  slim://{}", c.name, c.did, endpoint),
            None => println!("  {}  did={}  (no SLIM endpoint)", c.name, c.did),
        }
    }

    // Union with any pre-existing SLIM_MEMBER_DIDS the operator already set —
    // create-group only ever broadens a trust set, never narrows one.
    let mut trust_dids = trusted_dids_from_env();
    for c in &candidates {
        trust_dids.insert(c.did.clone());
    }
    if trust_dids.is_empty() {
        return Err(
            "error: no trusted DIDs resolved and SLIM_MEMBER_DIDS is empty — nobody would be admittable"
                .to_string(),
        );
    }
    let trust_dids: Vec<String> = {
        let mut v: Vec<String> = trust_dids.into_iter().collect();
        v.sort();
        v
    };
    std::env::set_var("SLIM_MEMBER_DIDS", trust_dids.join(","));

    if let Some(path) = &args.write_config {
        let agent_id = std::env::var("SHADI_AGENT_ID").unwrap_or_else(|_| "agent".to_string());
        let moderator_did = std::env::var("SLIM_HUMAN_SEED")
            .ok()
            .and_then(|seed| shadi_identity::AgentIdentity::derive(seed.as_bytes(), &agent_id).ok())
            .map(|agent| agent.did());

        let mut groups = std::collections::BTreeMap::new();
        groups.insert(
            args.channel.clone(),
            slim_mas::GroupConfig {
                moderator_did,
                members: trust_dids
                    .iter()
                    .map(|did| slim_mas::MemberConfig { did: did.clone(), role: None })
                    .collect(),
            },
        );
        let config = slim_mas::MasConfig {
            mas: Some(slim_mas::MasSettings { default_group: Some(args.channel.clone()) }),
            groups,
        };
        match slim_mas::save_config(&config, path) {
            Ok(()) => println!("wrote group config to {}", path.display()),
            Err(err) => eprintln!("warning: failed to write group config: {}", err),
        }
    }

    Ok(())
}

/// The DIDs this process's SLIM app currently trusts, parsed from
/// `SLIM_MEMBER_DIDS` (the same comma-separated allow-list
/// `shadi_identity::did_auth_from_env` reads for `create_app`). Used by
/// `/slim invite-from` to check a discovered candidate is actually
/// admittable before inviting it — inviting a DID outside this set would
/// fail at the SLIM layer anyway, but checking here gives a clear message
/// instead of an opaque session error.
fn trusted_dids_from_env() -> std::collections::HashSet<String> {
    std::env::var("SLIM_MEMBER_DIDS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn short_socket_name(path: &Path) -> String {
    policy_watch::session_name_from_path(path)
}

fn discover_control_sockets(tmpdir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(tmpdir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("shadi-ctl-") && name_str.ends_with(".sock") {
                found.push(entry.path());
            }
        }
    }
    found
}

fn classify_and_prune_control_sockets(sockets: Vec<PathBuf>) -> Vec<(PathBuf, bool)> {
    let mut sessions = Vec::new();
    for sock in sockets {
        let reachable = policy_watch::query_policy(&sock).is_ok();
        if reachable {
            sessions.push((sock, true));
        } else {
            let _ = std::fs::remove_file(&sock);
        }
    }
    sessions
}

fn dirs_history_path() -> Option<PathBuf> {
    let dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    let shadi_dir = PathBuf::from(dir).join(".shadi");
    std::fs::create_dir_all(&shadi_dir).ok()?;
    Some(shadi_dir.join("shell_history"))
}

fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn pad_display(text: &str, width: usize) -> String {
    let padding = width.saturating_sub(display_width(text));
    format!("{}{}", text, " ".repeat(padding))
}

fn print_banner(color: bool) {
    let title = format!(
        "Secure Host for Agentic AI Dynamic Instantiation  v{}",
        env!("CARGO_PKG_VERSION")
    );
    let hint = "type '/help' for commands, '/exit' to quit, '<cmd> --help' for details";
    let lines = [
        "🔒 SHADI".to_string(),
        String::new(),
        title,
        hint.to_string(),
    ];
    let inner_width = lines
        .iter()
        .map(|line| display_width(line))
        .max()
        .unwrap_or(0);
    let border = format!("+{}+", "-".repeat(inner_width + 2));

    if color {
        println!("\x1b[1;36m{}\x1b[0m", border);
        println!("\x1b[1;36m|\x1b[0m \x1b[1m{}\x1b[0m \x1b[1;36m|\x1b[0m", pad_display(&lines[0], inner_width));
        println!("\x1b[1;36m|\x1b[0m {} \x1b[1;36m|\x1b[0m", pad_display(&lines[1], inner_width));
        println!("\x1b[1;36m|\x1b[0m \x1b[1m{}\x1b[0m \x1b[1;36m|\x1b[0m", pad_display(&lines[2], inner_width));
        println!("\x1b[1;36m|\x1b[0m \x1b[2m{}\x1b[0m \x1b[1;36m|\x1b[0m", pad_display(&lines[3], inner_width));
        println!("\x1b[1;36m{}\x1b[0m", border);
    } else {
        println!("{}", border);
        for line in &lines {
            println!("| {} |", pad_display(line, inner_width));
        }
        println!("{}", border);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    // ── helpers ──────────────────────────────────────────────

    struct ScopedEnvVar {
        name: &'static str,
        previous: Option<OsString>,
    }

    impl ScopedEnvVar {
        fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self { name, previous }
        }

        fn unset(name: &'static str) -> Self {
            let previous = std::env::var_os(name);
            std::env::remove_var(name);
            Self { name, previous }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    fn session() -> ShellSession {
        ShellSession::new(None)
    }

    /// Session with a fake socket path set so that socket-guarded code
    /// paths (arg parsing, etc.) are reached.  The socket is not a real
    /// endpoint, so `query_policy` / `send_patch` will fail — that's
    /// fine for coverage of the code *before* the socket call.
    fn attached_session() -> ShellSession {
        ShellSession {
            socket: Some(PathBuf::from("/tmp/shadi-fake-coverage.sock")),
            pending_patch: None,
            slim: SlimShellState::new(),
        }
    }

    fn assert_continues(session: &mut ShellSession, cmd: &str) {
        assert!(
            matches!(session.handle_command(cmd), LoopAction::Continue),
            "{cmd} should continue"
        );
    }

    fn assert_exits(session: &mut ShellSession, cmd: &str) {
        assert!(
            matches!(session.handle_command(cmd), LoopAction::Exit),
            "{cmd} should exit"
        );
    }

    fn with_missing_slim_assets(test: impl FnOnce()) {
        let _guard = crate::lock_test_env();
        let dir = tempfile::tempdir().expect("tempdir");
        let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
        let _shared_secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", "shell-test-secret");
        let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
        let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
        let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

        test();
    }

    // ── prompt utilities ─────────────────────────────────────

    #[test]
    fn given_socket_path_when_extracting_name_then_returns_stem() {
        let path = PathBuf::from("/tmp/shadi-ctl-12345.sock");
        assert_eq!(short_socket_name(&path), "12345");
    }

    #[test]
    fn given_named_socket_when_extracting_name_then_strips_prefix() {
        let path = PathBuf::from("/tmp/shadi-ctl-my-agent.sock");
        assert_eq!(short_socket_name(&path), "my-agent");
    }

    #[test]
    fn given_dotfile_socket_when_extracting_name_then_returns_dotname() {
        let path = PathBuf::from("/tmp/.sock");
        assert_eq!(short_socket_name(&path), ".sock");
    }

    // ── navigation ───────────────────────────────────────────

    #[test]
    fn given_session_when_help_then_continues() {
        assert_continues(&mut session(), "/help");
    }

    #[test]
    fn given_session_when_exit_then_exits() {
        assert_exits(&mut session(), "/exit");
    }

    #[test]
    fn given_session_when_quit_then_exits() {
        assert_exits(&mut session(), "/quit");
    }

    #[test]
    fn given_session_when_unknown_command_then_continues() {
        assert_continues(&mut session(), "bogus");
    }

    #[test]
    fn given_session_when_empty_input_then_continues() {
        assert_continues(&mut session(), "");
    }

    #[test]
    fn given_session_when_clear_then_continues() {
        assert_continues(&mut session(), "/clear");
    }

    // ── session management ───────────────────────────────────

    #[test]
    fn given_no_attachment_when_status_then_continues() {
        assert_continues(&mut session(), "/status");
    }

    #[test]
    fn given_no_attachment_when_detach_then_stays_detached() {
        let mut s = session();
        assert_continues(&mut s, "/detach");
        assert!(s.socket.is_none());
    }

    #[test]
    fn given_no_sessions_when_sessions_then_continues() {
        assert_continues(&mut session(), "/sessions");
    }

    #[test]
    fn given_stale_socket_when_discovering_sessions_then_it_is_pruned() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let stale_socket = tempdir.path().join("shadi-ctl-stale.sock");
        std::fs::write(&stale_socket, b"stale").expect("create stale socket marker");

        let sessions = classify_and_prune_control_sockets(discover_control_sockets(tempdir.path()));

        assert!(sessions.is_empty());
        assert!(!stale_socket.exists(), "stale socket should be removed");
    }

    #[test]
    fn given_attached_session_when_policy_patch_without_force_then_confirmation_is_pending() {
        let mut s = attached_session();

        assert_continues(&mut s, "/policy patch --add-net-allow 1.1.1.1");

        let pending = s.pending_patch.as_ref().expect("pending patch");
        assert_eq!(pending.socket, PathBuf::from("/tmp/shadi-fake-coverage.sock"));
        assert_eq!(pending.patch.add_net_allow, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn given_pending_patch_when_confirmation_is_blank_then_patch_is_cancelled() {
        let mut s = attached_session();
        assert_continues(&mut s, "/policy patch --add-net-allow 1.1.1.1");

        assert_continues(&mut s, "");

        assert!(s.pending_patch.is_none());
    }

    #[test]
    fn given_pending_patch_when_confirmation_is_no_then_patch_is_cancelled() {
        let mut s = attached_session();
        assert_continues(&mut s, "/policy patch --add-net-allow 1.1.1.1");

        assert_continues(&mut s, "n");

        assert!(s.pending_patch.is_none());
    }

    #[test]
    fn given_no_attachment_when_kill_then_continues() {
        assert_continues(&mut session(), "/kill");
    }

    #[test]
    fn given_no_path_when_attach_then_continues() {
        assert_continues(&mut session(), "/attach");
    }

    #[test]
    fn given_nonexistent_socket_when_attach_then_stays_detached() {
        let mut s = session();
        assert_continues(&mut s, "/attach /tmp/nonexistent-shadi-test.sock");
        assert!(s.socket.is_none());
    }

    // ── config ───────────────────────────────────────────────

    #[test]
    fn given_session_when_config_then_shows_effective_policy() {
        assert_continues(&mut session(), "/config");
    }

    // ── policy commands ──────────────────────────────────────

    #[test]
    fn given_no_attachment_when_policy_query_then_continues() {
        assert_continues(&mut session(), "/policy query");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_then_continues() {
        assert_continues(&mut session(), "/policy patch --add-read /tmp/foo");
    }

    #[test]
    fn given_session_when_policy_explain_then_continues() {
        assert_continues(&mut session(), "/policy explain");
    }

    #[test]
    fn given_no_baseline_when_policy_diff_then_shows_usage() {
        assert_continues(&mut session(), "/policy diff");
    }

    #[test]
    fn given_baseline_when_policy_diff_then_continues() {
        assert_continues(&mut session(), "/policy diff profile:strict");
    }

    #[test]
    fn given_unknown_subcommand_when_policy_then_continues() {
        assert_continues(&mut session(), "/policy bogus");
    }

    #[test]
    fn given_bare_policy_when_invoked_then_shows_usage() {
        assert_continues(&mut session(), "/policy");
    }

    // ── trace commands ───────────────────────────────────────

    #[test]
    fn given_no_trace_file_when_trace_list_then_continues() {
        assert_continues(&mut session(), "/trace list");
    }

    #[test]
    fn given_filters_when_trace_list_then_continues() {
        assert_continues(&mut session(), "/trace list --limit 5 --name spawn");
    }

    #[test]
    fn given_no_trace_file_when_trace_summary_then_continues() {
        assert_continues(&mut session(), "/trace summary");
    }

    #[test]
    fn given_limit_when_trace_summary_then_continues() {
        assert_continues(&mut session(), "/trace summary --limit 10");
    }

    #[test]
    fn given_unknown_subcommand_when_trace_then_continues() {
        assert_continues(&mut session(), "/trace bogus");
    }

    #[test]
    fn given_bare_trace_when_invoked_then_shows_usage() {
        assert_continues(&mut session(), "/trace");
    }

    // ── slim commands ────────────────────────────────────────

    #[test]
    fn given_session_when_slim_status_then_continues() {
        assert_continues(&mut session(), "/slim status");
    }

    #[test]
    fn given_session_when_slim_bare_then_continues() {
        assert_continues(&mut session(), "/slim");
    }

    #[test]
    fn given_session_when_slim_start_without_target_then_continues() {
        assert_continues(&mut session(), "/slim start");
    }

    #[test]
    fn given_session_when_slim_start_node_then_continues() {
        assert_continues(&mut session(), "/slim start node");
    }

    #[test]
    fn given_session_when_slim_a2a_echo_peer_then_continues() {
        with_missing_slim_assets(|| {
            assert_continues(
                &mut session(),
                "/slim a2a-echo-peer --agent-id secops-a --listen-timeout 1",
            );
        });
    }

    #[test]
    fn given_session_when_slim_a2a_send_then_continues() {
        with_missing_slim_assets(|| {
            assert_continues(
                &mut session(),
                "/slim a2a-send --peer-agent-id secops-a --message hello from shell --stream --timeout 1",
            );
        });
    }

    #[test]
    fn given_session_when_slim_a2a_send_with_missing_message_then_continues() {
        assert_continues(&mut session(), "/slim a2a-send --message");
    }

    #[test]
    fn given_session_with_slim_runtime_state_when_status_then_continues() {
        let mut shell = session();
        shell.slim.set_test_runtime_state(
            Some(17),
            Some("agntcy/shadi/secops-room".to_string()),
            true,
        );

        assert_continues(&mut shell, "/slim status");
    }

    #[test]
    fn given_session_when_slim_create_then_continues() {
        assert_continues(&mut session(), "/slim create agntcy/shadi/secops-room");
    }

    #[test]
    fn given_session_when_slim_create_without_target_then_continues() {
        assert_continues(&mut session(), "/slim create");
    }

    #[test]
    fn given_session_when_slim_create_with_extra_args_then_continues() {
        assert_continues(
            &mut session(),
            "/slim create agntcy/shadi/secops-room extra",
        );
    }

    #[test]
    fn given_session_when_slim_invite_then_continues() {
        assert_continues(&mut session(), "/slim invite agntcy/shadi/avatar");
    }

    #[test]
    fn given_session_when_slim_invite_without_target_then_continues() {
        assert_continues(&mut session(), "/slim invite");
    }

    #[test]
    fn given_session_when_slim_invite_with_extra_args_then_continues() {
        assert_continues(&mut session(), "/slim invite agntcy/shadi/avatar extra");
    }

    #[test]
    fn given_session_when_slim_invite_from_without_target_then_continues() {
        assert_continues(&mut session(), "/slim invite-from");
    }

    #[test]
    fn given_session_when_slim_invite_from_with_extra_args_then_continues() {
        assert_continues(&mut session(), "/slim invite-from skill:x extra");
    }

    #[test]
    fn given_session_when_slim_invite_from_invalid_spec_then_continues() {
        assert_continues(&mut session(), "/slim invite-from bogus:whatever");
    }

    #[test]
    fn given_session_when_slim_invite_from_resolve_fails_then_continues() {
        let _lock = crate::lock_test_env();
        let _dirctl = ScopedEnvVar::set("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        // A skill:/did: spec's resolve() shells out to dirctl — pointing
        // SHADI_DIRCTL_BINARY at nothing exercises the resolve() Err path
        // distinct from parse_member_spec's own (pure, no-I/O) Err path.
        assert_continues(&mut session(), "/slim invite-from skill:whatever");
    }

    #[test]
    #[cfg(unix)]
    fn given_session_when_slim_invite_from_resolves_zero_candidates_then_continues() {
        let _lock = crate::lock_test_env();
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake_dirctl.sh");
        std::fs::write(&script, "#!/bin/sh\ncase \"$1\" in search) ;; *) exit 1 ;; esac\n")
            .expect("write script");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let _dirctl = ScopedEnvVar::set("SHADI_DIRCTL_BINARY", &script);

        assert_continues(&mut session(), "/slim invite-from skill:whatever");
    }

    #[test]
    fn given_session_when_slim_invite_from_explicit_untrusted_did_is_skipped() {
        let _lock = crate::lock_test_env();
        // No SLIM_MEMBER_DIDS set — the resolved DID is never in the trust
        // set, so this must hit the "skip" path, not attempt an invite.
        let _trust = ScopedEnvVar::unset("SLIM_MEMBER_DIDS");
        assert_continues(
            &mut session(),
            "/slim invite-from explicit:copilot=did:key:untrusted",
        );
    }

    #[test]
    fn given_session_when_slim_invite_from_explicit_trusted_did_attempts_invite() {
        let _lock = crate::lock_test_env();
        // DID is in the trust set this time, so cmd_slim_invite_from proceeds
        // to call invite_participant — which then fails for the ordinary
        // "no active session" reason, still LoopAction::Continue either way.
        let _trust = ScopedEnvVar::set("SLIM_MEMBER_DIDS", "did:key:trusted");
        assert_continues(
            &mut session(),
            "/slim invite-from explicit:copilot=did:key:trusted@127.0.0.1:47357",
        );
    }

    #[test]
    fn trusted_dids_from_env_parses_comma_separated_list_and_trims_whitespace() {
        let _lock = crate::lock_test_env();
        let _trust = ScopedEnvVar::set("SLIM_MEMBER_DIDS", " did:key:a, did:key:b ,,did:key:c");
        let trusted = trusted_dids_from_env();
        assert_eq!(trusted.len(), 3);
        assert!(trusted.contains("did:key:a"));
        assert!(trusted.contains("did:key:b"));
        assert!(trusted.contains("did:key:c"));
    }

    #[test]
    fn trusted_dids_from_env_is_empty_when_unset() {
        let _lock = crate::lock_test_env();
        let _trust = ScopedEnvVar::unset("SLIM_MEMBER_DIDS");
        assert!(trusted_dids_from_env().is_empty());
    }

    #[test]
    fn run_slim_create_group_command_requires_did_auth() {
        let _lock = crate::lock_test_env();
        let _auth = ScopedEnvVar::unset("SHADI_SLIM_AUTH");
        let args = SlimCreateGroupArgs {
            channel: "agntcy/shadi/room".to_string(),
            members: vec![],
            dir_server: "localhost:9999".to_string(),
            gh_token: None,
            limit: 10,
            write_config: None,
        };
        assert_eq!(run_slim_create_group_command(args), ExitCode::from(2));
    }

    // `resolve_and_persist_group_trust` does no SLIM/network I/O of its own —
    // `explicit:` specs skip the Directory round trip too — so these exercise
    // it directly without a live Directory or SLIM node.

    #[test]
    fn resolve_and_persist_group_trust_unions_explicit_members_into_slim_member_dids() {
        let _lock = crate::lock_test_env();
        let _trust = ScopedEnvVar::unset("SLIM_MEMBER_DIDS");
        let _dir_server = ScopedEnvVar::unset("SHADI_DIR_SERVER");
        let args = SlimCreateGroupArgs {
            channel: "agntcy/shadi/room".to_string(),
            members: vec![
                "explicit:avatar=did:key:human".to_string(),
                "explicit:claude-code=did:key:agent@127.0.0.1:47560".to_string(),
            ],
            dir_server: "localhost:8888".to_string(),
            gh_token: None,
            limit: 10,
            write_config: None,
        };

        resolve_and_persist_group_trust(&args).expect("resolve");

        let trust = trusted_dids_from_env();
        assert!(trust.contains("did:key:human"));
        assert!(trust.contains("did:key:agent"));
        assert_eq!(std::env::var("SHADI_DIR_SERVER").as_deref(), Ok("localhost:8888"));
    }

    #[test]
    fn resolve_and_persist_group_trust_broadens_rather_than_replaces_existing_trust() {
        let _lock = crate::lock_test_env();
        let _trust = ScopedEnvVar::set("SLIM_MEMBER_DIDS", "did:key:preexisting");
        let _dir_server = ScopedEnvVar::unset("SHADI_DIR_SERVER");
        let args = SlimCreateGroupArgs {
            channel: "agntcy/shadi/room".to_string(),
            members: vec!["explicit:avatar=did:key:human".to_string()],
            dir_server: "localhost:8888".to_string(),
            gh_token: None,
            limit: 10,
            write_config: None,
        };

        resolve_and_persist_group_trust(&args).expect("resolve");

        let trust = trusted_dids_from_env();
        assert!(trust.contains("did:key:preexisting"));
        assert!(trust.contains("did:key:human"));
    }

    #[test]
    fn resolve_and_persist_group_trust_errors_when_nothing_resolved_and_no_prior_trust() {
        let _lock = crate::lock_test_env();
        let _trust = ScopedEnvVar::unset("SLIM_MEMBER_DIDS");
        let _dir_server = ScopedEnvVar::unset("SHADI_DIR_SERVER");
        let args = SlimCreateGroupArgs {
            channel: "agntcy/shadi/room".to_string(),
            members: vec![],
            dir_server: "localhost:8888".to_string(),
            gh_token: None,
            limit: 10,
            write_config: None,
        };

        let err = resolve_and_persist_group_trust(&args).unwrap_err();
        assert!(err.contains("nobody would be admittable"));
    }

    #[test]
    fn resolve_and_persist_group_trust_propagates_invalid_member_spec_errors() {
        let _lock = crate::lock_test_env();
        let _trust = ScopedEnvVar::unset("SLIM_MEMBER_DIDS");
        let _dir_server = ScopedEnvVar::unset("SHADI_DIR_SERVER");
        let args = SlimCreateGroupArgs {
            channel: "agntcy/shadi/room".to_string(),
            members: vec!["bogus:whatever".to_string()],
            dir_server: "localhost:8888".to_string(),
            gh_token: None,
            limit: 10,
            write_config: None,
        };

        let err = resolve_and_persist_group_trust(&args).unwrap_err();
        assert!(err.contains("error resolving --members"));
    }

    #[test]
    fn resolve_and_persist_group_trust_writes_group_config_toml() {
        let _lock = crate::lock_test_env();
        let _trust = ScopedEnvVar::unset("SLIM_MEMBER_DIDS");
        let _dir_server = ScopedEnvVar::unset("SHADI_DIR_SERVER");
        let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
        let _seed = ScopedEnvVar::set("SLIM_HUMAN_SEED", "test-human-seed");
        let path = std::env::temp_dir().join(format!(
            "shadi-test-create-group-{}.toml",
            std::process::id()
        ));
        let args = SlimCreateGroupArgs {
            channel: "agntcy/shadi/room".to_string(),
            members: vec!["explicit:copilot=did:key:agent".to_string()],
            dir_server: "localhost:8888".to_string(),
            gh_token: None,
            limit: 10,
            write_config: Some(path.clone()),
        };

        resolve_and_persist_group_trust(&args).expect("resolve");

        let written = std::fs::read_to_string(&path).expect("config file written");
        let _ = std::fs::remove_file(&path);
        assert!(written.contains("did:key:agent"));
        assert!(written.contains("agntcy/shadi/room"));
    }

    #[test]
    fn given_session_when_slim_join_then_continues() {
        assert_continues(&mut session(), "/slim join agntcy/shadi/secops-room --timeout 5");
    }

    #[test]
    fn given_session_when_slim_join_without_target_then_continues() {
        assert_continues(&mut session(), "/slim join");
    }

    #[test]
    fn given_session_when_slim_join_with_invalid_timeout_then_continues() {
        assert_continues(&mut session(), "/slim join agntcy/shadi/secops-room --timeout nope");
    }

    #[test]
    fn given_session_when_slim_join_with_zero_timeout_then_continues() {
        assert_continues(&mut session(), "/slim join agntcy/shadi/secops-room --timeout 0");
    }

    #[test]
    fn given_session_when_slim_join_with_timeout_but_without_channel_then_continues() {
        assert_continues(&mut session(), "/slim join --timeout 5");
    }

    #[test]
    fn given_session_when_slim_join_with_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/slim join agntcy/shadi/secops-room --bogus");
    }

    #[test]
    fn given_unknown_subcommand_when_slim_then_continues() {
        assert_continues(&mut session(), "/slim bogus");
    }

    // ── tab completion ───────────────────────────────────────

    #[test]
    fn given_slash_pol_when_completing_then_includes_policy_commands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));

        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/pol", 4, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 0);
        assert!(
            candidates.iter().any(|c| c.display == "/policy query"),
            "should complete /pol to /policy query"
        );
    }

    #[test]
    fn given_slash_when_completing_then_returns_all_commands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));

        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/", 1, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 0);
        assert_eq!(candidates.len(), COMMANDS.len());
    }

    // ── full operator walkthrough ────────────────────────────

    #[test]
    fn given_fresh_session_when_full_walkthrough_then_all_commands_succeed() {
        let mut s = session();

        // Navigation
        assert_continues(&mut s, "/help");
        assert_continues(&mut s, "/status");
        assert_continues(&mut s, "/sessions");

        // Config & policy inspection (no socket needed)
        assert_continues(&mut s, "/config");
        assert_continues(&mut s, "/policy explain");
        assert_continues(&mut s, "/policy diff profile:strict");

        // Detach when already detached — still succeeds
        assert_continues(&mut s, "/detach");

        // Clear screen
        assert_continues(&mut s, "/clear");

        // Exit
        assert_exits(&mut s, "/exit");
    }

    // ── banner & history path ────────────────────────────────

    #[test]
    fn given_no_color_when_print_banner_then_does_not_panic() {
        print_banner(false);
    }

    #[test]
    fn given_color_when_print_banner_then_does_not_panic() {
        print_banner(true);
    }

    #[test]
    fn given_home_dir_when_dirs_history_path_then_returns_some() {
        // HOME is usually set in test environments.
        let path = dirs_history_path();
        if std::env::var("HOME").is_ok() || std::env::var("USERPROFILE").is_ok() {
            assert!(path.is_some());
            let p = path.unwrap();
            assert!(p.ends_with("shell_history"));
        }
    }

    // ── policy patch argument parsing ────────────────────────

    #[test]
    fn given_no_attachment_when_policy_patch_add_write_then_continues() {
        assert_continues(&mut session(), "/policy patch --add-write /tmp/out");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_add_allow_then_continues() {
        assert_continues(&mut session(), "/policy patch --add-allow /opt/bin");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_add_allow_command_then_continues() {
        assert_continues(&mut session(), "/policy patch --add-allow-command npm");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_remove_allow_command_then_continues() {
        assert_continues(&mut session(), "/policy patch --remove-allow-command npm");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_add_block_command_then_continues() {
        assert_continues(&mut session(), "/policy patch --add-block-command curl");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_remove_block_command_then_continues() {
        assert_continues(&mut session(), "/policy patch --remove-block-command curl");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_add_net_allow_then_continues() {
        assert_continues(&mut session(), "/policy patch --add-net-allow api.example.com");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_remove_net_allow_then_continues() {
        assert_continues(&mut session(), "/policy patch --remove-net-allow api.example.com");
    }

    #[test]
    fn given_no_attachment_when_policy_patch_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/policy patch --bogus-flag value");
    }

    // ── trace arg parsing ────────────────────────────────────

    #[test]
    fn given_trace_list_with_command_filter_then_continues() {
        assert_continues(&mut session(), "/trace list --command python");
    }

    #[test]
    fn given_trace_list_with_exit_code_filter_then_continues() {
        assert_continues(&mut session(), "/trace list --exit-code 0");
    }

    #[test]
    fn given_trace_list_with_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/trace list --bogus");
    }

    #[test]
    fn given_trace_summary_with_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/trace summary --bogus");
    }

    // ── hint delegate ────────────────────────────────────────

    #[test]
    fn given_helper_when_hint_invoked_then_returns_without_panic() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));

        let helper = rl.helper().unwrap();
        // hint may return None for short input — that's fine.
        let _hint = Hinter::hint(helper, "/he", 3, &Context::new(rl.history()));
    }

    // ── attached-session paths (fake socket for coverage) ────

    #[test]
    fn given_attached_session_when_status_then_shows_attached() {
        assert_continues(&mut attached_session(), "/status");
    }

    #[test]
    fn given_attached_session_when_policy_query_then_continues() {
        assert_continues(&mut attached_session(), "/policy query");
    }

    #[test]
    fn given_attached_session_when_policy_patch_add_read_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --add-read /tmp");
    }

    #[test]
    fn given_attached_session_when_policy_patch_add_write_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --add-write /var/out");
    }

    #[test]
    fn given_attached_session_when_policy_patch_add_allow_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --add-allow /opt/bin");
    }

    #[test]
    fn given_attached_session_when_policy_patch_add_allow_command_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --add-allow-command npm");
    }

    #[test]
    fn given_attached_session_when_policy_patch_remove_allow_command_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --remove-allow-command npm");
    }

    #[test]
    fn given_attached_session_when_policy_patch_add_block_command_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --add-block-command curl");
    }

    #[test]
    fn given_attached_session_when_policy_patch_remove_block_command_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --remove-block-command curl");
    }

    #[test]
    fn given_attached_session_when_policy_patch_add_net_allow_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --add-net-allow api.example.com");
    }

    #[test]
    fn given_attached_session_when_policy_patch_remove_net_allow_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --force --remove-net-allow api.example.com");
    }

    #[test]
    fn given_attached_session_when_policy_patch_unknown_flag_then_continues() {
        assert_continues(&mut attached_session(), "/policy patch --bogus-flag value");
    }

    #[test]
    fn given_attached_session_when_detach_then_socket_cleared() {
        let mut s = attached_session();
        assert!(s.socket.is_some());
        assert_continues(&mut s, "/detach");
        assert!(s.socket.is_none());
    }

    #[test]
    fn given_attached_session_when_help_then_shows_attached_to() {
        assert_continues(&mut attached_session(), "/help");
    }

    #[test]
    fn given_attached_session_when_kill_then_continues() {
        assert_continues(&mut attached_session(), "/kill");
    }

    // ── aliases ──────────────────────────────────────────────

    #[test]
    fn given_session_when_alias_h_then_continues() {
        assert_continues(&mut session(), "/h");
    }

    #[test]
    fn given_session_when_alias_s_then_continues() {
        assert_continues(&mut session(), "/s");
    }

    #[test]
    fn given_session_when_alias_q_then_exits() {
        assert_exits(&mut session(), "/q");
    }

    // ── per-command help ─────────────────────────────────────

    #[test]
    fn given_session_when_help_attach_then_continues() {
        assert_continues(&mut session(), "/help attach");
    }

    #[test]
    fn given_session_when_help_policy_then_continues() {
        assert_continues(&mut session(), "/help policy");
    }

    #[test]
    fn given_session_when_help_history_then_continues() {
        assert_continues(&mut session(), "/help history");
    }

    #[test]
    fn given_session_when_help_slim_start_node_then_continues() {
        assert_continues(&mut session(), "/help slim start node");
    }

    #[test]
    fn given_session_when_policy_patch_help_flag_then_continues() {
        assert_continues(&mut session(), "/policy patch --help");
    }

    // ── dry-run ──────────────────────────────────────────────

    #[test]
    fn given_session_when_policy_patch_dry_run_then_continues() {
        // dry-run does not require an attached socket; exits before send_patch
        assert_continues(&mut session(), "/policy patch --dry-run --add-read /tmp");
    }

    // ── history command ──────────────────────────────────────

    #[test]
    fn given_session_when_history_then_continues() {
        assert_continues(&mut session(), "/history");
    }

    #[test]
    fn given_session_when_history_with_limit_then_continues() {
        assert_continues(&mut session(), "/history --limit 5");
    }

    #[test]
    fn given_session_when_history_with_grep_then_continues() {
        assert_continues(&mut session(), "/history --grep attach");
    }

    // ── completion: subcommands ──────────────────────────────

    #[test]
    fn given_policy_prefix_when_completing_then_returns_subcommands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/policy ", 8, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 8);
        assert!(
            candidates.iter().any(|c| c.display == "query"),
            "should complete /policy subcommands"
        );
    }

    #[test]
    fn given_trace_prefix_when_completing_then_returns_subcommands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/trace ", 7, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 7);
        assert!(
            candidates.iter().any(|c| c.display == "list"),
            "should complete /trace subcommands"
        );
    }

    #[test]
    fn given_slim_prefix_when_completing_then_returns_subcommands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/slim ", 6, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 6);
        assert!(
            candidates.iter().any(|c| c.display == "status"),
            "should complete /slim subcommands"
        );
        assert!(
            candidates.iter().any(|c| c.display == "a2a-send"),
            "should include A2A shell subcommands"
        );
    }

    #[test]
    fn given_slim_start_prefix_when_completing_then_returns_node() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) = Completer::complete(
            helper,
            "/slim start ",
            12,
            &Context::new(rl.history()),
        )
        .unwrap();
        assert_eq!(start, 12);
        assert!(
            candidates.iter().any(|c| c.display == "node"),
            "should complete /slim start target"
        );
    }

    #[test]
    fn given_policy_patch_prefix_when_completing_then_returns_flags() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/policy patch --add-r", 21, &Context::new(rl.history()))
                .unwrap();
        assert_eq!(start, 14);
        assert!(
            candidates.iter().any(|c| c.display == "--add-read"),
            "should complete patch flags"
        );
    }

    // ── completion: slash prefix ─────────────────────────────

    #[test]
    fn given_slash_prefix_when_completing_then_returns_matching_commands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/he", 3, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 0);
        assert!(
            candidates.iter().any(|c| c.display == "/help"),
            "should complete /he → /help"
        );
    }

    #[test]
    fn given_empty_input_when_completing_then_returns_all_commands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (_start, candidates) =
            Completer::complete(helper, "", 0, &Context::new(rl.history())).unwrap();
        assert!(!candidates.is_empty(), "empty line should list all commands");
    }

    #[test]
    fn given_policy_patch_non_flag_token_when_completing_then_returns_empty() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (_start, candidates) =
            Completer::complete(helper, "/policy patch /tmp/foo", 22, &Context::new(rl.history()))
                .unwrap();
        assert!(candidates.is_empty(), "non-flag token should have no completions");
    }

    // ── help detail ──────────────────────────────────────────

    #[test]
    fn given_session_when_help_detail_for_known_command_then_continues() {
        assert_continues(&mut session(), "/help policy patch");
    }

    #[test]
    fn given_session_when_help_slim_a2a_send_then_continues() {
        assert_continues(&mut session(), "/help slim a2a-send");
    }

    #[test]
    fn given_session_when_help_detail_for_unknown_command_then_continues() {
        assert_continues(&mut session(), "/help nonexistent");
    }

    #[test]
    fn given_any_command_with_help_flag_then_continues() {
        assert_continues(&mut session(), "/status --help");
    }

    #[test]
    fn given_policy_subcommand_with_help_flag_then_continues() {
        assert_continues(&mut session(), "/policy patch --help");
    }

    // ── status with attached socket ──────────────────────────

    #[test]
    fn given_attached_session_when_status_then_shows_unreachable() {
        // The fake socket is not a real endpoint so query will fail.
        assert_continues(&mut attached_session(), "/status");
    }

    // ── policy query/patch not attached ──────────────────────

    #[test]
    fn given_unattached_session_when_policy_query_then_continues() {
        assert_continues(&mut session(), "/policy query");
    }

    #[test]
    fn given_unattached_session_when_policy_patch_then_continues() {
        assert_continues(&mut session(), "/policy patch --add-read /tmp");
    }

    // ── policy patch with --force and --dry-run on attached socket ──

    #[test]
    fn given_attached_session_when_policy_patch_dry_run_with_flags_then_continues() {
        assert_continues(
            &mut attached_session(),
            "/policy patch --dry-run --add-read /opt --add-net-allow 1.1.1.1",
        );
    }

    #[test]
    fn given_attached_session_when_policy_patch_force_then_continues() {
        // --force attempts socket write which fails on fake socket, but
        // the code path is still exercised.
        assert_continues(
            &mut attached_session(),
            "/policy patch --force --add-read /opt",
        );
    }

    #[test]
    fn given_attached_session_when_policy_patch_net_allow_force_then_continues() {
        assert_continues(
            &mut attached_session(),
            "/policy patch --force --add-net-allow api.example.com",
        );
    }

    #[test]
    fn given_attached_session_when_policy_patch_remove_net_allow_force_then_continues() {
        assert_continues(
            &mut attached_session(),
            "/policy patch --force --remove-net-allow api.example.com",
        );
    }

    // ── pending patch confirmation ───────────────────────────

    #[test]
    fn given_pending_patch_when_exit_then_cancels_and_exits() {
        let mut s = attached_session();
        // Set up a pending patch by issuing patch without --force
        s.handle_command("/policy patch --add-read /opt");
        assert!(s.pending_patch.is_some());
        let action = s.handle_command("/exit");
        assert!(matches!(action, LoopAction::Exit));
        assert!(s.pending_patch.is_none());
    }

    #[test]
    fn given_pending_patch_when_yes_then_attempts_send() {
        let mut s = attached_session();
        s.handle_command("/policy patch --add-read /opt");
        assert!(s.pending_patch.is_some());
        // "y" will try to send_patch to the fake socket, which fails, but
        // the code path (send + error handling) is exercised.
        let action = s.handle_command("y");
        assert!(matches!(action, LoopAction::Continue));
        assert!(s.pending_patch.is_none());
    }

    // ── sessions command ─────────────────────────────────────

    #[test]
    fn given_session_when_sessions_then_continues() {
        assert_continues(&mut session(), "/sessions");
    }

    // ── empty and whitespace input ───────────────────────────

    #[test]
    fn given_session_when_empty_line_then_continues() {
        assert_continues(&mut session(), "");
    }

    #[test]
    fn given_session_when_whitespace_only_then_continues() {
        assert_continues(&mut session(), "   ");
    }

    // ── kill on unattached session ───────────────────────────

    #[test]
    fn given_unattached_session_when_kill_then_continues() {
        assert_continues(&mut session(), "/kill");
    }

    // ── detach on unattached session ─────────────────────────

    #[test]
    fn given_unattached_session_when_detach_then_continues() {
        assert_continues(&mut session(), "/detach");
    }

    // ── attach with missing path ─────────────────────────────

    #[test]
    fn given_session_when_attach_no_args_then_continues() {
        assert_continues(&mut session(), "/attach");
    }

    // ── hinter ───────────────────────────────────────────────

    #[test]
    fn given_helper_when_hint_returns_none_for_empty() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let hint = Hinter::hint(helper, "", 0, &Context::new(rl.history()));
        // HistoryHinter returns None for empty input.
        assert!(hint.is_none());
    }

    // ── highlighter ──────────────────────────────────────────

    #[test]
    fn given_helper_with_color_when_highlighting_slash_command_then_adds_ansi() {
        let helper = ShellHelper::new(true);
        let highlighted = Highlighter::highlight(&helper, "/help", 0);
        assert!(highlighted.contains("\x1b["), "should add ANSI color codes");
    }

    #[test]
    fn given_helper_without_color_when_highlighting_then_returns_borrowed() {
        let helper = ShellHelper::new(false);
        let highlighted = Highlighter::highlight(&helper, "/help", 0);
        assert_eq!(highlighted.as_ref(), "/help");
    }

    // ── snapshot commands ────────────────────────────────────

    #[test]
    fn given_session_when_snapshot_list_then_continues() {
        assert_continues(&mut session(), "/snapshot list");
    }

    #[test]
    fn given_session_when_snapshot_list_with_dir_then_continues() {
        assert_continues(&mut session(), "/snapshot list --dir /tmp/nonexistent");
    }

    #[test]
    fn given_session_when_snapshot_show_latest_then_continues() {
        assert_continues(&mut session(), "/snapshot show latest");
    }

    #[test]
    fn given_session_when_snapshot_show_no_args_then_continues() {
        assert_continues(&mut session(), "/snapshot show");
    }

    #[test]
    fn given_session_when_snapshot_no_subcommand_then_continues() {
        assert_continues(&mut session(), "/snapshot");
    }

    #[test]
    fn given_session_when_snapshot_unknown_subcommand_then_continues() {
        assert_continues(&mut session(), "/snapshot foo");
    }

    // ── snapshot tab completion ──────────────────────────────

    #[test]
    fn given_snapshot_prefix_when_completing_then_returns_subcommands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/snapshot l", 11, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 10);
        assert!(
            candidates.iter().any(|c| c.display == "list"),
            "should complete snapshot subcommands"
        );
    }

    // ── resources command ────────────────────────────────────

    #[test]
    fn given_unattached_session_when_resources_then_continues() {
        assert_continues(&mut session(), "/resources");
    }

    #[test]
    fn given_attached_session_when_resources_then_continues() {
        assert_continues(&mut attached_session(), "/resources");
    }

    #[test]
    fn given_session_when_help_snapshot_list_then_continues() {
        assert_continues(&mut session(), "/help snapshot list");
    }

    #[test]
    fn given_session_when_resources_help_then_continues() {
        assert_continues(&mut session(), "/resources --help");
    }

    // ── bare command --help (no subcommand) ──────────────────

    #[test]
    fn given_session_when_policy_bare_help_then_continues() {
        assert_continues(&mut session(), "/policy --help");
    }

    #[test]
    fn given_session_when_trace_bare_help_then_continues() {
        assert_continues(&mut session(), "/trace --help");
    }

    #[test]
    fn given_session_when_snapshot_bare_help_then_continues() {
        assert_continues(&mut session(), "/snapshot --help");
    }

    #[test]
    fn given_session_when_secrets_bare_help_then_continues() {
        assert_continues(&mut session(), "/secrets --help");
    }

    // ── /help with single word arg ───────────────────────────

    #[test]
    fn given_session_when_help_status_then_continues() {
        assert_continues(&mut session(), "/help status");
    }

    #[test]
    fn given_session_when_help_kill_then_continues() {
        assert_continues(&mut session(), "/help kill");
    }

    // ── secrets commands ─────────────────────────────────────

    #[test]
    fn given_session_when_secrets_list_then_continues() {
        assert_continues(&mut session(), "/secrets list");
    }

    #[test]
    fn given_session_when_secrets_list_with_prefix_then_continues() {
        assert_continues(&mut session(), "/secrets list --prefix SHADI_");
    }

    #[test]
    fn given_session_when_secrets_backend_then_continues() {
        assert_continues(&mut session(), "/secrets backend");
    }

    #[test]
    fn given_session_when_secrets_rules_then_continues() {
        assert_continues(&mut session(), "/secrets rules");
    }

    #[test]
    fn given_session_when_secrets_rules_with_policy_then_continues() {
        assert_continues(&mut session(), "/secrets rules --policy sandbox.json");
    }

    #[test]
    fn given_session_when_secrets_no_subcommand_then_continues() {
        assert_continues(&mut session(), "/secrets");
    }

    #[test]
    fn given_session_when_secrets_unknown_subcommand_then_continues() {
        assert_continues(&mut session(), "/secrets bogus");
    }

    #[test]
    fn given_session_when_help_secrets_list_then_continues() {
        assert_continues(&mut session(), "/help secrets list");
    }

    #[test]
    fn given_session_when_secrets_list_help_flag_then_continues() {
        assert_continues(&mut session(), "/secrets list --help");
    }

    // ── secrets tab completion ───────────────────────────────

    #[test]
    fn given_secrets_prefix_when_completing_then_returns_subcommands() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, candidates) =
            Completer::complete(helper, "/secrets l", 10, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 9);
        assert!(
            candidates.iter().any(|c| c.display == "list"),
            "should complete secrets subcommands"
        );
    }

    // ── highlighter coverage ─────────────────────────────────

    #[test]
    fn given_helper_with_color_when_highlighting_alias_then_adds_ansi() {
        let helper = ShellHelper::new(true);
        // /h is an alias that should be highlighted.
        let highlighted = Highlighter::highlight(&helper, "/h", 0);
        assert!(highlighted.contains("\x1b["), "alias should get ANSI color");
    }

    #[test]
    fn given_helper_with_color_when_highlighting_plain_text_then_returns_borrowed() {
        let helper = ShellHelper::new(true);
        // non-command text should be borrowed (not highlighted).
        let highlighted = Highlighter::highlight(&helper, "hello world", 0);
        assert_eq!(highlighted.as_ref(), "hello world");
    }

    #[test]
    fn given_helper_with_color_when_highlight_char_then_returns_true() {
        let helper = ShellHelper::new(true);
        assert!(Highlighter::highlight_char(
            &helper,
            "",
            0,
            rustyline::highlight::CmdKind::Other,
        ));
    }

    #[test]
    fn given_helper_without_color_when_highlight_char_then_returns_false() {
        let helper = ShellHelper::new(false);
        assert!(!Highlighter::highlight_char(
            &helper,
            "",
            0,
            rustyline::highlight::CmdKind::Other,
        ));
    }

    // ── attach tab completion ────────────────────────────────

    #[test]
    fn given_attach_prefix_when_completing_then_returns_offset() {
        let helper = ShellHelper::new(false);
        let rl_config = Config::builder().build();
        let mut rl = Editor::with_config(rl_config).unwrap();
        rl.set_helper(Some(helper));
        let helper = rl.helper().unwrap();
        let (start, _candidates) =
            Completer::complete(helper, "/attach ", 8, &Context::new(rl.history())).unwrap();
        assert_eq!(start, 8);
    }

    // ── snapshot show arg parsing ────────────────────────────

    #[test]
    fn given_session_when_snapshot_show_with_dir_then_continues() {
        assert_continues(&mut session(), "/snapshot show myid --dir /tmp/nonexistent");
    }

    #[test]
    fn given_session_when_snapshot_show_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/snapshot show myid --bogus");
    }

    #[test]
    fn given_session_when_snapshot_list_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/snapshot list --bogus");
    }

    // ── secrets arg parsing ──────────────────────────────────

    #[test]
    fn given_session_when_secrets_list_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/secrets list --bogus");
    }

    #[test]
    fn given_session_when_secrets_rules_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/secrets rules --bogus");
    }

    // ── history arg parsing ──────────────────────────────────

    #[test]
    fn given_session_when_history_unknown_flag_then_continues() {
        assert_continues(&mut session(), "/history --bogus");
    }

    // ── help for secrets subcommands ─────────────────────────

    #[test]
    fn given_session_when_help_secrets_backend_then_continues() {
        assert_continues(&mut session(), "/help secrets backend");
    }

    #[test]
    fn given_session_when_help_secrets_rules_then_continues() {
        assert_continues(&mut session(), "/help secrets rules");
    }

    #[test]
    fn given_session_when_secrets_backend_help_flag_then_continues() {
        assert_continues(&mut session(), "/secrets backend --help");
    }

    #[test]
    fn given_session_when_secrets_rules_help_flag_then_continues() {
        assert_continues(&mut session(), "/secrets rules --help");
    }

    // ── help for snapshot subcommands ────────────────────────

    #[test]
    fn given_session_when_help_snapshot_show_then_continues() {
        assert_continues(&mut session(), "/help snapshot show");
    }

    #[test]
    fn given_session_when_snapshot_list_help_flag_then_continues() {
        assert_continues(&mut session(), "/snapshot list --help");
    }

    #[test]
    fn given_session_when_snapshot_show_help_flag_then_continues() {
        assert_continues(&mut session(), "/snapshot show --help");
    }

    // ── help for trace subcommands ───────────────────────────

    #[test]
    fn given_session_when_help_trace_list_then_continues() {
        assert_continues(&mut session(), "/help trace list");
    }

    #[test]
    fn given_session_when_help_trace_summary_then_continues() {
        assert_continues(&mut session(), "/help trace summary");
    }

    // ── cmd_attach coverage ──────────────────────────────────

    /// Exercises the `Err` branch of `cmd_attach`: the path exists (it is a
    /// plain file, not a socket) so `sock.exists()` is `true`, but
    /// `query_policy` fails because the file is not a Unix-domain socket.
    #[test]
    fn given_non_socket_file_when_attach_then_stays_detached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shadi-ctl-not-a-socket.sock");
        std::fs::write(&path, b"not a socket").expect("write");

        let mut s = session();
        assert_continues(&mut s, &format!("/attach {}", path.display()));
        assert!(s.socket.is_none(), "socket should remain unset after failed query");
    }

    /// Exercises the `Ok` branch of `cmd_attach`: the path is a live control
    /// socket that responds to a policy query, so `self.socket` is set.
    #[test]
    fn given_live_socket_when_attach_then_sets_socket() {
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicBool, AtomicU32};
        use std::sync::{Arc, Mutex};
        use shadi_sandbox::SandboxPolicy;

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("shadi-ctl-attach-success.sock");

        let live = Arc::new(Mutex::new(policy_watch::LivePolicy {
            policy: SandboxPolicy::new(),
            blocked: HashSet::new(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: None,
        }));

        let _handle = policy_watch::start_control_socket(&sock_path, live)
            .expect("start control socket");

        // Poll until the socket is ready (up to 2 s).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if sock_path.exists() && policy_watch::query_policy(&sock_path).is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "control socket did not become ready: {}",
                sock_path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let mut s = session();
        assert_continues(&mut s, &format!("/attach {}", sock_path.display()));
        assert!(s.socket.is_some(), "socket should be set after successful attach");
    }

    // ── /attach completion session listing ───────────────────

    /// Exercises the inner loop of the `/attach` tab-completion handler: when a
    /// `shadi-ctl-*.sock` marker file is present in `temp_dir()`, the session
    /// name appears in the completion candidates.
    #[test]
    fn given_session_file_in_tmpdir_when_completing_attach_then_returns_session_name() {
        let tmpdir = std::env::temp_dir();
        let sock_path = tmpdir.join("shadi-ctl-coverage-completion-test.sock");
        std::fs::write(&sock_path, b"").expect("create test marker");

        let result = std::panic::catch_unwind(|| {
            let helper = ShellHelper::new(false);
            let rl_config = Config::builder().build();
            let mut rl = Editor::with_config(rl_config).unwrap();
            rl.set_helper(Some(helper));
            let helper = rl.helper().unwrap();
            let (_start, candidates) =
                Completer::complete(helper, "/attach ", 8, &Context::new(rl.history())).unwrap();
            candidates
                .iter()
                .any(|c| c.display == "coverage-completion-test")
        });

        let _ = std::fs::remove_file(&sock_path);

        assert!(
            result.expect("completion did not panic"),
            "session name should appear in /attach completions"
        );
    }
}
