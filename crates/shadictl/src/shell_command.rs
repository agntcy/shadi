// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, EditMode, Editor, Helper};
use unicode_width::UnicodeWidthStr;

use crate::cli_types::{
    ConfigCli, ConfigCommand, ConfigShowArgs, OutputFormat, PolicyCli, PolicyCommand,
    PolicyDiffArgs, PolicyExplainArgs, ShellArgs,
};
use crate::introspection_command::{run_config_command, run_policy_command};
use crate::policy_watch;
use crate::trace_command::{resolve_trace_file, trace_list, trace_summary};
use shadi_sandbox::PolicyPatch;

const COMMANDS: &[(&str, &str)] = &[
    ("/help", "Show available commands (alias: /h)"),
    ("/status", "Show current session status (alias: /s)"),
    ("/attach", "Attach to a running sandbox session by socket path"),
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
    ("/history", "Show command history"),
    ("/clear", "Clear the terminal screen"),
    ("/exit", "Exit the interactive shell (alias: /q, /quit)"),
];

/// Detailed help text for commands that accept arguments.
const COMMAND_HELP: &[(&str, &str)] = &[
    ("/attach", "\
Usage: /attach <socket-path>

Attach to a running SHADI sandbox session via its control socket.

Examples:
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

        // Socket path completion for /attach.
        if let Some(path_input) = input.strip_prefix("/attach ") {
            let path_input = path_input.trim_start();
            let tmpdir = std::env::temp_dir();
            if let Ok(entries) = std::fs::read_dir(&tmpdir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("shadi-ctl-") && name_str.ends_with(".sock") {
                        let full = entry.path().to_string_lossy().to_string();
                        if full.starts_with(path_input) || path_input.is_empty() {
                            candidates.push(Pair {
                                display: full.clone(),
                                replacement: full,
                            });
                        }
                    }
                }
            }
            let offset = pos - path_input.len();
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
            let cmd_key = if parts[0] == "/policy" || parts[0] == "/trace" {
                if parts.len() >= 3 {
                    format!("{} {}", parts[0], parts[1])
                } else {
                    parts[0].to_string()
                }
            } else {
                parts[0].to_string()
            };
            return self.cmd_help_detail(&cmd_key);
        }

        match parts[0] {
            "/help" | "/h" => {
                if parts.len() >= 2 {
                    let target = if parts.len() >= 3 {
                        format!("{} {}", parts[1], parts[2])
                    } else {
                        parts[1].to_string()
                    };
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
            "/attach" => {
                if parts.len() < 2 {
                    eprintln!("usage: /attach <socket-path>");
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
                let marker = if *reachable { "reachable" } else { "stale" };
                println!("  {} ({})", sock.display(), marker);
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

    fn cmd_attach(&mut self, path: &str) {
        let sock = PathBuf::from(path);
        if !sock.exists() {
            eprintln!("socket path does not exist: {}", path);
            return;
        }
        match policy_watch::query_policy(&sock) {
            Ok(_) => {
                println!("attached to {}", path);
                self.socket = Some(sock);
            }
            Err(err) => {
                eprintln!("failed to connect to {}: {}", path, err);
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
}

enum LoopAction {
    Continue,
    Exit,
}

pub(crate) fn run_shell_command(args: ShellArgs) -> ExitCode {
    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();

    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
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

    let mut session = ShellSession::new(args.socket);

    print_banner(use_color);
    if let Some(ref sock) = session.socket {
        if use_color {
            println!("  \x1b[32m attached to: {}\x1b[0m", sock.display());
        } else {
            println!("  attached to: {}", sock.display());
        }
    }
    println!();

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
                if trimmed.is_empty() {
                    if session.pending_patch.is_some() {
                        println!("patch cancelled");
                        session.pending_patch = None;
                    }
                    continue;
                }
                if session.pending_patch.is_none() {
                    let _ = rl.add_history_entry(trimmed);
                }
                match session.handle_command(trimmed) {
                    LoopAction::Continue => {}
                    LoopAction::Exit => break,
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

    if let Some(ref path) = history_path {
        let _ = rl.save_history(path);
    }

    ExitCode::SUCCESS
}

fn short_socket_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("session")
        .to_string()
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

    // ── helpers ──────────────────────────────────────────────

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

    // ── prompt utilities ─────────────────────────────────────

    #[test]
    fn given_socket_path_when_extracting_name_then_returns_stem() {
        let path = PathBuf::from("/tmp/shadi-ctl-12345.sock");
        assert_eq!(short_socket_name(&path), "shadi-ctl-12345");
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
}
