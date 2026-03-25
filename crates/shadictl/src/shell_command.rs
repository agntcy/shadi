// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, EditMode, Editor, Helper};

use crate::cli_types::{
    ConfigCli, ConfigCommand, ConfigShowArgs, OutputFormat, PolicyCli, PolicyCommand,
    PolicyDiffArgs, PolicyExplainArgs, ShellArgs,
};
use crate::introspection_command::{run_config_command, run_policy_command};
use crate::policy_watch;
use crate::trace_command::{resolve_trace_file, trace_list, trace_summary};
use shadi_sandbox::PolicyPatch;

const COMMANDS: &[(&str, &str)] = &[
    ("/help", "Show available commands"),
    ("/status", "Show current session status"),
    ("/attach", "Attach to a running sandbox session by socket path"),
    ("/detach", "Detach from the current session"),
    ("/sessions", "Discover running SHADI sandbox control sockets"),
    ("/config", "Show effective runtime configuration"),
    ("/policy query", "Query the effective policy of the attached session"),
    ("/policy patch", "Patch the policy of the attached session"),
    ("/policy explain", "Explain resolved policy and source inputs"),
    ("/policy diff", "Diff effective policy against a baseline profile"),
    ("/trace list", "List recent trace log entries"),
    ("/trace summary", "Summarize trace logs by span name"),
    ("/clear", "Clear the terminal screen"),
    ("/exit", "Exit the interactive shell"),
    ("/quit", "Exit the interactive shell"),
];

struct ShellHelper {
    hinter: HistoryHinter,
}

impl ShellHelper {
    fn new() -> Self {
        Self {
            hinter: HistoryHinter {},
        }
    }
}

impl Helper for ShellHelper {}
impl Validator for ShellHelper {}
impl Highlighter for ShellHelper {}

impl Hinter for ShellHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

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

        for &(cmd, _desc) in COMMANDS {
            if cmd.starts_with(input) {
                candidates.push(Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                });
            }
        }

        Ok((0, candidates))
    }
}

struct ShellSession {
    socket: Option<PathBuf>,
}

impl ShellSession {
    fn new(socket: Option<PathBuf>) -> Self {
        Self { socket }
    }

    fn handle_command(&mut self, line: &str) -> LoopAction {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return LoopAction::Continue;
        }

        match parts[0] {
            "/help" => self.cmd_help(),
            "/status" => self.cmd_status(),
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
            "/detach" => {
                self.cmd_detach();
                LoopAction::Continue
            }
            "/clear" => {
                print!("\x1B[2J\x1B[1;1H");
                LoopAction::Continue
            }
            "/exit" | "/quit" => LoopAction::Exit,
            _ => {
                eprintln!("unknown command: {}", parts[0]);
                eprintln!("type '/help' for available commands");
                LoopAction::Continue
            }
        }
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

    fn cmd_policy_patch(&self, args: &[&str]) -> LoopAction {
        let Some(ref sock) = self.socket else {
            eprintln!("not attached to a session; use '/attach <socket-path>' first");
            return LoopAction::Continue;
        };

        let mut patch = PolicyPatch::default();
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
                _ => {
                    eprintln!("unknown patch argument: {}", args[i]);
                    eprintln!("usage: /policy patch [--add-read PATH] [--add-write PATH] [--add-allow PATH]");
                    eprintln!("       [--add-allow-command CMD] [--remove-allow-command CMD]");
                    eprintln!("       [--add-block-command CMD] [--remove-block-command CMD]");
                    eprintln!("       [--add-net-allow DEST] [--remove-net-allow DEST]");
                    return LoopAction::Continue;
                }
            }
        }

        match policy_watch::send_patch(sock, &patch) {
            Ok(resp) => {
                println!("accepted:  {}", resp.accepted);
                println!("filesystem: {:?}", resp.filesystem);
                println!("commands:   {:?}", resp.commands);
                println!("network:    {:?}", resp.network);
                if !resp.message.is_empty() {
                    println!("message:    {}", resp.message);
                }
                if !resp.pending_restart.is_empty() {
                    println!("pending restart: {}", resp.pending_restart.join(", "));
                }
            }
            Err(err) => eprintln!("error patching policy: {}", err),
        }
        LoopAction::Continue
    }

    fn cmd_sessions(&self) -> LoopAction {
        let tmpdir = std::env::temp_dir();
        let mut found = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&tmpdir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("shadi-ctl-") && name_str.ends_with(".sock") {
                    found.push(entry.path());
                }
            }
        }
        if found.is_empty() {
            println!("no running SHADI sandbox sessions found in {}", tmpdir.display());
        } else {
            println!("found {} session(s):", found.len());
            for sock in &found {
                let reachable = policy_watch::query_policy(sock).is_ok();
                let marker = if reachable { "reachable" } else { "stale" };
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

    let helper = ShellHelper::new();
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
    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());

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
        let prompt = if use_color {
            match &session.socket {
                Some(sock) => format!("\x1b[1;36mshadi\x1b[0m(\x1b[33m{}\x1b[0m)\x1b[1;36m>\x1b[0m ", short_socket_name(sock)),
                None => "\x1b[1;36mshadi>\x1b[0m ".to_string(),
            }
        } else {
            match &session.socket {
                Some(sock) => format!("shadi({})> ", short_socket_name(sock)),
                None => "shadi> ".to_string(),
            }
        };

        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);
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

fn dirs_history_path() -> Option<PathBuf> {
    let dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    let shadi_dir = PathBuf::from(dir).join(".shadi");
    std::fs::create_dir_all(&shadi_dir).ok()?;
    Some(shadi_dir.join("shell_history"))
}

fn print_banner(color: bool) {
    if color {
        println!(
            "\x1b[1;36m\
  ____  _   _    _    ____ ___\n\
 / ___|| | | |  / \\  |  _ \\_ _|\n\
 \\___ \\| |_| | / _ \\ | | | | |\n\
  ___) |  _  |/ ___ \\| |_| | |\n\
 |____/|_| |_/_/   \\_\\____/___|\x1b[0m"
        );
        println!();
        println!(
            "  \x1b[1mSandbox Hardening for AI Developer Infrastructure\x1b[0m"
        );
        println!(
            "  \x1b[2mtype '/help' for available commands, '/exit' to quit\x1b[0m"
        );
    } else {
        println!(
            "\
  ____  _   _    _    ____ ___\n\
 / ___|| | | |  / \\  |  _ \\_ _|\n\
 \\___ \\| |_| | / _ \\ | | | | |\n\
  ___) |  _  |/ ___ \\| |_| | |\n\
 |____/|_| |_/_/   \\_\\____/___|\n"
        );
        println!("  Sandbox Hardening for AI Developer Infrastructure");
        println!("  type '/help' for available commands, '/exit' to quit");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────

    fn session() -> ShellSession {
        ShellSession::new(None)
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
        let helper = ShellHelper::new();
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
        let helper = ShellHelper::new();
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
}
