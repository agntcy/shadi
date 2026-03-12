// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::io::BufRead;

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use base64::Engine;
use clap::{ArgAction, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
#[cfg(not(test))]
use reqwest::blocking::Client;
#[cfg(not(test))]
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shadi_sandbox::{spawn_sandboxed, SandboxPolicy};
use agent_secrets::{SecretPolicy, SecretStore};
use shadi_memory::{MemoryEntry, SqlCipherStore};
use sequoia_openpgp as openpgp;
use tracing::{field, info_span};

#[derive(Parser, Debug)]
#[command(name = "shadi")]
#[command(about = "Secure Host Agentic AI Dynamic Instantiation")]
struct Cli {
    #[arg(long = "profile", value_enum, value_name = "PROFILE")]
    profile: Option<LauncherProfile>,

    #[arg(long = "policy", value_name = "FILE")]
    policy_file: Option<PathBuf>,

    #[arg(long = "allow", value_name = "PATH", action = ArgAction::Append)]
    allow: Vec<PathBuf>,

    #[arg(long = "read", value_name = "PATH", action = ArgAction::Append)]
    read: Vec<PathBuf>,

    #[arg(long = "write", value_name = "PATH", action = ArgAction::Append)]
    write: Vec<PathBuf>,

    #[arg(long = "net-block", action = ArgAction::SetTrue)]
    net_block: bool,

    #[arg(long = "allow-command", value_name = "CMD", action = ArgAction::Append)]
    allow_command: Vec<String>,

    #[arg(long = "inject-keychain", value_name = "KEY=ENV", action = ArgAction::Append)]
    inject_keychain: Vec<String>,

    #[arg(long = "list-keychain", action = ArgAction::SetTrue)]
    list_keychain: bool,

    #[arg(long = "list-prefix", value_name = "PREFIX")]
    list_prefix: Option<String>,

    #[arg(long = "print-policy", action = ArgAction::SetTrue)]
    print_policy: bool,

    #[arg(long = "git-snapshot", action = ArgAction::SetTrue)]
    git_snapshot: bool,

    #[arg(long = "git-snapshot-dir", value_name = "DIR")]
    git_snapshot_dir: Option<PathBuf>,

    #[arg(long = "git-snapshot-untracked", action = ArgAction::SetTrue)]
    git_snapshot_untracked: bool,

    #[arg(last = true)]
    command: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum LauncherProfile {
    Strict,
    Balanced,
    Connected,
}

#[derive(Parser, Debug)]
#[command(name = "memory", about = "Query SQLCipher memory using SHADI secrets")]
struct MemoryCli {
    #[arg(long, env = "SHADI_MEMORY_DB", value_name = "PATH")]
    db: PathBuf,

    #[arg(long, env = "SHADI_MEMORY_KEY")]
    key: Option<String>,

    #[arg(long = "key-name", env = "SHADI_MEMORY_KEY_NAME", default_value = "shadi/memory/sqlcipher_key")]
    key_name: String,

    #[command(subcommand)]
    command: MemoryCommand,
}

#[derive(Parser, Debug)]
#[command(name = "trace", about = "Inspect local SHADI trace logs")]
struct TraceCli {
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    #[command(subcommand)]
    command: TraceCommand,
}

#[derive(Subcommand, Debug)]
enum TraceCommand {
    List {
        #[arg(long, default_value = "50")]
        limit: usize,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        exit_code: Option<i32>,
    },
    Summary {
        #[arg(long, default_value = "200")]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
enum MemoryCommand {
    Init,
    Put {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
        #[arg(long)]
        payload: Option<String>,
        #[arg(long = "payload-file")]
        payload_file: Option<PathBuf>,
    },
    Get {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
    },
    Search {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        query: String,
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    List {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    Delete {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
    },
}

#[derive(Parser, Debug)]
#[command(name = "did-from-gpg", about = "Create did:key DID document from a GPG Ed25519 public key")]
struct DidFromGpgArgs {
    #[arg(
        short = 'k',
        long = "key",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    key_ref: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "key_ref",
        conflicts_with = "key_ref"
    )]
    input: Option<PathBuf>,

    #[arg(short = 'o', long = "out", value_name = "FILE", default_value = "did-document.json")]
    out_file: PathBuf,
}

#[derive(Parser, Debug)]
#[command(name = "did-from-github", about = "Create did:key DID document from a GitHub GPG public key")]
struct DidFromGitHubArgs {
    #[arg(long = "user", value_name = "USERNAME")]
    user: String,

    #[arg(long = "out", value_name = "FILE")]
    out_file: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(name = "get-secret", about = "Read a secret from the SHADI secret store")]
struct GetSecretArgs {
    #[arg(long = "key", value_name = "KEY")]
    key: String,
}

#[derive(Parser, Debug)]
#[command(name = "derive-agent-did", about = "Derive an agent DID from a human GPG key")]
struct DeriveAgentDidArgs {
    #[arg(
        short = 's',
        long = "secret",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    secret: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "secret",
        conflicts_with = "secret"
    )]
    input: Option<PathBuf>,

    #[arg(short = 'n', long = "name", value_name = "NAME")]
    agent_name: String,

    #[arg(long = "prefix", value_name = "PATH", default_value = "agent_keys")]
    prefix: String,

    #[arg(short = 'o', long = "out", value_name = "FILE")]
    out_file: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum HumanIdentitySource {
    Gpg,
    Seed,
}

#[derive(Parser, Debug)]
#[command(name = "derive-agent-identity", about = "Derive one or more local agent identities from a human identity source")]
struct DeriveAgentIdentityArgs {
    #[arg(long = "source", value_enum, default_value = "gpg")]
    source: HumanIdentitySource,

    #[arg(
        short = 's',
        long = "human-secret",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    human_secret: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "human_secret",
        conflicts_with = "human_secret"
    )]
    input: Option<PathBuf>,

    #[arg(short = 'n', long = "name", value_name = "NAME", action = ArgAction::Append, required = true)]
    agent_names: Vec<String>,

    #[arg(long = "prefix", value_name = "PATH", default_value = "agent_keys")]
    prefix: String,

    #[arg(long = "human-did-key", value_name = "SECRET")]
    human_did_key: Option<String>,

    #[arg(long = "out-dir", value_name = "DIR")]
    out_dir: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(name = "verify-agent-identity", about = "Verify an agent identity is derived from a human identity source")]
struct VerifyAgentIdentityArgs {
    #[arg(long = "source", value_enum, default_value = "gpg")]
    source: HumanIdentitySource,

    #[arg(
        short = 's',
        long = "human-secret",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    human_secret: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "human_secret",
        conflicts_with = "human_secret"
    )]
    input: Option<PathBuf>,

    #[arg(short = 'n', long = "name", value_name = "NAME")]
    agent_name: String,

    #[arg(long = "prefix", value_name = "PATH", default_value = "agent_keys")]
    prefix: String,

    #[arg(long = "public-key-key", value_name = "SECRET")]
    public_key_key: Option<String>,

    #[arg(long = "did-key", value_name = "SECRET")]
    did_key: Option<String>,

    #[arg(long = "human-did-key", value_name = "SECRET")]
    human_did_key: Option<String>,

    #[arg(long = "require-human-binding", action = ArgAction::SetTrue)]
    require_human_binding: bool,
}

#[derive(Parser, Debug)]
#[command(name = "put-key", about = "Store an OpenPGP key in the SHADI secret store")]
struct PutKeyArgs {
    #[arg(short = 'k', long = "key", value_name = "SECRET")]
    key: String,

    #[arg(short = 'i', long = "in", value_name = "FILE")]
    input: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
    #[serde(default)]
    net_block: Option<bool>,
    #[serde(default)]
    allow_command: Vec<String>,
    #[serde(default)]
    block_command: Vec<String>,
}

#[derive(Debug)]
struct ResolvedPolicy {
    policy: SandboxPolicy,
    blocked: HashSet<String>,
    allow: HashSet<String>,
}

#[cfg(test)]
static TEST_SECRET_STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

#[cfg(test)]
fn test_secret_store_map() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    TEST_SECRET_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
struct TestSecretStore;

#[cfg(test)]
impl SecretStore for TestSecretStore {
    fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> agent_secrets::SecretResult<()> {
        let mut guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        guard.insert(key.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> agent_secrets::SecretResult<agent_secrets::memory::SecretBytes> {
        let guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        let value = guard
            .get(key)
            .ok_or(agent_secrets::SecretError::InvalidInput)?
            .clone();
        Ok(agent_secrets::memory::SecretBytes::new(value))
    }

    fn delete(&self, key: &str) -> agent_secrets::SecretResult<()> {
        let mut guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        guard.remove(key);
        Ok(())
    }

    fn list_keys(&self) -> agent_secrets::SecretResult<Vec<String>> {
        let guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        Ok(guard.keys().cloned().collect())
    }
}

#[cfg(test)]
fn default_secret_store() -> Box<dyn SecretStore> {
    Box::new(TestSecretStore)
}

#[cfg(not(test))]
fn default_secret_store() -> Box<dyn SecretStore> {
    agent_secrets::default_store()
}

#[cfg(test)]
fn test_store_put(key: &str, value: &[u8]) {
    let mut guard = test_secret_store_map().lock().expect("test store lock");
    guard.insert(key.to_string(), value.to_vec());
}

#[cfg(test)]
fn test_store_get(key: &str) -> Option<Vec<u8>> {
    let guard = test_secret_store_map().lock().expect("test store lock");
    guard.get(key).cloned()
}


fn main() -> ExitCode {
    shadi_telemetry::init("shadi-core");
    let cli = Cli::parse();
    run_cli(cli)
}

fn run_cli(cli: Cli) -> ExitCode {
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("memory")) {
        return run_memory_command(&cli.command[1..]);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("trace")) {
        return run_trace_command(&cli.command[1..]);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("did-from-gpg")) {
        return run_did_from_gpg_command(&cli.command);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("did-from-github")) {
        return run_did_from_github_command(&cli.command);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("get-secret")) {
        return run_get_secret_command(&cli.command);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("derive-agent-did")) {
        return run_derive_agent_did_command(&cli.command);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("derive-agent-identity")) {
        return run_derive_agent_identity_command(&cli.command);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("verify-agent-identity")) {
        return run_verify_agent_identity_command(&cli.command);
    }
    if matches!(cli.command.first().map(|cmd| cmd.as_str()), Some("put-key")) {
        return run_put_key_command(&cli.command);
    }

    if cli.list_keychain {
        return match list_keychain(cli.list_prefix.as_deref()) {
            Ok(()) => ExitCode::from(0),
            Err(err) => {
                eprintln!("failed to list secrets: {}", err);
                ExitCode::from(2)
            }
        };
    }

    if cli.print_policy && cli.command.is_empty() {
        let file_policy = match cli.policy_file.as_ref() {
            Some(path) => match load_policy_file(path) {
                Ok(policy) => policy,
                Err(err) => {
                    eprintln!("failed to read policy {}: {}", path.display(), err);
                    return ExitCode::from(2);
                }
            },
            None => PolicyFile::default(),
        };

        let resolved = match resolve_policy(&cli, &file_policy) {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("{}", err);
                return ExitCode::from(2);
            }
        };

        return match format_policy(&resolved.policy, &resolved.blocked, &resolved.allow) {
            Ok(output) => {
                println!("{}", output);
                ExitCode::from(0)
            }
            Err(err) => {
                eprintln!("failed to print policy: {}", err);
                ExitCode::from(2)
            }
        };
    }

    if cli.command.is_empty() {
        eprintln!("missing command to run");
        return ExitCode::from(2);
    }
    let file_policy = match cli.policy_file.as_ref() {
        Some(path) => match load_policy_file(path) {
            Ok(policy) => policy,
            Err(err) => {
                eprintln!("failed to read policy {}: {}", path.display(), err);
                return ExitCode::from(2);
            }
        },
        None => PolicyFile::default(),
    };

    let resolved = match resolve_policy(&cli, &file_policy) {
        Ok(resolved) => resolved,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let cmd_name = cli.command.first().map(|cmd| cmd.as_str()).unwrap_or("");
    if is_command_blocked(cmd_name, &resolved.blocked, &resolved.allow) {
        eprintln!("blocked command: {}", cmd_name);
        return ExitCode::from(2);
    }

    if cli.print_policy {
        return match format_policy(&resolved.policy, &resolved.blocked, &resolved.allow) {
            Ok(output) => {
                println!("{}", output);
                ExitCode::from(0)
            }
            Err(err) => {
                eprintln!("failed to print policy: {}", err);
                ExitCode::from(2)
            }
        };
    }

    let cwd = match std::env::current_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("failed to determine current working directory: {}", err);
            return ExitCode::from(1);
        }
    };

    run_sandboxed_command(&cli, &resolved, &cwd)
}

fn run_trace_command(args: &[String]) -> ExitCode {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push("shadictl-trace".to_string());
    argv.extend_from_slice(args);
    let cli = match TraceCli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let path = resolve_trace_file(cli.file);
    match &cli.command {
        TraceCommand::List {
            limit,
            name,
            command,
            exit_code,
        } => match trace_list(&path, *limit, name.as_deref(), command.as_deref(), *exit_code) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(1)
            }
        },
        TraceCommand::Summary { limit } => match trace_summary(&path, *limit) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(1)
            }
        },
    }
}

fn resolve_trace_file(cli_path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_path {
        return path;
    }
    if let Ok(path) = std::env::var("SHADI_OTEL_FILE") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(".shadi/traces.jsonl")
}

fn trace_list(
    path: &Path,
    limit: usize,
    name: Option<&str>,
    command: Option<&str>,
    exit_code: Option<i32>,
) -> Result<(), String> {
    let lines = read_trace_lines(path, limit)?;
    for line in lines {
        if let Some(value) = parse_trace_line(&line) {
            if !trace_matches(&value, name, command, exit_code) {
                continue;
            }
        }
        println!("{}", line);
    }
    Ok(())
}

fn trace_summary(path: &Path, limit: usize) -> Result<(), String> {
    let lines = read_trace_lines(path, limit)?;
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for line in lines {
        if let Some(value) = parse_trace_line(&line) {
            if let Some(name) = trace_span_name(&value) {
                *counts.entry(name).or_insert(0) += 1;
            }
        }
    }

    for (name, count) in counts {
        println!("{}\t{}", count, name);
    }
    Ok(())
}

fn read_trace_lines(path: &Path, limit: usize) -> Result<Vec<String>, String> {
    let file = std::fs::File::open(path)
        .map_err(|err| format!("failed to open trace file {}: {}", path.display(), err))?;
    let reader = std::io::BufReader::new(file);
    let mut lines: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read trace file: {}", err))?;
        if limit == 0 {
            continue;
        }
        lines.push_back(line);
        if lines.len() > limit {
            lines.pop_front();
        }
    }
    Ok(lines.into_iter().collect())
}

fn parse_trace_line(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str(line).ok()
}

fn trace_span_name(value: &serde_json::Value) -> Option<String> {
    if let Some(name) = value
        .get("span")
        .and_then(|span| span.get("name"))
        .and_then(|name| name.as_str())
    {
        return Some(name.to_string());
    }

    if let Some(spans) = value.get("spans").and_then(|spans| spans.as_array()) {
        if let Some(name) = spans
            .iter()
            .filter_map(|span| span.get("name"))
            .filter_map(|name| name.as_str())
            .next()
        {
            return Some(name.to_string());
        }
    }

    None
}

fn trace_matches(
    value: &serde_json::Value,
    name: Option<&str>,
    command: Option<&str>,
    exit_code: Option<i32>,
) -> bool {
    if let Some(expected) = name {
        if trace_span_name(value)
            .as_deref()
            .map(|value| !value.contains(expected))
            .unwrap_or(true)
        {
            return false;
        }
    }

    if let Some(expected) = command {
        let found = value
            .get("fields")
            .and_then(|fields| fields.get("command"))
            .and_then(|value| value.as_str())
            .map(|value| value.contains(expected))
            .unwrap_or(false);
        if !found {
            return false;
        }
    }

    if let Some(expected) = exit_code {
        let found = value
            .get("fields")
            .and_then(|fields| fields.get("exit.code"))
            .and_then(|value| value.as_i64())
            .map(|value| value == expected as i64)
            .unwrap_or(false);
        if !found {
            return false;
        }
    }

    true
}

fn run_sandboxed_command(cli: &Cli, resolved: &ResolvedPolicy, cwd: &Path) -> ExitCode {
    let cmd_name = cli.command.first().map(|cmd| cmd.as_str()).unwrap_or("");
    let policy_source = cli
        .policy_file
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "default".to_string());
    let mut allowed_paths = BTreeSet::new();
    allowed_paths.extend(resolved.policy.allow_read().iter().cloned());
    allowed_paths.extend(resolved.policy.allow_write().iter().cloned());
    let network_mode = if resolved.policy.net_blocked() { "blocked" } else { "allowed" };

    let mut command = Command::new(cmd_name);
    if cli.command.len() > 1 {
        command.args(&cli.command[1..]);
    }
    command.current_dir(cwd);

    if let Err(err) = inject_keychain_secrets(&mut command, &cli.inject_keychain) {
        eprintln!("failed to inject keychain secrets: {}", err);
        return ExitCode::from(2);
    }

    let mut snapshot = GitSnapshotSession::start(cli, resolved, cwd);
    let snapshot_enabled = snapshot.is_some();

    let span = info_span!(
        "shadi.sandbox.run",
        command = %cmd_name,
        cwd = %cwd.display(),
        policy.source = %policy_source,
        policy.allowed_paths = allowed_paths.len() as i64,
        network.mode = %network_mode,
        snapshot.enabled = snapshot_enabled,
        exit.code = field::Empty,
        snapshot.path = field::Empty,
    );
    let _guard = span.enter();

    match spawn_sandboxed(&mut command, &resolved.policy) {
        Ok(mut child) => match child.wait() {
            Ok(status) => {
                let exit_code = status.code().unwrap_or(1);
                span.record("exit.code", &exit_code);
                let snapshot_path = finalize_git_snapshot(snapshot.as_mut(), status.code(), None);
                if let Some(path) = snapshot_path {
                    span.record("snapshot.path", &path.display().to_string());
                }
                ExitCode::from(status.code().unwrap_or(1) as u8)
            }
            Err(err) => {
                span.record("exit.code", &-1);
                let snapshot_path = finalize_git_snapshot(
                    snapshot.as_mut(),
                    None,
                    Some(format!("failed to wait for child: {}", err)),
                );
                if let Some(path) = snapshot_path {
                    span.record("snapshot.path", &path.display().to_string());
                }
                eprintln!("failed to wait for child: {}", err);
                ExitCode::from(1)
            }
        },
        Err(err) => {
            span.record("exit.code", &-1);
            let snapshot_path = finalize_git_snapshot(
                snapshot.as_mut(),
                None,
                Some(format!("failed to start sandboxed command: {}", err)),
            );
            if let Some(path) = snapshot_path {
                span.record("snapshot.path", &path.display().to_string());
            }
            eprintln!("failed to start sandboxed command: {}", err);
            ExitCode::from(1)
        }
    }
}

fn finalize_git_snapshot(
    snapshot: Option<&mut GitSnapshotSession>,
    exit_code: Option<i32>,
    error: Option<String>,
) -> Option<PathBuf> {
    if let Some(snapshot) = snapshot {
        match snapshot.finish(exit_code, error) {
            Ok(path) => Some(path),
            Err(err) => {
                eprintln!("warning: failed to write git snapshot artifact: {}", err);
                None
            }
        }
    } else {
        None
    }
}

#[derive(Debug)]
struct GitSnapshotConfig {
    output_dir: PathBuf,
    include_untracked: bool,
}

impl GitSnapshotConfig {
    fn from_cli(cli: &Cli) -> Option<Self> {
        if !cli.git_snapshot {
            return None;
        }

        Some(Self {
            output_dir: cli
                .git_snapshot_dir
                .clone()
                .unwrap_or_else(default_git_snapshot_dir),
            include_untracked: cli.git_snapshot_untracked,
        })
    }
}

#[derive(Debug)]
struct GitSnapshotSession {
    artifact: GitSnapshotArtifact,
    output_dir: PathBuf,
}

impl GitSnapshotSession {
    fn start(cli: &Cli, resolved: &ResolvedPolicy, cwd: &Path) -> Option<Self> {
        let config = GitSnapshotConfig::from_cli(cli)?;
        let started_at_ms = unix_timestamp_ms();
        let policy = snapshot_policy_value(&resolved.policy, &resolved.blocked, &resolved.allow);
        let git = capture_git_snapshot(cwd, config.include_untracked);

        Some(Self {
            artifact: GitSnapshotArtifact {
                schema_version: 1,
                artifact_id: build_snapshot_artifact_id(&cli.command, started_at_ms),
                command: cli.command.clone(),
                cwd: cwd.display().to_string(),
                policy,
                timestamps: GitSnapshotTimestamps {
                    started_at_ms,
                    finished_at_ms: None,
                    duration_ms: None,
                },
                outcome: GitSnapshotOutcome {
                    exit_code: None,
                    error: None,
                },
                git,
                layout: GitSnapshotLayout::default(),
            },
            output_dir: config.output_dir,
        })
    }

    fn finish(&mut self, exit_code: Option<i32>, error: Option<String>) -> Result<PathBuf, String> {
        let finished_at_ms = unix_timestamp_ms();
        self.artifact.timestamps.finished_at_ms = Some(finished_at_ms);
        self.artifact.timestamps.duration_ms = Some(finished_at_ms.saturating_sub(self.artifact.timestamps.started_at_ms));
        self.artifact.outcome.exit_code = exit_code;
        self.artifact.outcome.error = error;

        for repository in &mut self.artifact.git.repositories {
            if repository.capture_error.is_none() {
                match collect_git_repo_state(
                    Path::new(&repository.repo_root),
                    self.artifact.git.include_untracked_inventory,
                ) {
                    Ok(after) => {
                        let summary = summarize_status_lines(&after.status_porcelain);
                        repository.diff_summary = Some(summary);
                        repository.after = Some(after);
                    }
                    Err(err) => {
                        repository.capture_error = Some(err);
                    }
                }
            }

            repository.comparison = build_git_state_comparison(
                repository.before.as_ref(),
                repository.after.as_ref(),
            );
        }

        self.artifact.git.sync_primary_repository_fields();
        self.artifact.git.refresh_change_summary();

        std::fs::create_dir_all(&self.output_dir)
            .map_err(|err| format!("failed to create {}: {}", self.output_dir.display(), err))?;

        let run_dir = self.output_dir.join("runs").join(&self.artifact.artifact_id);
        std::fs::create_dir_all(&run_dir)
            .map_err(|err| format!("failed to create {}: {}", run_dir.display(), err))?;

        let path = run_dir.join("snapshot.json");
        let latest = self.output_dir.join("latest.json");
        self.artifact.layout.root_dir = self.output_dir.display().to_string();
        self.artifact.layout.run_dir = run_dir.display().to_string();
        self.artifact.layout.snapshot_file = path.display().to_string();
        self.artifact.layout.latest_file = latest.display().to_string();

        let payload = serde_json::to_string_pretty(&self.artifact).map_err(|err| err.to_string())?;
        std::fs::write(&path, format!("{}\n", payload))
            .map_err(|err| format!("failed to write {}: {}", path.display(), err))?;

        std::fs::write(&latest, format!("{}\n", payload))
            .map_err(|err| format!("failed to write {}: {}", latest.display(), err))?;
        Ok(path)
    }
}

#[derive(Debug, Serialize)]
struct GitSnapshotArtifact {
    schema_version: u32,
    artifact_id: String,
    command: Vec<String>,
    cwd: String,
    policy: Value,
    timestamps: GitSnapshotTimestamps,
    outcome: GitSnapshotOutcome,
    git: GitSnapshotRecord,
    layout: GitSnapshotLayout,
}

#[derive(Debug, Serialize)]
struct GitSnapshotLayout {
    root_dir: String,
    run_dir: String,
    snapshot_file: String,
    latest_file: String,
}

impl Default for GitSnapshotLayout {
    fn default() -> Self {
        Self {
            root_dir: String::new(),
            run_dir: String::new(),
            snapshot_file: String::new(),
            latest_file: String::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct GitSnapshotTimestamps {
    started_at_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
}

#[derive(Debug, Serialize)]
struct GitSnapshotOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct GitSnapshotRecord {
    detected: bool,
    changed_repositories: usize,
    any_repo_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_root: Option<String>,
    include_untracked_inventory: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_summary: Option<GitDiffSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<GitStateComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capture_error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    repositories: Vec<GitTrackedRepository>,
}

impl GitSnapshotRecord {
    fn sync_primary_repository_fields(&mut self) {
        if let Some(primary) = self.repositories.first() {
            self.repo_root = Some(primary.repo_root.clone());
            self.before = primary.before.clone();
            self.after = primary.after.clone();
            self.diff_summary = primary.diff_summary.clone();
            self.comparison = primary.comparison.clone();
            self.capture_error = primary.capture_error.clone();
        } else {
            self.repo_root = None;
            self.before = None;
            self.after = None;
            self.diff_summary = None;
            self.comparison = None;
            self.capture_error = None;
        }
    }

    fn refresh_change_summary(&mut self) {
        self.changed_repositories = self
            .repositories
            .iter()
            .filter(|repository| {
                repository
                    .comparison
                    .as_ref()
                    .map(|comparison| comparison.overall_changed)
                    .unwrap_or(false)
            })
            .count();
        self.any_repo_changed = self.changed_repositories > 0;
        self.detected = !self.repositories.is_empty();
    }
}

#[derive(Debug, Clone, Serialize)]
struct GitTrackedRepository {
    repo_root: String,
    relative_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<GitRepoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_summary: Option<GitDiffSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<GitStateComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capture_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct GitRepoState {
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<String>,
    status_porcelain: Vec<String>,
    diff_binary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked_inventory: Option<Vec<String>>,
    hashes: GitRepoStateHashes,
}

#[derive(Debug, Clone, Serialize)]
struct GitRepoStateHashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    head_sha256: Option<String>,
    status_sha256: String,
    diff_binary_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked_inventory_sha256: Option<String>,
    state_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct GitStateComparison {
    #[serde(skip_serializing_if = "Option::is_none")]
    before_state_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_state_sha256: Option<String>,
    head_changed: bool,
    status_changed: bool,
    diff_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    untracked_changed: Option<bool>,
    overall_changed: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
struct GitDiffSummary {
    added: usize,
    modified: usize,
    deleted: usize,
    renamed: usize,
    copied: usize,
    unmerged: usize,
    untracked: usize,
    other: usize,
    changed: bool,
}

fn default_git_snapshot_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./.tmp"))
        .join("git-snapshots")
}

fn build_snapshot_artifact_id(command: &[String], started_at_ms: u128) -> String {
    let cmd = command
        .first()
        .map(|value| sanitize_snapshot_component(value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "command".to_string());
    format!("{}-{}-{}", started_at_ms, std::process::id(), cmd)
}

fn sanitize_snapshot_component(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').chars().take(48).collect()
}

fn snapshot_policy_value(
    policy: &SandboxPolicy,
    blocked: &HashSet<String>,
    allow: &HashSet<String>,
) -> Value {
    match format_policy(policy, blocked, allow) {
        Ok(output) => serde_json::from_str(&output).unwrap_or_else(|_| Value::String(output)),
        Err(err) => Value::String(err),
    }
}

fn capture_git_snapshot(cwd: &Path, include_untracked: bool) -> GitSnapshotRecord {
    match discover_git_repo_roots(cwd) {
        Ok(repo_roots) if repo_roots.is_empty() => GitSnapshotRecord {
            detected: false,
            changed_repositories: 0,
            any_repo_changed: false,
            repo_root: None,
            include_untracked_inventory: include_untracked,
            before: None,
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: None,
            repositories: Vec::new(),
        },
        Ok(repo_roots) => {
            let repositories = repo_roots
                .into_iter()
                .map(|repo_root| capture_git_repository_snapshot(cwd, &repo_root, include_untracked))
                .collect::<Vec<_>>();

            let mut record = GitSnapshotRecord {
                detected: true,
                changed_repositories: 0,
                any_repo_changed: false,
                repo_root: None,
                include_untracked_inventory: include_untracked,
                before: None,
                after: None,
                diff_summary: None,
                comparison: None,
                capture_error: None,
                repositories,
            };
            record.sync_primary_repository_fields();
            record.refresh_change_summary();
            record
        }
        Err(err) => GitSnapshotRecord {
            detected: false,
            changed_repositories: 0,
            any_repo_changed: false,
            repo_root: None,
            include_untracked_inventory: include_untracked,
            before: None,
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: Some(err),
            repositories: Vec::new(),
        },
    }
}

fn capture_git_repository_snapshot(cwd: &Path, repo_root: &Path, include_untracked: bool) -> GitTrackedRepository {
    let repo_root_string = repo_root.display().to_string();
    match collect_git_repo_state(repo_root, include_untracked) {
        Ok(before) => GitTrackedRepository {
            repo_root: repo_root_string,
            relative_path: repo_relative_path(cwd, repo_root),
            before: Some(before),
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: None,
        },
        Err(err) => GitTrackedRepository {
            repo_root: repo_root_string,
            relative_path: repo_relative_path(cwd, repo_root),
            before: None,
            after: None,
            diff_summary: None,
            comparison: None,
            capture_error: Some(err),
        },
    }
}

fn repo_relative_path(cwd: &Path, repo_root: &Path) -> String {
    match repo_root.strip_prefix(cwd) {
        Ok(relative) if relative.as_os_str().is_empty() => ".".to_string(),
        Ok(relative) => relative.display().to_string(),
        Err(_) if cwd.starts_with(repo_root) => ".".to_string(),
        Err(_) => repo_root.display().to_string(),
    }
}

fn discover_git_repo_roots(cwd: &Path) -> Result<Vec<PathBuf>, String> {
    let mut repo_roots = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(primary_root) = detect_git_repo_root(cwd)? {
        let normalized = canonicalize_or_clone(&primary_root);
        seen.insert(normalized.clone());
        repo_roots.push(normalized);
    }

    let scope_root = canonicalize_or_clone(cwd);
    let mut nested_roots = find_nested_git_repo_roots(&scope_root)?;
    nested_roots.sort();

    for repo_root in nested_roots {
        if seen.insert(repo_root.clone()) {
            repo_roots.push(repo_root);
        }
    }

    Ok(repo_roots)
}

fn find_nested_git_repo_roots(scope_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut repo_roots = Vec::new();
    let mut stack = vec![scope_root.to_path_buf()];

    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|err| format!("failed to scan {}: {}", directory.display(), err))?;

        for entry in entries {
            let entry = entry.map_err(|err| format!("failed to scan {}: {}", directory.display(), err))?;
            let path = entry.path();
            let file_name = entry.file_name();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("failed to inspect {}: {}", path.display(), err))?;

            if file_name == std::ffi::OsStr::new(".git") {
                if let Some(repo_dir) = path.parent() {
                    if let Some(repo_root) = detect_git_repo_root(repo_dir)? {
                        let normalized = canonicalize_or_clone(&repo_root);
                        if normalized.starts_with(scope_root) || scope_root.starts_with(&normalized) {
                            repo_roots.push(normalized);
                        }
                    }
                }
                continue;
            }

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }

    Ok(repo_roots)
}

fn canonicalize_or_clone(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn detect_git_repo_root(cwd: &Path) -> Result<Option<PathBuf>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to execute git: {}", err))?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "git returned non-utf8 output for repo root".to_string())?;
    let root = stdout.trim();
    if root.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(root)))
}

fn collect_git_repo_state(repo_root: &Path, include_untracked: bool) -> Result<GitRepoState, String> {
    let head = run_git_capture_optional(repo_root, &["rev-parse", "HEAD"])?;
    let status = run_git_capture(repo_root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    let status_porcelain = split_nonempty_lines(&status);
    let diff_binary = run_git_capture(repo_root, &["diff", "--binary"])?;
    let untracked_inventory = if include_untracked {
        let files = run_git_capture(repo_root, &["ls-files", "--others", "--exclude-standard"])?;
        Some(split_nonempty_lines(&files))
    } else {
        None
    };
    let hashes = build_git_repo_state_hashes(
        head.as_deref(),
        &status_porcelain,
        &diff_binary,
        untracked_inventory.as_deref(),
    );

    Ok(GitRepoState {
        head,
        status_porcelain: status_porcelain.clone(),
        diff_binary,
        untracked_inventory,
        hashes,
    })
}

fn build_git_repo_state_hashes(
    head: Option<&str>,
    status_porcelain: &[String],
    diff_binary: &str,
    untracked_inventory: Option<&[String]>,
) -> GitRepoStateHashes {
    let head_sha256 = head.map(sha256_hex);
    let status_text = status_porcelain.join("\n");
    let status_sha256 = sha256_hex(&status_text);
    let diff_binary_sha256 = sha256_hex(diff_binary);
    let untracked_inventory_sha256 = untracked_inventory.map(|entries| sha256_hex(&entries.join("\n")));
    let state_sha256 = sha256_hex(
        &json!({
            "head": head,
            "status_porcelain": status_porcelain,
            "diff_binary_sha256": diff_binary_sha256,
            "untracked_inventory": untracked_inventory,
        })
        .to_string(),
    );

    GitRepoStateHashes {
        head_sha256,
        status_sha256,
        diff_binary_sha256,
        untracked_inventory_sha256,
        state_sha256,
    }
}

fn build_git_state_comparison(
    before: Option<&GitRepoState>,
    after: Option<&GitRepoState>,
) -> Option<GitStateComparison> {
    let before = before?;
    let after = after?;

    Some(GitStateComparison {
        before_state_sha256: Some(before.hashes.state_sha256.clone()),
        after_state_sha256: Some(after.hashes.state_sha256.clone()),
        head_changed: before.head != after.head,
        status_changed: before.hashes.status_sha256 != after.hashes.status_sha256,
        diff_changed: before.hashes.diff_binary_sha256 != after.hashes.diff_binary_sha256,
        untracked_changed: match (
            before.hashes.untracked_inventory_sha256.as_ref(),
            after.hashes.untracked_inventory_sha256.as_ref(),
        ) {
            (Some(left), Some(right)) => Some(left != right),
            (None, None) => None,
            _ => Some(true),
        },
        overall_changed: before.hashes.state_sha256 != after.hashes.state_sha256,
    })
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn run_git_capture(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute git {}: {}", args.join(" "), err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            repo_root.display(),
            stderr.trim()
        ));
    }

    String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-utf8 output", args.join(" ")))
}

fn run_git_capture_optional(repo_root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute git {}: {}", args.join(" "), err))?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-utf8 output", args.join(" ")))?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

fn split_nonempty_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

fn summarize_status_lines(lines: &[String]) -> GitDiffSummary {
    let mut summary = GitDiffSummary::default();

    for line in lines {
        let status = line.get(0..2).unwrap_or("");
        if status == "??" {
            summary.untracked += 1;
            continue;
        }

        for code in status.chars() {
            match code {
                'A' => summary.added += 1,
                'M' => summary.modified += 1,
                'D' => summary.deleted += 1,
                'R' => summary.renamed += 1,
                'C' => summary.copied += 1,
                'U' => summary.unmerged += 1,
                ' ' => {}
                _ => summary.other += 1,
            }
        }
    }

    summary.changed = !lines.is_empty();
    summary
}

fn unix_timestamp_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn run_memory_command(args: &[String]) -> ExitCode {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push("shadictl-memory".to_string());
    argv.extend_from_slice(args);
    let cli = match MemoryCli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let key = match resolve_memory_key(&cli) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(1);
        }
    };

    let store = match SqlCipherStore::open(&cli.db, &key) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(1);
        }
    };

    match handle_memory_command(&cli, &store) {
        Ok(output) => {
            println!("{}", output);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(1)
        }
    }
}

fn handle_memory_command(cli: &MemoryCli, store: &SqlCipherStore) -> Result<String, String> {
    let span = info_span!(
        "shadi.memory.command",
        memory.command = field::Empty,
        memory.scope = field::Empty,
        memory.entry_key = field::Empty,
        memory.limit = field::Empty,
        memory.query = field::Empty,
    );
    let _guard = span.enter();

    match &cli.command {
        MemoryCommand::Init => {
            span.record("memory.command", &"init");
            Ok("ok".to_string())
        }
        MemoryCommand::Put {
            scope,
            entry_key,
            payload,
            payload_file,
        } => {
            span.record("memory.command", &"put");
            span.record("memory.scope", &field::display(scope));
            span.record("memory.entry_key", &field::display(entry_key));
            let payload = read_memory_payload(payload.clone(), payload_file.clone())?;
            let id = store
                .put(scope, entry_key, &payload)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({"status": "saved", "id": id}).to_string())
        }
        MemoryCommand::Get { scope, entry_key } => {
            span.record("memory.command", &"get");
            span.record("memory.scope", &field::display(scope));
            span.record("memory.entry_key", &field::display(entry_key));
            let entry = store
                .get_latest(scope, entry_key)
                .map_err(|err| err.to_string())?;
            match entry {
                Some(entry) => serde_json::to_string_pretty(&entry).map_err(|err| err.to_string()),
                None => Ok(serde_json::json!({"found": false}).to_string()),
            }
        }
        MemoryCommand::Search {
            scope,
            query,
            limit,
        } => {
            span.record("memory.command", &"search");
            if let Some(scope) = scope.as_ref() {
                span.record("memory.scope", &field::display(scope));
            }
            span.record("memory.query", &field::display(query));
            span.record("memory.limit", &(*limit as i64));
            let entries = store
                .search(scope.as_deref(), query, *limit)
                .map_err(|err| err.to_string())?;
            format_memory_entries(entries)
        }
        MemoryCommand::List { scope, limit } => {
            span.record("memory.command", &"list");
            if let Some(scope) = scope.as_ref() {
                span.record("memory.scope", &field::display(scope));
            }
            span.record("memory.limit", &(*limit as i64));
            let entries = store
                .list(scope.as_deref(), *limit)
                .map_err(|err| err.to_string())?;
            format_memory_entries(entries)
        }
        MemoryCommand::Delete { scope, entry_key } => {
            span.record("memory.command", &"delete");
            span.record("memory.scope", &field::display(scope));
            span.record("memory.entry_key", &field::display(entry_key));
            let affected = store
                .delete(scope, entry_key)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({"deleted": affected}).to_string())
        }
    }
}

fn resolve_memory_key(cli: &MemoryCli) -> Result<String, String> {
    if let Some(key) = cli.key.as_ref() {
        if key.is_empty() {
            return Err("SHADI_MEMORY_KEY is empty".to_string());
        }
        return Ok(key.to_string());
    }

    let store = default_secret_store();
    let secret = store
        .get(&cli.key_name)
        .map_err(|_| format!("missing SHADI key: {}", cli.key_name))?;
    let raw = secret.expose(|bytes| bytes.to_vec());
    String::from_utf8(raw).map_err(|_| "SHADI memory key is not utf-8".to_string())
}

fn read_memory_payload(
    payload: Option<String>,
    payload_file: Option<PathBuf>,
) -> Result<String, String> {
    match (payload, payload_file) {
        (Some(text), None) => Ok(text),
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read payload file: {}", err)),
        (None, None) => Err("payload or payload-file must be provided".to_string()),
        (Some(_), Some(_)) => Err("use either payload or payload-file".to_string()),
    }
}

fn format_memory_entries(entries: Vec<MemoryEntry>) -> Result<String, String> {
    serde_json::to_string_pretty(&entries).map_err(|err| err.to_string())
}

fn run_derive_agent_did_command(args: &[String]) -> ExitCode {
    let parsed = match DeriveAgentDidArgs::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };

    match run_derive_agent_did(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

fn run_derive_agent_identity_command(args: &[String]) -> ExitCode {
    let parsed = match DeriveAgentIdentityArgs::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };

    match run_derive_agent_identity(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

fn run_verify_agent_identity_command(args: &[String]) -> ExitCode {
    let parsed = match VerifyAgentIdentityArgs::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };

    match run_verify_agent_identity(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

fn run_get_secret_command(args: &[String]) -> ExitCode {
    let parsed = match GetSecretArgs::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };

    match run_get_secret(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

fn run_did_from_github_command(args: &[String]) -> ExitCode {
    let parsed = match DidFromGitHubArgs::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };

    match run_did_from_github(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

fn run_did_from_gpg_command(args: &[String]) -> ExitCode {
    let parsed = match DidFromGpgArgs::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };

    match run_did_from_gpg(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

fn run_did_from_gpg(args: DidFromGpgArgs) -> Result<(), String> {
    let public_key = read_openpgp_input("--key", args.key_ref.as_deref(), args.input.as_ref())?;

    let pkey = extract_ed25519_public_key(&public_key)?;

    let (did, vm_id, doc) = build_did_document(&pkey)?;
    let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;
    std::fs::write(&args.out_file, format!("{}\n", output)).map_err(|err| {
        format!("failed to write {}: {}", args.out_file.display(), err)
    })?;

    println!("DID: {}", did);
    println!("Verification Method ID: {}", vm_id);
    println!("Wrote DID Document: {}", args.out_file.display());
    Ok(())
}

fn run_did_from_github(args: DidFromGitHubArgs) -> Result<(), String> {
    let public_key = fetch_github_gpg_key(&args.user)?;
    let pkey = extract_ed25519_public_key(&public_key)?;

    let (did, vm_id, doc) = build_did_document(&pkey)?;
    let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;

    let did_key = format!("github/{}/did", args.user);
    let did_doc_key = format!("github/{}/diddoc", args.user);

    let store = default_secret_store();
    store
        .put(&did_key, did.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", did_key, err))?;
    store
        .put(&did_doc_key, output.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", did_doc_key, err))?;

    if let Some(out_file) = args.out_file.as_ref() {
        std::fs::write(out_file, format!("{}\n", output)).map_err(|err| {
            format!("failed to write {}: {}", out_file.display(), err)
        })?;
    }

    println!("DID: {}", did);
    println!("Verification Method ID: {}", vm_id);
    println!("Stored DID in secret key: {}", did_key);
    println!("Stored DID Document in secret key: {}", did_doc_key);
    if let Some(out_file) = args.out_file.as_ref() {
        println!("Wrote DID Document: {}", out_file.display());
    }
    Ok(())
}

fn run_get_secret(args: GetSecretArgs) -> Result<(), String> {
    let store = default_secret_store();
    let secret = store
        .get(&args.key)
        .map_err(|_| format!("keychain lookup failed for {}", args.key))?;
    let value = secret.expose(|bytes| bytes.to_vec());
    let value = secret_bytes_to_utf8(&value)?;
    println!("{}", value);
    Ok(())
}

fn run_derive_agent_did(args: DeriveAgentDidArgs) -> Result<(), String> {
    let secret_key = read_openpgp_input("--secret", args.secret.as_deref(), args.input.as_ref())?;
    let (private_key, public_key) = derive_agent_keypair(&secret_key, &args.agent_name)?;
    let (did, vm_id, doc) = build_did_document(&public_key)?;
    let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;

    store_derived_agent_identity(
        args.prefix.trim_end_matches('/'),
        &args.agent_name,
        &private_key,
        &public_key,
        &did,
        &output,
        None,
    )?;

    if let Some(out_file) = args.out_file.as_ref() {
        std::fs::write(out_file, format!("{}\n", output)).map_err(|err| {
            format!("failed to write {}: {}", out_file.display(), err)
        })?;
    }

    println!("DID: {}", did);
    println!("Verification Method ID: {}", vm_id);
    println!("Stored private key: {}/{}/private", args.prefix.trim_end_matches('/'), args.agent_name);
    println!("Stored public key: {}/{}/public", args.prefix.trim_end_matches('/'), args.agent_name);
    println!("Stored DID: {}/{}/did", args.prefix.trim_end_matches('/'), args.agent_name);
    println!("Stored DID Document: {}/{}/diddoc", args.prefix.trim_end_matches('/'), args.agent_name);
    if let Some(out_file) = args.out_file.as_ref() {
        println!("Wrote DID Document: {}", out_file.display());
    }
    Ok(())
}

fn run_derive_agent_identity(args: DeriveAgentIdentityArgs) -> Result<(), String> {
    let seed_material = match args.source {
        HumanIdentitySource::Gpg => read_openpgp_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?,
        HumanIdentitySource::Seed => read_seed_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?,
    };

    let human_did = match args.human_did_key.as_deref() {
        Some(key) => {
            let store = default_secret_store();
            let secret = store
                .get(key)
                .map_err(|_| format!("keychain lookup failed for {}", key))?;
            Some(secret_bytes_to_utf8(&secret.expose(|bytes| bytes.to_vec()))?)
        }
        None => None,
    };

    let prefix = args.prefix.trim_end_matches('/');
    if let Some(out_dir) = args.out_dir.as_ref() {
        std::fs::create_dir_all(out_dir)
            .map_err(|err| format!("failed to create {}: {}", out_dir.display(), err))?;
    }

    for agent_name in &args.agent_names {
        let (private_key, public_key) = derive_agent_keypair(&seed_material, agent_name)?;
        let (did, vm_id, doc) = build_did_document(&public_key)?;
        let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;

        store_derived_agent_identity(
            prefix,
            agent_name,
            &private_key,
            &public_key,
            &did,
            &output,
            human_did.as_deref(),
        )?;

        if let Some(out_dir) = args.out_dir.as_ref() {
            let out_file = out_dir.join(format!("{}.did.json", agent_name));
            std::fs::write(&out_file, format!("{}\n", output)).map_err(|err| {
                format!("failed to write {}: {}", out_file.display(), err)
            })?;
            println!("Wrote DID Document: {}", out_file.display());
        }

        println!("Agent: {}", agent_name);
        println!("DID: {}", did);
        println!("Verification Method ID: {}", vm_id);
        println!("Stored private key: {}/{}/private", prefix, agent_name);
        println!("Stored public key: {}/{}/public", prefix, agent_name);
        println!("Stored DID: {}/{}/did", prefix, agent_name);
        println!("Stored DID Document: {}/{}/diddoc", prefix, agent_name);
        if args.human_did_key.is_some() {
            println!("Stored human binding: {}/{}/human_did", prefix, agent_name);
        }
    }

    Ok(())
}

fn run_verify_agent_identity(args: VerifyAgentIdentityArgs) -> Result<(), String> {
    let seed_material = match args.source {
        HumanIdentitySource::Gpg => read_openpgp_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?,
        HumanIdentitySource::Seed => read_seed_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?,
    };

    let (_private_key, expected_public_key) = derive_agent_keypair(&seed_material, &args.agent_name)?;
    let (expected_did, _vm_id, _doc) = build_did_document(&expected_public_key)?;

    let prefix = args.prefix.trim_end_matches('/');
    let public_key_name = args
        .public_key_key
        .clone()
        .unwrap_or_else(|| format!("{}/{}/public", prefix, args.agent_name));
    let did_key_name = args
        .did_key
        .clone()
        .unwrap_or_else(|| format!("{}/{}/did", prefix, args.agent_name));

    let store = default_secret_store();
    let stored_public_b64 = store
        .get(&public_key_name)
        .map_err(|_| format!("keychain lookup failed for {}", public_key_name))?
        .expose(|bytes| bytes.to_vec());
    let stored_public_b64 = secret_bytes_to_utf8(&stored_public_b64)?;
    let stored_public_key = base64::engine::general_purpose::STANDARD
        .decode(stored_public_b64.as_bytes())
        .map_err(|err| format!("failed to decode {}: {}", public_key_name, err))?;

    if stored_public_key != expected_public_key {
        return Err("agent public key mismatch: derived key does not match stored key".to_string());
    }

    let stored_did = store
        .get(&did_key_name)
        .map_err(|_| format!("keychain lookup failed for {}", did_key_name))?
        .expose(|bytes| bytes.to_vec());
    let stored_did = secret_bytes_to_utf8(&stored_did)?;

    if stored_did != expected_did {
        return Err("agent DID mismatch: derived DID does not match stored DID".to_string());
    }

    if args.require_human_binding || args.human_did_key.is_some() {
        let binding_key = format!("{}/{}/human_did", prefix, args.agent_name);
        let bound_human_did = store
            .get(&binding_key)
            .map_err(|_| format!("missing human binding at {}", binding_key))?
            .expose(|bytes| bytes.to_vec());
        let bound_human_did = secret_bytes_to_utf8(&bound_human_did)?;

        if let Some(human_did_key) = args.human_did_key.as_deref() {
            let expected_human_did = store
                .get(human_did_key)
                .map_err(|_| format!("keychain lookup failed for {}", human_did_key))?
                .expose(|bytes| bytes.to_vec());
            let expected_human_did = secret_bytes_to_utf8(&expected_human_did)?;

            if bound_human_did != expected_human_did {
                return Err("human binding mismatch: agent bound DID does not match expected human DID".to_string());
            }
        }
    }

    println!("verified: true");
    println!("agent: {}", args.agent_name);
    println!("stored_public_key: {}", public_key_name);
    println!("stored_did: {}", did_key_name);
    println!("derived_did: {}", expected_did);

    Ok(())
}

fn store_derived_agent_identity(
    prefix: &str,
    agent_name: &str,
    private_key: &[u8],
    public_key: &[u8],
    did: &str,
    diddoc_json: &str,
    human_did: Option<&str>,
) -> Result<(), String> {
    let private_key_name = format!("{}/{}/private", prefix, agent_name);
    let public_key_name = format!("{}/{}/public", prefix, agent_name);
    let did_key_name = format!("{}/{}/did", prefix, agent_name);
    let diddoc_key_name = format!("{}/{}/diddoc", prefix, agent_name);

    let store = default_secret_store();
    let private_b64 = base64::engine::general_purpose::STANDARD.encode(private_key);
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    store
        .put(&private_key_name, private_b64.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", private_key_name, err))?;
    store
        .put(&public_key_name, public_b64.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", public_key_name, err))?;
    store
        .put(&did_key_name, did.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", did_key_name, err))?;
    store
        .put(&diddoc_key_name, diddoc_json.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", diddoc_key_name, err))?;

    if let Some(human_did) = human_did {
        let binding_key = format!("{}/{}/human_did", prefix, agent_name);
        store
            .put(&binding_key, human_did.as_bytes(), SecretPolicy::default())
            .map_err(|err| format!("failed to store secret {}: {}", binding_key, err))?;
    }

    Ok(())
}

fn read_seed_input(
    label: &str,
    secret_key: Option<&str>,
    input: Option<&PathBuf>,
) -> Result<Vec<u8>, String> {
    if let Some(secret_key) = secret_key {
        let store = default_secret_store();
        let secret = store
            .get(secret_key)
            .map_err(|_| format!("keychain lookup failed for {}", secret_key))?;
        return Ok(secret.expose(|bytes| bytes.to_vec()));
    }

    if let Some(input) = input {
        return std::fs::read(input)
            .map_err(|err| format!("failed to read {}: {}", input.display(), err));
    }

    Err(format!("missing {} or --in", label))
}

fn build_did_document(pkey: &[u8]) -> Result<(String, String, serde_json::Value), String> {
    let pubkey = if pkey.len() == 33 && pkey[0] == 0x40 {
        pkey[1..].to_vec()
    } else if pkey.len() == 32 {
        pkey.to_vec()
    } else {
        return Err(format!(
            "unexpected Ed25519 key material length: {}",
            pkey.len()
        ));
    };

    let mut multicodec = Vec::with_capacity(2 + pubkey.len());
    multicodec.push(0xED);
    multicodec.push(0x01);
    multicodec.extend_from_slice(&pubkey);
    let fingerprint = format!("z{}", bs58::encode(multicodec).into_string());

    let did = format!("did:key:{}", fingerprint);
    let vm_id = format!("{}#{}", did, fingerprint);

    let doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": fingerprint
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
        "capabilityDelegation": [vm_id],
        "capabilityInvocation": [vm_id]
    });

    Ok((did, vm_id, doc))
}

fn run_put_key_command(args: &[String]) -> ExitCode {
    let parsed = match PutKeyArgs::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };

    match run_put_key(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

fn run_put_key(args: PutKeyArgs) -> Result<(), String> {
    let payload = std::fs::read(&args.input)
        .map_err(|err| format!("failed to read {}: {}", args.input.display(), err))?;
    let store = default_secret_store();
    store
        .put(&args.key, &payload, SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", args.key, err))?;
    println!("Stored OpenPGP key in secret: {}", args.key);
    Ok(())
}

fn read_openpgp_input(
    label: &str,
    secret_key: Option<&str>,
    input: Option<&PathBuf>,
) -> Result<Vec<u8>, String> {
    if let Some(secret_key) = secret_key {
        let store = default_secret_store();
        let secret = store
            .get(secret_key)
            .map_err(|_| format!("keychain lookup failed for {}", secret_key))?;
        return Ok(secret.expose(|bytes| bytes.to_vec()));
    }

    if let Some(input) = input {
        return std::fs::read(input)
            .map_err(|err| format!("failed to read {}: {}", input.display(), err));
    }

    Err(format!("missing {} or --in", label))
}

fn fetch_github_gpg_key(user: &str) -> Result<Vec<u8>, String> {
    let payload = github_api_get_gpg_keys(user)?;
    extract_github_public_key(&payload).and_then(decode_github_public_key)
}

fn extract_github_public_key(payload: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(payload).map_err(|err| err.to_string())?;
    let keys = value
        .as_array()
        .ok_or_else(|| "unexpected GitHub response format".to_string())?;
    let first = keys
        .first()
        .ok_or_else(|| "no GPG keys found for GitHub user".to_string())?;
    let public_key = first
        .get("public_key")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing public_key in GitHub response".to_string())?;
    Ok(public_key.to_string())
}

fn decode_github_public_key(public_key: String) -> Result<Vec<u8>, String> {
    if public_key.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        return Ok(public_key.into_bytes());
    }

    let compact = public_key
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("");
    if compact.is_empty() {
        return Err("GitHub public_key is empty".to_string());
    }

    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|err| format!("failed to decode GitHub public_key: {}", err))
}

#[cfg(test)]
static TEST_GITHUB_PAYLOAD: OnceLock<Mutex<Option<String>>> = OnceLock::new();

#[cfg(test)]
fn test_github_payload_slot() -> &'static Mutex<Option<String>> {
    TEST_GITHUB_PAYLOAD.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn set_test_github_payload(payload: Option<String>) {
    let mut guard = test_github_payload_slot().lock().expect("github payload lock");
    *guard = payload;
}

#[cfg(test)]
fn github_api_get_gpg_keys(_user: &str) -> Result<String, String> {
    let guard = test_github_payload_slot().lock().expect("github payload lock");
    guard
        .clone()
        .ok_or_else(|| "test github payload not set".to_string())
}

#[cfg(not(test))]
fn github_api_get_gpg_keys(user: &str) -> Result<String, String> {
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| "GH_TOKEN or GITHUB_TOKEN must be set for GitHub API".to_string())?;

    let url = format!("https://api.github.com/users/{}/gpg_keys", user);
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
    headers.insert(USER_AGENT, HeaderValue::from_static("shadi-shadictl"));
    let auth = format!("Bearer {}", token);
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth).map_err(|_| "invalid GitHub token".to_string())?,
    );

    let client = Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|err| format!("failed to build HTTP client: {}", err))?;

    let response = client
        .get(url)
        .send()
        .map_err(|err| format!("GitHub API request failed: {}", err))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(format!("GitHub API error {}: {}", status, body));
    }

    response.text().map_err(|err| format!("failed to read GitHub response: {}", err))
}


fn derive_agent_keypair(secret_key: &[u8], agent_name: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    if agent_name.trim().is_empty() {
        return Err("agent name cannot be empty".to_string());
    }
    let hk = Hkdf::<Sha256>::new(Some(b"shadi-agent-derive"), secret_key);
    let mut seed = [0u8; 32];
    hk.expand(agent_name.as_bytes(), &mut seed)
        .map_err(|_| "failed to derive agent key".to_string())?;
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    Ok((signing.to_bytes().to_vec(), verifying.to_bytes().to_vec()))
}

fn extract_ed25519_public_key(openpgp_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use openpgp::crypto::mpi::PublicKey as MpiPublicKey;
    use openpgp::crypto::Curve;
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;

    let cert = openpgp::Cert::from_reader(openpgp_bytes)
        .map_err(|err| format!("failed to parse OpenPGP certificate: {}", err))?;
    let policy = &StandardPolicy::new();

    for key in cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
    {
        match key.key().mpis() {
            MpiPublicKey::Ed25519 { a } => return Ok(a.to_vec()),
            MpiPublicKey::EdDSA { curve, q } if *curve == Curve::Ed25519 => {
                return Ok(q.value().to_vec());
            }
            _ => {}
        }
    }

    Err("no Ed25519 public key found in OpenPGP certificate".to_string())
}


fn format_policy(
    policy: &SandboxPolicy,
    blocked: &HashSet<String>,
    allow: &HashSet<String>,
) -> Result<String, String> {
    #[derive(serde::Serialize)]
    struct PolicyDump {
        allow: Vec<String>,
        read: Vec<String>,
        write: Vec<String>,
        net_block: bool,
        allow_command: Vec<String>,
        block_command: Vec<String>,
    }

    let allow_paths = policy
        .allow_read()
        .iter()
        .filter(|path| policy.allow_write().iter().any(|write| write == *path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let read_paths = policy
        .allow_read()
        .iter()
        .filter(|path| !policy.allow_write().iter().any(|write| write == *path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let write_paths = policy
        .allow_write()
        .iter()
        .filter(|path| !policy.allow_read().iter().any(|read| read == *path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let mut blocked_list = blocked.iter().cloned().collect::<Vec<_>>();
    blocked_list.sort();
    let mut allow_list = allow.iter().cloned().collect::<Vec<_>>();
    allow_list.sort();

    let dump = PolicyDump {
        allow: allow_paths,
        read: read_paths,
        write: write_paths,
        net_block: policy.net_blocked(),
        allow_command: allow_list,
        block_command: blocked_list,
    };

    serde_json::to_string_pretty(&dump).map_err(|err| err.to_string())
}

fn resolve_policy(cli: &Cli, file_policy: &PolicyFile) -> Result<ResolvedPolicy, String> {
    let mut blocked = default_blocked_commands()
        .into_iter()
        .map(|cmd| cmd.to_string())
        .collect::<HashSet<_>>();
    for cmd in file_policy.block_command.iter() {
        blocked.insert(cmd.to_string());
    }

    let mut allow = file_policy
        .allow_command
        .iter()
        .map(|cmd| cmd.to_string())
        .collect::<HashSet<_>>();
    for cmd in cli.allow_command.iter() {
        allow.insert(cmd.to_string());
    }

    let profile_name = match cli.profile.unwrap_or(LauncherProfile::Balanced) {
        LauncherProfile::Strict => "strict",
        LauncherProfile::Balanced => "balanced",
        LauncherProfile::Connected => "connected",
    };
    let span = info_span!(
        "shadi.policy.resolve",
        policy.allowed_paths = field::Empty,
        network.mode = field::Empty,
        policy.profile = %profile_name,
    );
    let _guard = span.enter();

    let profile = profile_defaults(cli.profile);
    let profile_net_block = profile.net_block.unwrap_or(false);
    let mut policy = SandboxPolicy::new().block_network(cli.net_block || file_policy.net_block.unwrap_or(profile_net_block));

    policy = apply_string_paths(policy, &profile.read, PathMode::Read)?;
    policy = apply_string_paths(policy, &profile.write, PathMode::Write)?;
    policy = apply_string_paths(policy, &profile.allow, PathMode::Allow)?;

    policy = apply_string_paths(policy, &file_policy.read, PathMode::Read)?;
    policy = apply_string_paths(policy, &file_policy.write, PathMode::Write)?;
    policy = apply_string_paths(policy, &file_policy.allow, PathMode::Allow)?;

    policy = apply_paths(policy, &cli.read, PathMode::Read)?;
    policy = apply_paths(policy, &cli.write, PathMode::Write)?;
    policy = apply_paths(policy, &cli.allow, PathMode::Allow)?;

    let mut allowed_paths = BTreeSet::new();
    allowed_paths.extend(policy.allow_read().iter().cloned());
    allowed_paths.extend(policy.allow_write().iter().cloned());
    span.record("policy.allowed_paths", &(allowed_paths.len() as i64));
    let network_mode = if policy.net_blocked() { "blocked" } else { "allowed" };
    span.record("network.mode", &field::display(network_mode));

    Ok(ResolvedPolicy {
        policy,
        blocked,
        allow,
    })
}

fn profile_defaults(profile: Option<LauncherProfile>) -> PolicyFile {
    match profile.unwrap_or(LauncherProfile::Balanced) {
        LauncherProfile::Strict => PolicyFile {
            allow: vec![".".to_string()],
            read: vec![".".to_string()],
            write: Vec::new(),
            net_block: Some(true),
            allow_command: Vec::new(),
            block_command: Vec::new(),
        },
        LauncherProfile::Balanced => PolicyFile {
            allow: vec![".".to_string()],
            read: vec!["/".to_string()],
            write: Vec::new(),
            net_block: Some(true),
            allow_command: Vec::new(),
            block_command: Vec::new(),
        },
        LauncherProfile::Connected => PolicyFile {
            allow: vec![".".to_string()],
            read: vec!["/".to_string()],
            write: Vec::new(),
            net_block: Some(false),
            allow_command: Vec::new(),
            block_command: Vec::new(),
        },
    }
}

fn is_command_blocked(cmd: &str, blocked: &HashSet<String>, allow: &HashSet<String>) -> bool {
    blocked.contains(cmd) && !allow.contains(cmd)
}

enum PathMode {
    Read,
    Write,
    Allow,
}

fn apply_string_paths(
    mut policy: SandboxPolicy,
    paths: &[String],
    mode: PathMode,
) -> Result<SandboxPolicy, String> {
    for path in paths.iter() {
        let path = canonicalize_string_path(path)
            .map_err(|err| format!("invalid {} path {}: {}", mode.label(), path, err))?;
        policy = apply_path(policy, &path, &mode);
    }
    Ok(policy)
}

fn apply_paths(
    mut policy: SandboxPolicy,
    paths: &[PathBuf],
    mode: PathMode,
) -> Result<SandboxPolicy, String> {
    for path in paths.iter() {
        let path = canonicalize_path(path)
            .map_err(|err| format!("invalid {} path {}: {}", mode.label(), path.display(), err))?;
        policy = apply_path(policy, &path, &mode);
    }
    Ok(policy)
}

fn apply_path(mut policy: SandboxPolicy, path: &PathBuf, mode: &PathMode) -> SandboxPolicy {
    match mode {
        PathMode::Read => policy = policy.allow_read_path(path),
        PathMode::Write => policy = policy.allow_write_path(path),
        PathMode::Allow => policy = policy.allow_read_path(path).allow_write_path(path),
    }
    policy
}

impl PathMode {
    fn label(&self) -> &'static str {
        match self {
            PathMode::Read => "read",
            PathMode::Write => "write",
            PathMode::Allow => "allow",
        }
    }
}

fn list_keychain(prefix: Option<&str>) -> Result<(), String> {
    let store = default_secret_store();
    let keys = list_keychain_with_store(store.as_ref(), prefix)?;
    for key in keys {
        println!("{}", key);
    }
    Ok(())
}

fn list_keychain_with_store(
    store: &dyn SecretStore,
    prefix: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut keys = store.list_keys().map_err(|err| err.to_string())?;
    if let Some(prefix) = prefix {
        keys.retain(|key| key.starts_with(prefix));
    }
    keys.sort();
    Ok(keys)
}

fn canonicalize_path(path: &PathBuf) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

fn canonicalize_string_path(path: &str) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(Path::new(path))
}

fn load_policy_file(path: &Path) -> std::io::Result<PolicyFile> {
    let span = info_span!("shadi.policy.load", policy.source = %path.display());
    let _guard = span.enter();
    let data = std::fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn inject_keychain_secrets(command: &mut Command, mappings: &[String]) -> Result<(), String> {
    if mappings.is_empty() {
        return Ok(());
    }

    let span = info_span!("shadi.secrets.inject", secret.count = mappings.len() as i64);
    let _guard = span.enter();
    let store = default_secret_store();
    inject_keychain_with_store(store.as_ref(), command, mappings)
}

fn inject_keychain_with_store(
    store: &dyn SecretStore,
    command: &mut Command,
    mappings: &[String],
) -> Result<(), String> {
    for mapping in mappings {
        let (key, env) = parse_key_env(mapping)?;
        let secret = store
            .get(key)
            .map_err(|_| format!("keychain lookup failed for {}", key))?;
        let value = secret.expose(|bytes| bytes.to_vec());
        let value = secret_bytes_to_utf8(&value)?;
        command.env(env, value);
    }

    Ok(())
}

fn secret_bytes_to_utf8(value: &[u8]) -> Result<String, String> {
    String::from_utf8(value.to_vec()).map_err(|_| "secret is not utf-8".to_string())
}

fn parse_key_env(value: &str) -> Result<(&str, &str), String> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("");
    let env = parts.next().unwrap_or("");
    if key.is_empty() || env.is_empty() {
        return Err("inject-keychain must be in KEY=ENV format".to_string());
    }
    Ok((key, env))
}

fn default_blocked_commands() -> HashSet<&'static str> {
    [
        "rm",
        "rmdir",
        "shred",
        "srm",
        "dd",
        "mkfs",
        "fdisk",
        "parted",
        "wipefs",
        "chmod",
        "chown",
        "chgrp",
        "chattr",
        "shutdown",
        "reboot",
        "halt",
        "systemctl",
        "apt",
        "brew",
        "pip",
        "yum",
        "pacman",
        "mv",
        "cp",
        "truncate",
        "sudo",
        "su",
        "doas",
        "pkexec",
        "scp",
        "rsync",
        "sftp",
        "ftp",
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use agent_secrets::{SecretError, SecretResult};
    use agent_secrets::memory::SecretBytes;
    use agent_secrets::policy::SecretPolicy;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn build_cli() -> Cli {
        Cli {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            inject_keychain: Vec::new(),
            list_keychain: false,
            list_prefix: None,
            print_policy: false,
            git_snapshot: false,
            git_snapshot_dir: None,
            git_snapshot_untracked: false,
            command: vec!["echo".to_string(), "ok".to_string()],
        }
    }

    fn run_git(cwd: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(args)
            .output()
            .expect("run git");
        if !output.status.success() {
            panic!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn init_git_repo() -> TempDir {
        let dir = temp_dir();
        run_git(dir.path(), &["init"]);
        run_git(dir.path(), &["config", "user.name", "SHADI Tests"]);
        run_git(dir.path(), &["config", "user.email", "shadi-tests@example.com"]);
        dir
    }

    fn seed_git_repo(repo_path: &Path) {
        let tracked = repo_path.join("tracked.txt");
        std::fs::write(&tracked, "initial\n").expect("write tracked file");
        run_git(repo_path, &["add", "tracked.txt"]);
        run_git(repo_path, &["commit", "-m", "initial"]);
    }

    fn init_nested_git_repo(parent: &Path, name: &str) -> PathBuf {
        let repo_path = parent.join(name);
        std::fs::create_dir_all(&repo_path).expect("create nested repo dir");
        run_git(&repo_path, &["init"]);
        run_git(&repo_path, &["config", "user.name", "SHADI Tests"]);
        run_git(&repo_path, &["config", "user.email", "shadi-tests@example.com"]);
        repo_path
    }

    fn git_snapshot_artifacts(dir: &Path) -> Vec<PathBuf> {
        let mut entries = std::fs::read_dir(dir.join("runs"))
            .expect("read snapshot dir")
            .map(|entry| entry.expect("dir entry").path().join("snapshot.json"))
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn snapshot_test_command() -> (Vec<String>, PathBuf) {
        #[cfg(target_os = "macos")]
        {
            (
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf 'changed\n' >> tracked.txt && printf 'new\n' > note.txt".to_string(),
                ],
                PathBuf::from("/bin"),
            )
        }

        #[cfg(target_os = "windows")]
        {
            let system32 = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
                + "\\System32";
            (
                vec![
                    format!("{}\\cmd.exe", system32),
                    "/C".to_string(),
                    "echo changed>>tracked.txt && echo new>note.txt".to_string(),
                ],
                PathBuf::from(system32),
            )
        }
    }

    fn sample_openpgp_cert_armored() -> Vec<u8> {
        use openpgp::cert::prelude::*;
        use openpgp::serialize::Serialize;

        let (cert, _) = CertBuilder::general_purpose(Some("alice@example.org"))
            .generate()
            .expect("generate cert");
        let mut exported = Vec::new();
        cert.armored().export(&mut exported).expect("export cert");
        exported
    }

    fn sample_openpgp_secret_armored() -> Vec<u8> {
        use openpgp::cert::prelude::*;
        use openpgp::serialize::Serialize;

        let (cert, _) = CertBuilder::general_purpose(Some("alice@example.org"))
            .generate()
            .expect("generate cert");
        let mut exported = Vec::new();
        cert.as_tsk()
            .armored()
            .export(&mut exported)
            .expect("export secret key");
        exported
    }

    fn unique_key(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    fn policy_from_paths(read: &[PathBuf], write: &[PathBuf], allow: &[PathBuf]) -> PolicyFile {
        PolicyFile {
            read: read.iter().map(|p| p.display().to_string()).collect(),
            write: write.iter().map(|p| p.display().to_string()).collect(),
            allow: allow.iter().map(|p| p.display().to_string()).collect(),
            net_block: Some(false),
            allow_command: Vec::new(),
            block_command: Vec::new(),
        }
    }

    #[test]
    fn resolve_policy_merges_paths_and_commands() {
        let read_dir = temp_dir();
        let write_dir = temp_dir();
        let allow_dir = temp_dir();
        let read_path = read_dir.path().canonicalize().expect("canonicalize");
        let write_path = write_dir.path().canonicalize().expect("canonicalize");
        let allow_path = allow_dir.path().canonicalize().expect("canonicalize");

        let mut cli = build_cli();
        cli.read.push(read_path.clone());
        cli.allow_command.push("rm".to_string());

        let policy_file = policy_from_paths(&[], &[write_path.clone()], &[allow_path.clone()]);
        let resolved = resolve_policy(&cli, &policy_file).expect("resolve");

        assert!(resolved.policy.allow_read().iter().any(|p| p == &read_path));
        assert!(resolved.policy.allow_write().iter().any(|p| p == &write_path));
        assert!(resolved.policy.allow_read().iter().any(|p| p == &allow_path));
        assert!(resolved.policy.allow_write().iter().any(|p| p == &allow_path));
        assert!(resolved.allow.contains("rm"));
    }

    #[test]
    fn resolve_policy_rejects_missing_paths() {
        let cli = build_cli();
        let policy_file = PolicyFile {
            read: vec!["/path/does/not/exist".to_string()],
            write: Vec::new(),
            allow: Vec::new(),
            net_block: Some(false),
            allow_command: Vec::new(),
            block_command: Vec::new(),
        };

        let err = resolve_policy(&cli, &policy_file).unwrap_err();
        assert!(err.contains("invalid read path"));
    }

    #[test]
    fn resolve_policy_sets_net_block() {
        let mut cli = build_cli();
        cli.net_block = true;
        let policy_file = PolicyFile::default();
        let resolved = resolve_policy(&cli, &policy_file).expect("resolve");
        assert!(resolved.policy.net_blocked());
    }

    #[test]
    fn resolve_policy_honors_file_net_block() {
        let cli = build_cli();
        let policy_file = PolicyFile {
            net_block: Some(true),
            ..PolicyFile::default()
        };
        let resolved = resolve_policy(&cli, &policy_file).expect("resolve");
        assert!(resolved.policy.net_blocked());
    }

    #[test]
    fn resolve_policy_uses_balanced_profile_by_default() {
        let cli = build_cli();
        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve");
        let default_read = canonicalize_string_path("/").expect("canonical root path");
        assert!(resolved.policy.net_blocked());
        assert!(resolved
            .policy
            .allow_read()
            .iter()
            .any(|path| path == &default_read));
    }

    #[test]
    fn resolve_policy_uses_connected_profile() {
        let mut cli = build_cli();
        cli.profile = Some(LauncherProfile::Connected);
        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve");
        assert!(!resolved.policy.net_blocked());
    }

    #[test]
    fn resolve_policy_uses_strict_profile() {
        let mut cli = build_cli();
        cli.profile = Some(LauncherProfile::Strict);
        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve");
        let default_read = canonicalize_string_path("/").expect("canonical root path");
        assert!(resolved.policy.net_blocked());
        assert!(!resolved
            .policy
            .allow_read()
            .iter()
            .any(|path| path == &default_read));
    }

    #[test]
    fn resolve_policy_merges_command_lists() {
        let mut cli = build_cli();
        cli.allow_command.push("rm".to_string());
        let policy_file = PolicyFile {
            allow_command: vec!["echo".to_string()],
            block_command: vec!["rm".to_string()],
            ..PolicyFile::default()
        };
        let resolved = resolve_policy(&cli, &policy_file).expect("resolve");
        assert!(resolved.blocked.contains("rm"));
        assert!(resolved.allow.contains("rm"));
        assert!(resolved.allow.contains("echo"));
    }

    #[test]
    fn is_command_blocked_allows_unknown_when_not_blocked() {
        let blocked = default_blocked_commands()
            .into_iter()
            .map(|cmd| cmd.to_string())
            .collect::<HashSet<_>>();
        let allow = HashSet::new();
        assert!(!is_command_blocked("echo", &blocked, &allow));
    }

    #[test]
    fn command_blocking_respects_allowlist() {
        let blocked = default_blocked_commands()
            .into_iter()
            .map(|cmd| cmd.to_string())
            .collect::<HashSet<_>>();
        let mut allow = HashSet::new();
        allow.insert("rm".to_string());

        assert!(!is_command_blocked("rm", &blocked, &allow));
        assert!(is_command_blocked("mv", &blocked, &HashSet::new()));
    }

    #[test]
    fn format_policy_sorts_commands() {
        let policy = SandboxPolicy::new();
        let blocked = ["rm".to_string(), "cp".to_string()].into_iter().collect();
        let allow = ["zsh".to_string(), "bash".to_string()].into_iter().collect();

        let output = format_policy(&policy, &blocked, &allow).expect("format");
        assert!(output.contains("\"block_command\""));
        assert!(output.contains("\"allow_command\""));
    }

    #[test]
    fn format_policy_groups_allow_paths() {
        let dir = temp_dir();
        let path = dir.path().canonicalize().expect("canonicalize");
        let policy = SandboxPolicy::new()
            .allow_read_path(&path)
            .allow_write_path(&path);
        let output = format_policy(&policy, &HashSet::new(), &HashSet::new()).expect("format");
        let path_str = path.display().to_string().replace('\\', "\\\\");
        assert!(output.contains(&path_str));
    }

    #[test]
    fn format_policy_separates_read_and_write() {
        let read_dir = temp_dir();
        let write_dir = temp_dir();
        let read_path = read_dir.path().canonicalize().expect("canonicalize");
        let write_path = write_dir.path().canonicalize().expect("canonicalize");
        let policy = SandboxPolicy::new()
            .allow_read_path(&read_path)
            .allow_write_path(&write_path);
        let output = format_policy(&policy, &HashSet::new(), &HashSet::new()).expect("format");
        let read_str = read_path.display().to_string().replace('\\', "\\\\");
        let write_str = write_path.display().to_string().replace('\\', "\\\\");
        assert!(output.contains(&read_str));
        assert!(output.contains(&write_str));
    }

    #[test]
    fn load_policy_file_parses_json() {
        let dir = temp_dir();
        let path = dir.path().join("policy.json");
        let tmp_dir = std::env::var("SHADI_TMP_DIR").unwrap_or_else(|_| "./.tmp".to_string());
        std::fs::write(
            &path,
            format!(r#"{{"allow": ["{}"], "net_block": true}}"#, tmp_dir),
        )
        .expect("write");

        let policy = load_policy_file(&path).expect("load");
        assert_eq!(policy.allow, vec![tmp_dir]);
        assert_eq!(policy.net_block, Some(true));
    }

    #[test]
    fn load_policy_file_rejects_invalid_json() {
        let dir = temp_dir();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, "not-json").expect("write");
        let err = load_policy_file(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn run_cli_missing_command_returns_error() {
        let mut cli = build_cli();
        cli.command.clear();
        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_print_policy_returns_ok() {
        let mut cli = build_cli();
        cli.command.clear();
        cli.print_policy = true;
        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
    }

    #[test]
    fn run_cli_blocks_disallowed_command() {
        let mut cli = build_cli();
        cli.command = vec!["rm".to_string()];
        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn run_cli_executes_allowed_command() {
        let mut cli = build_cli();
        cli.command = vec!["/usr/bin/true".to_string()];
        cli.allow.push(PathBuf::from("/usr/bin"));
        let code = run_cli(cli);
        assert_ne!(code, ExitCode::from(2));
    }

    #[test]
    fn summarize_status_lines_counts_git_changes() {
        let summary = summarize_status_lines(&[
            " M tracked.txt".to_string(),
            "A  staged.txt".to_string(),
            "R  old.txt -> new.txt".to_string(),
            "?? scratch.txt".to_string(),
        ]);

        assert_eq!(summary.modified, 1);
        assert_eq!(summary.added, 1);
        assert_eq!(summary.renamed, 1);
        assert_eq!(summary.untracked, 1);
        assert!(summary.changed);
    }

    #[test]
    fn git_snapshot_layout_default_starts_empty() {
        let layout = GitSnapshotLayout::default();

        assert!(layout.root_dir.is_empty());
        assert!(layout.run_dir.is_empty());
        assert!(layout.snapshot_file.is_empty());
        assert!(layout.latest_file.is_empty());
    }

    #[test]
    fn finalize_git_snapshot_accepts_none() {
        finalize_git_snapshot(None, Some(0), None);
    }

    #[test]
    fn finalize_git_snapshot_handles_write_failure() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let mut cli = build_cli();
        cli.command = vec!["portable-test".to_string()];
        cli.git_snapshot = true;

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let mut session = GitSnapshotSession::start(&cli, &resolved, &repo_path).expect("start snapshot");

        let blocking_file = temp_dir();
        let blocking_path = blocking_file.path().join("snapshot-blocker");
        std::fs::write(&blocking_path, "occupied\n").expect("write blocking file");
        session.output_dir = blocking_path;

        finalize_git_snapshot(Some(&mut session), Some(0), None);
    }

    #[test]
    fn run_sandboxed_command_returns_error_when_process_cannot_start() {
        let cwd_root = temp_dir();
        let cwd = cwd_root.path().canonicalize().expect("canonical cwd");

        let mut cli = build_cli();
        cli.command = vec![cwd.join("missing-command").display().to_string()];
        cli.allow.push(cwd.clone());

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &cwd);

        assert_eq!(exit, ExitCode::from(1));
    }

    #[test]
    fn git_snapshot_session_writes_artifact_without_sandbox() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        cli.command = vec!["portable-test".to_string()];
        cli.git_snapshot = true;
        cli.git_snapshot_untracked = true;
        cli.git_snapshot_dir = Some(snapshot_dir.clone());

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let mut session = GitSnapshotSession::start(&cli, &resolved, &repo_path).expect("start snapshot");

        let tracked = repo_path.join("tracked.txt");
        let mut tracked_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&tracked)
            .expect("open tracked file");
        use std::io::Write as _;
        writeln!(tracked_file, "changed").expect("append tracked file");
        std::fs::write(repo_path.join("note.txt"), "new\n").expect("write untracked file");

        let artifact_path = session.finish(Some(0), None).expect("finish snapshot");
        assert!(artifact_path.starts_with(snapshot_dir.join("runs")));

        let payload = std::fs::read_to_string(&artifact_path).expect("read artifact");
        let artifact: Value = serde_json::from_str(&payload).expect("parse artifact json");

        assert_eq!(artifact["schema_version"], 1);
        assert_eq!(artifact["git"]["detected"], true);
        assert_eq!(artifact["git"]["include_untracked_inventory"], true);
        assert_eq!(artifact["layout"]["root_dir"], snapshot_dir.display().to_string());
        assert_eq!(artifact["layout"]["latest_file"], snapshot_dir.join("latest.json").display().to_string());

        let run_dir = PathBuf::from(artifact["layout"]["run_dir"].as_str().expect("run dir"));
        assert!(run_dir.starts_with(snapshot_dir.join("runs")));
        assert!(artifact["git"]["before"]["status_porcelain"]
            .as_array()
            .expect("before status array")
            .is_empty());

        let after_status = artifact["git"]["after"]["status_porcelain"]
            .as_array()
            .expect("after status array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        assert!(after_status.iter().any(|line| line.contains("note.txt")));
        assert_eq!(artifact["git"]["diff_summary"]["untracked"], 1);
        assert!(artifact["git"]["after"]["diff_binary"]
            .as_str()
            .expect("after diff binary")
            .contains("tracked.txt"));

        let untracked = artifact["git"]["after"]["untracked_inventory"]
            .as_array()
            .expect("untracked inventory")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        assert!(untracked.contains(&"note.txt"));
        assert_eq!(artifact["git"]["comparison"]["overall_changed"], true);
        assert_eq!(artifact["git"]["comparison"]["status_changed"], true);
        assert_eq!(artifact["git"]["comparison"]["diff_changed"], true);
        assert!(artifact["git"]["before"]["hashes"]["state_sha256"]
            .as_str()
            .expect("before state hash")
            .len()
            == 64);
        assert!(artifact["git"]["after"]["hashes"]["state_sha256"]
            .as_str()
            .expect("after state hash")
            .len()
            == 64);
        assert_eq!(artifact["outcome"]["exit_code"], 0);

        let latest = std::fs::read_to_string(snapshot_dir.join("latest.json")).expect("read latest artifact");
        let latest_artifact: Value = serde_json::from_str(&latest).expect("parse latest artifact");
        assert_eq!(latest_artifact["artifact_id"], artifact["artifact_id"]);
    }

    #[test]
    fn git_snapshot_session_tracks_nested_repository_changes() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let nested_repo = init_nested_git_repo(&repo_path, "nested");
        std::fs::write(nested_repo.join("nested.txt"), "initial\n").expect("write nested file");
        run_git(&nested_repo, &["add", "nested.txt"]);
        run_git(&nested_repo, &["commit", "-m", "initial"]);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        cli.command = vec!["portable-test".to_string()];
        cli.git_snapshot = true;
        cli.git_snapshot_dir = Some(snapshot_dir.clone());

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let mut session = GitSnapshotSession::start(&cli, &resolved, &repo_path).expect("start snapshot");

        let nested_file = nested_repo.join("nested.txt");
        let mut nested_handle = std::fs::OpenOptions::new()
            .append(true)
            .open(&nested_file)
            .expect("open nested file");
        use std::io::Write as _;
        writeln!(nested_handle, "changed").expect("append nested file");
            drop(nested_handle);
        run_git(&nested_repo, &["add", "nested.txt"]);
        run_git(&nested_repo, &["commit", "-m", "update"]);

        let artifact_path = session.finish(Some(0), None).expect("finish snapshot");
        let payload = std::fs::read_to_string(&artifact_path).expect("read artifact");
        let artifact: Value = serde_json::from_str(&payload).expect("parse artifact json");

        assert_eq!(artifact["git"]["detected"], true);
        assert_eq!(artifact["git"]["any_repo_changed"], true);
        assert_eq!(artifact["git"]["changed_repositories"], 1);
        assert_eq!(artifact["git"]["comparison"]["overall_changed"], false);

        let repositories = artifact["git"]["repositories"]
            .as_array()
            .expect("repository array");
        assert_eq!(repositories.len(), 2);

        let nested = repositories
            .iter()
            .find(|repository| repository["relative_path"] == "nested")
            .expect("nested repository entry");
        assert_eq!(nested["comparison"]["overall_changed"], true);
        assert_eq!(nested["comparison"]["head_changed"], true);
        assert_eq!(nested["diff_summary"]["changed"], false);

        let primary = repositories
            .iter()
            .find(|repository| repository["relative_path"] == ".")
            .expect("primary repository entry");
        assert_eq!(primary["comparison"]["overall_changed"], false);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn run_sandboxed_command_writes_git_snapshot_artifact() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        let (command, command_prefix) = snapshot_test_command();
        cli.command = command;
        cli.allow.push(command_prefix);
        cli.allow.push(repo_path.clone());
        cli.git_snapshot = true;
        cli.git_snapshot_untracked = true;
        cli.git_snapshot_dir = Some(snapshot_dir.clone());

        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &repo_path);

        let artifacts = git_snapshot_artifacts(&snapshot_dir);
        assert_eq!(artifacts.len(), 1);

        let payload = std::fs::read_to_string(&artifacts[0]).expect("read artifact");
        let artifact: Value = serde_json::from_str(&payload).expect("parse artifact json");

        assert_eq!(artifact["schema_version"], 1);
        assert_eq!(artifact["git"]["detected"], true);
        assert_eq!(artifact["git"]["include_untracked_inventory"], true);
        assert_eq!(artifact["layout"]["root_dir"], snapshot_dir.display().to_string());
        assert_eq!(artifact["layout"]["latest_file"], snapshot_dir.join("latest.json").display().to_string());
        let run_dir = PathBuf::from(artifact["layout"]["run_dir"].as_str().expect("run dir"));
        assert!(run_dir.starts_with(snapshot_dir.join("runs")));

        #[cfg(target_os = "windows")]
        if let Some(error) = artifact["outcome"]["error"].as_str() {
            assert_eq!(exit, ExitCode::from(1));
            assert!(error.contains("CreateAppContainerProfile failed"));
            assert!(artifact["outcome"]["exit_code"].is_null());
            return;
        }

        assert_eq!(exit, ExitCode::from(0));
        assert!(artifact["git"]["before"]["status_porcelain"]
            .as_array()
            .expect("before status array")
            .is_empty());

        let after_status = artifact["git"]["after"]["status_porcelain"]
            .as_array()
            .expect("after status array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        assert!(after_status.iter().any(|line| line.contains("note.txt")));
        assert_eq!(artifact["git"]["diff_summary"]["untracked"], 1);
        assert!(artifact["git"]["after"]["diff_binary"]
            .as_str()
            .expect("after diff binary")
            .contains("tracked.txt"));

        let untracked = artifact["git"]["after"]["untracked_inventory"]
            .as_array()
            .expect("untracked inventory")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        assert!(untracked.contains(&"note.txt"));
        assert_eq!(artifact["git"]["comparison"]["overall_changed"], true);
        assert_eq!(artifact["git"]["comparison"]["status_changed"], true);
        assert_eq!(artifact["git"]["comparison"]["diff_changed"], true);
        assert!(artifact["git"]["before"]["hashes"]["state_sha256"]
            .as_str()
            .expect("before state hash")
            .len()
            == 64);
        assert!(artifact["git"]["after"]["hashes"]["state_sha256"]
            .as_str()
            .expect("after state hash")
            .len()
            == 64);
        assert_eq!(artifact["outcome"]["exit_code"], 0);
        assert!(artifact["outcome"]["error"].is_null());

        let latest = std::fs::read_to_string(snapshot_dir.join("latest.json")).expect("read latest artifact");
        let latest_artifact: Value = serde_json::from_str(&latest).expect("parse latest artifact");
        assert_eq!(latest_artifact["artifact_id"], artifact["artifact_id"]);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn run_cli_executes_allowed_command() {
        let mut cli = build_cli();
        let system32 = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
            + "\\System32";
        cli.command = vec![format!("{}\\where.exe", system32), "cmd".to_string()];
        cli.allow.push(PathBuf::from(&system32));
        let code = run_cli(cli);
        assert_ne!(code, ExitCode::from(2));
    }

    #[test]
    fn canonicalize_helpers_resolve_paths() {
        let dir = temp_dir();
        let path = canonicalize_path(&dir.path().to_path_buf()).expect("path");
        let text = canonicalize_string_path(dir.path().to_str().expect("str")).expect("str path");
        assert_eq!(path, text);
    }

    #[test]
    fn read_openpgp_input_reads_file() {
        let dir = temp_dir();
        let path = dir.path().join("key.asc");
        std::fs::write(&path, b"test-key").expect("write");

        let payload = read_openpgp_input("--key", None, Some(&path)).expect("read");
        assert_eq!(payload, b"test-key".to_vec());
    }

    #[test]
    fn read_openpgp_input_reports_missing() {
        let err = read_openpgp_input("--key", None, None).unwrap_err();
        assert!(err.contains("missing --key"));
    }

    #[test]
    fn read_openpgp_input_errors_on_missing_file() {
        let dir = temp_dir();
        let path = dir.path().join("missing.asc");
        let err = read_openpgp_input("--key", None, Some(&path)).unwrap_err();
        assert!(err.contains("failed to read"));
    }

    #[test]
    fn inject_keychain_noop_when_empty() {
        let mut command = Command::new("/usr/bin/true");
        inject_keychain_secrets(&mut command, &[]).expect("inject");
    }

    struct MemoryStore {
        entries: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
    }

    impl SecretStore for MemoryStore {
        fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
            let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            guard.insert(key.to_string(), secret.to_vec());
            Ok(())
        }

        fn get(&self, key: &str) -> SecretResult<SecretBytes> {
            let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            let value = guard.get(key).ok_or(SecretError::InvalidInput)?.clone();
            Ok(SecretBytes::new(value))
        }

        fn delete(&self, key: &str) -> SecretResult<()> {
            let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            guard.remove(key);
            Ok(())
        }

        fn list_keys(&self) -> SecretResult<Vec<String>> {
            let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            Ok(guard.keys().cloned().collect())
        }
    }

    #[test]
    fn list_keychain_with_store_filters_prefix() {
        let store = MemoryStore::new();
        store.put("secops/a", b"1", SecretPolicy::default()).unwrap();
        store.put("other/b", b"2", SecretPolicy::default()).unwrap();

        let keys = list_keychain_with_store(&store, Some("secops/")).unwrap();
        assert_eq!(keys, vec!["secops/a".to_string()]);
    }

    #[test]
    fn list_keychain_with_store_sorts_keys() {
        let store = MemoryStore::new();
        store.put("b", b"1", SecretPolicy::default()).unwrap();
        store.put("a", b"2", SecretPolicy::default()).unwrap();

        let keys = list_keychain_with_store(&store, None).unwrap();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn inject_keychain_with_store_sets_env() {
        let store = MemoryStore::new();
        store.put("secops/token", b"value", SecretPolicy::default()).unwrap();

        let mut command = Command::new("/usr/bin/true");
        inject_keychain_with_store(&store, &mut command, &["secops/token=TOKEN".to_string()]).unwrap();

        let envs = command.get_envs().collect::<Vec<_>>();
        assert!(envs.iter().any(|(key, value)| {
            *key == std::ffi::OsStr::new("TOKEN")
                && *value == Some(std::ffi::OsStr::new("value"))
        }));
    }

    #[test]
    fn inject_keychain_with_store_reports_missing_key() {
        let store = MemoryStore::new();
        let mut command = Command::new("/usr/bin/true");
        let err = inject_keychain_with_store(&store, &mut command, &["missing=TOKEN".to_string()]).unwrap_err();
        assert!(err.contains("keychain lookup failed"));
    }

    #[test]
    fn inject_keychain_with_store_rejects_invalid_mapping() {
        let store = MemoryStore::new();
        let mut command = Command::new("/usr/bin/true");
        let err = inject_keychain_with_store(&store, &mut command, &["invalid".to_string()]).unwrap_err();
        assert!(err.contains("inject-keychain must be"));
    }

    #[test]
    fn list_keychain_returns_ok_when_enabled() {
        let key_a = unique_key("secops/key-a");
        let key_b = unique_key("secops/key-b");
        test_store_put(&key_a, b"a");
        test_store_put(&key_b, b"b");

        list_keychain(Some("secops/")).expect("list");
    }

    #[test]
    fn inject_keychain_secrets_uses_default_store() {
        let key = unique_key("shadi-test-secret");
        test_store_put(&key, b"value");

        let mut command = Command::new("/usr/bin/true");
        inject_keychain_secrets(&mut command, &[format!("{}=TOKEN", key)]).expect("inject");

        let envs = command.get_envs().collect::<Vec<_>>();
        assert!(envs.iter().any(|(env_key, value)| {
            *env_key == std::ffi::OsStr::new("TOKEN")
                && *value == Some(std::ffi::OsStr::new("value"))
        }));

    }

    #[test]
    fn run_cli_list_keychain_routes_to_store() {
        let key_a = unique_key("secops/key-a");
        let key_b = unique_key("other/key-b");
        test_store_put(&key_a, b"a");
        test_store_put(&key_b, b"b");

        let mut cli = build_cli();
        cli.command.clear();
        cli.list_keychain = true;
        cli.list_prefix = Some("secops/".to_string());

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
    }

    #[test]
    fn run_cli_put_key_command_stores_payload() {
        let dir = temp_dir();
        let path = dir.path().join("key.asc");
        std::fs::write(&path, b"payload").expect("write");

        let key = unique_key("openpgp/test");

        let mut cli = build_cli();
        cli.command = vec![
            "put-key".to_string(),
            "--key".to_string(),
            key.clone(),
            "--in".to_string(),
            path.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        assert_eq!(test_store_get(&key), Some(b"payload".to_vec()));
    }

    #[test]
    fn run_cli_put_key_missing_file_returns_error() {
        let dir = temp_dir();
        let path = dir.path().join("missing.asc");
        let key = unique_key("openpgp/missing");

        let mut cli = build_cli();
        cli.command = vec![
            "put-key".to_string(),
            "--key".to_string(),
            key,
            "--in".to_string(),
            path.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_get_secret_command_reads_store() {
        let key = unique_key("secret/key");
        test_store_put(&key, b"value");

        let mut cli = build_cli();
        cli.command = vec![
            "get-secret".to_string(),
            "--key".to_string(),
            key,
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
    }

    #[test]
    fn run_cli_get_secret_missing_key_returns_error() {
        let key = unique_key("missing/key");

        let mut cli = build_cli();
        cli.command = vec![
            "get-secret".to_string(),
            "--key".to_string(),
            key,
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_did_from_gpg_writes_document() {
        let dir = temp_dir();
        let input = dir.path().join("key.asc");
        let output = dir.path().join("did.json");
        std::fs::write(&input, sample_openpgp_cert_armored()).expect("write");

        let mut cli = build_cli();
        cli.command = vec![
            "did-from-gpg".to_string(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        let content = std::fs::read_to_string(&output).expect("read did doc");
        assert!(content.contains("\"did:key:"));
    }

    #[test]
    fn run_cli_derive_agent_did_stores_outputs() {
        let root_key = unique_key("root-secret");
        test_store_put(&root_key, b"root-secret");

        let dir = temp_dir();
        let output = dir.path().join("agent.json");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-did".to_string(),
            "--secret".to_string(),
            root_key.clone(),
            "--name".to_string(),
            "agent-a".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        assert!(test_store_get("agents/agent-a/private").is_some());
        assert!(test_store_get("agents/agent-a/public").is_some());
        assert!(test_store_get("agents/agent-a/did").is_some());
        assert!(test_store_get("agents/agent-a/diddoc").is_some());
        let content = std::fs::read_to_string(&output).expect("read did doc");
        assert!(content.contains("\"did:key:"));
    }

    #[test]
    fn run_cli_derive_agent_did_from_openpgp_file() {
        let dir = temp_dir();
        let input = dir.path().join("human.sec");
        std::fs::write(&input, sample_openpgp_secret_armored()).expect("write");

        let agent_name = unique_key("agent-gpg");
        let output = dir.path().join("agent.json");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-did".to_string(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        assert!(test_store_get(&format!("agents/{}/private", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/public", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/did", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/diddoc", agent_name)).is_some());
        let content = std::fs::read_to_string(&output).expect("read did doc");
        assert!(content.contains("\"did:key:"));
    }

    #[test]
    fn run_cli_put_key_then_derive_agent_did_from_keychain() {
        let dir = temp_dir();
        let input = dir.path().join("human.sec");
        std::fs::write(&input, sample_openpgp_secret_armored()).expect("write");

        let key_name = unique_key("human-gpg");
        let mut cli = build_cli();
        cli.command = vec![
            "put-key".to_string(),
            "--key".to_string(),
            key_name.clone(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        assert!(test_store_get(&key_name).is_some());

        let agent_name = unique_key("agent-from-keychain");
        let output = dir.path().join("agent.json");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-did".to_string(),
            "--secret".to_string(),
            key_name,
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        assert!(test_store_get(&format!("agents/{}/private", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/public", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/did", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/diddoc", agent_name)).is_some());
        let content = std::fs::read_to_string(&output).expect("read did doc");
        assert!(content.contains("\"did:key:"));
    }

    #[test]
    fn run_cli_derive_agent_identity_from_seed_for_multiple_agents() {
        let seed_key = unique_key("human-seed");
        test_store_put(&seed_key, b"human-seed-material");

        let dir = temp_dir();
        let out_dir = dir.path().join("idents");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            "agent-a".to_string(),
            "--name".to_string(),
            "agent-b".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
            "--out-dir".to_string(),
            out_dir.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        assert!(test_store_get("agents/agent-a/private").is_some());
        assert!(test_store_get("agents/agent-a/did").is_some());
        assert!(test_store_get("agents/agent-b/private").is_some());
        assert!(test_store_get("agents/agent-b/did").is_some());
        let a_doc = std::fs::read_to_string(out_dir.join("agent-a.did.json")).expect("read did doc");
        let b_doc = std::fs::read_to_string(out_dir.join("agent-b.did.json")).expect("read did doc");
        assert!(a_doc.contains("\"did:key:"));
        assert!(b_doc.contains("\"did:key:"));
    }

    #[test]
    fn run_cli_derive_agent_identity_stores_human_did_binding() {
        let root_key = unique_key("human-gpg");
        test_store_put(&root_key, b"root-secret");
        let human_did_key = unique_key("human-did");
        test_store_put(&human_did_key, b"did:key:zHuman");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            root_key,
            "--human-did-key".to_string(),
            human_did_key,
            "--name".to_string(),
            "agent-bound".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        let stored = test_store_get("agents/agent-bound/human_did").expect("human did binding");
        assert_eq!(stored, b"did:key:zHuman".to_vec());
    }

    #[test]
    fn run_cli_verify_agent_identity_succeeds() {
        let seed_key = unique_key("verify-human-seed");
        test_store_put(&seed_key, b"verify-seed-material");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            "agent-verify".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            "agent-verify".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));
    }

    #[test]
    fn run_cli_verify_agent_identity_fails_on_mismatch() {
        let seed_key = unique_key("verify-human-seed-a");
        test_store_put(&seed_key, b"seed-a");
        let other_seed_key = unique_key("verify-human-seed-b");
        test_store_put(&other_seed_key, b"seed-b");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            "agent-mismatch".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            other_seed_key,
            "--name".to_string(),
            "agent-mismatch".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_checks_human_binding() {
        let seed_key = unique_key("verify-binding-seed");
        test_store_put(&seed_key, b"binding-seed");
        let human_did_key = unique_key("verify-human-did");
        test_store_put(&human_did_key, b"did:key:zHumanBinding");

        let mut cli = build_cli();
        cli.command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--human-did-key".to_string(),
            human_did_key.clone(),
            "--name".to_string(),
            "agent-binding".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--human-did-key".to_string(),
            human_did_key,
            "--require-human-binding".to_string(),
            "--name".to_string(),
            "agent-binding".to_string(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));
    }

    #[test]
    fn run_cli_did_from_github_stores_outputs() {
        let armored = String::from_utf8(sample_openpgp_cert_armored()).expect("armored");
        let payload = serde_json::json!([
            {"id": 1, "public_key": armored}
        ])
        .to_string();
        set_test_github_payload(Some(payload));

        let dir = temp_dir();
        let output = dir.path().join("github.json");

        let mut cli = build_cli();
        cli.command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            "alice".to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
        assert!(test_store_get("github/alice/did").is_some());
        assert!(test_store_get("github/alice/diddoc").is_some());
        let content = std::fs::read_to_string(&output).expect("read did doc");
        assert!(content.contains("\"did:key:"));

        set_test_github_payload(None);
    }

    #[test]
    fn blocklist_blocks_default_command() {
        let blocked = default_blocked_commands();
        assert!(blocked.contains("rm"));
    }

    #[test]
    fn allowlist_overrides_blocklist() {
        let blocked = default_blocked_commands();
        let allow = ["rm"].into_iter().collect::<HashSet<_>>();
        assert!(blocked.contains("rm"));
        assert!(allow.contains("rm"));
    }

    #[test]
    fn parse_key_env_rejects_missing_parts() {
        assert!(parse_key_env("onlykey").is_err());
        assert!(parse_key_env("=ENV").is_err());
        assert!(parse_key_env("KEY=").is_err());
    }

    #[test]
    fn parse_key_env_accepts_valid_format() {
        let (key, env) = parse_key_env("secret=ENV").unwrap();
        assert_eq!(key, "secret");
        assert_eq!(env, "ENV");
    }

    #[test]
    fn extract_ed25519_public_key_from_cert() {
        let public_key = extract_ed25519_public_key(&sample_openpgp_cert_armored()).expect("extract key");
        assert!(public_key.len() == 32 || public_key.len() == 33);
        if public_key.len() == 33 {
            assert_eq!(public_key[0], 0x40);
        }
    }

    #[test]
    fn build_did_document_from_ed25519_key() {
        let pubkey = vec![0x01; 32];
        let mut pkey = vec![0x40];
        pkey.extend_from_slice(&pubkey);

        let (did, vm_id, doc) = build_did_document(&pkey).unwrap();

        let mut multicodec = vec![0xED, 0x01];
        multicodec.extend_from_slice(&pubkey);
        let fingerprint = format!("z{}", bs58::encode(multicodec).into_string());

        assert_eq!(did, format!("did:key:{}", fingerprint));
        assert_eq!(vm_id, format!("{}#{}", did, fingerprint));
        assert_eq!(doc["id"], did);
        assert_eq!(doc["verificationMethod"][0]["id"], vm_id);
        assert_eq!(doc["verificationMethod"][0]["publicKeyMultibase"], fingerprint);
    }

    #[test]
    fn build_did_document_rejects_wrong_length() {
        let err = build_did_document(&vec![0x01; 31]).unwrap_err();
        assert!(err.contains("unexpected Ed25519"));
    }

    #[test]
    fn extract_github_public_key_returns_first() {
        let payload = r#"[
            {"id": 1, "public_key": "KEY1"},
            {"id": 2, "public_key": "KEY2"}
        ]"#;

        let key = extract_github_public_key(payload).unwrap();
        assert_eq!(key, "KEY1");
    }

    #[test]
    fn extract_github_public_key_errors_on_empty_list() {
        let err = extract_github_public_key("[]").unwrap_err();
        assert!(err.contains("no GPG keys"));
    }

    #[test]
    fn extract_github_public_key_errors_on_missing_field() {
        let payload = r#"[{"id": 1}]"#;
        let err = extract_github_public_key(payload).unwrap_err();
        assert!(err.contains("public_key"));
    }

    #[test]
    fn extract_github_public_key_errors_on_unexpected_format() {
        let err = extract_github_public_key("{}").unwrap_err();
        assert!(err.contains("unexpected GitHub response"));
    }

    #[test]
    fn decode_github_public_key_accepts_armored() {
        let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n";
        let decoded = decode_github_public_key(armored.to_string()).unwrap();
        assert_eq!(decoded, armored.as_bytes());
    }

    #[test]
    fn decode_github_public_key_decodes_base64() {
        let decoded = decode_github_public_key("AQID".to_string()).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn decode_github_public_key_rejects_empty() {
        let err = decode_github_public_key("\n  \n".to_string()).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn secret_bytes_to_utf8_rejects_invalid_utf8() {
        let err = secret_bytes_to_utf8(&[0xff, 0xff]).unwrap_err();
        assert!(err.contains("utf-8"));
    }

    #[test]
    fn derive_agent_keypair_is_deterministic() {
        let seed = b"root-secret";
        let (priv1, pub1) = derive_agent_keypair(seed, "agent-a").expect("derive");
        let (priv2, pub2) = derive_agent_keypair(seed, "agent-a").expect("derive");
        assert_eq!(priv1, priv2);
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn derive_agent_keypair_changes_with_name() {
        let seed = b"root-secret";
        let (_, pub1) = derive_agent_keypair(seed, "agent-a").expect("derive");
        let (_, pub2) = derive_agent_keypair(seed, "agent-b").expect("derive");
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn derive_agent_keypair_rejects_empty_name() {
        let err = derive_agent_keypair(b"root-secret", " ").unwrap_err();
        assert!(err.contains("agent name"));
    }
}
