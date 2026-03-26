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
use slim_mas::{is_member_allowed, load_config as load_mas_config, resolve_group, resolve_group_dids};
use sequoia_openpgp as openpgp;
use tracing::{field, info_span};

mod memory_command;
mod identity_command;
mod cli_types;
mod introspection_command;
mod policy_helpers;
mod policy_watch;
mod resource_info;
mod sandbox_snapshot;
mod secrets_command;
mod slim_mas_command;
mod snapshot_command;
mod trace_command;
mod trusted_secret_delivery;
mod shell_command;

use cli_types::*;
use introspection_command::*;
use identity_command::*;
use memory_command::*;
use policy_helpers::*;
use policy_watch::*;
use sandbox_snapshot::*;
use slim_mas_command::*;
use trace_command::*;
use trusted_secret_delivery::*;
use shell_command::*;

#[cfg(test)]
static TEST_SECRET_STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

#[cfg(test)]
static TEST_SECRET_STORE_PUT_FAILURES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[cfg(test)]
fn test_secret_store_map() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    TEST_SECRET_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
fn test_secret_store_put_failures() -> &'static Mutex<HashSet<String>> {
    TEST_SECRET_STORE_PUT_FAILURES.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(test)]
struct TestSecretStore;

#[cfg(test)]
impl SecretStore for TestSecretStore {
    fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> agent_secrets::SecretResult<()> {
        if test_secret_store_put_failures()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?
            .contains(key)
        {
            return Err(agent_secrets::SecretError::StorageFailure);
        }

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

#[cfg(test)]
fn test_store_fail_put(key: &str) {
    let mut guard = test_secret_store_put_failures()
        .lock()
        .expect("test store put failures lock");
    guard.insert(key.to_string());
}

#[cfg(test)]
fn test_store_clear_failures() {
    let mut guard = test_secret_store_put_failures()
        .lock()
        .expect("test store put failures lock");
    guard.clear();
}

#[cfg(test)]
pub(crate) fn scrub_test_secret_backend_env(command: &mut Command) {
    for key in [
        "SHADI_SECRET_BACKEND",
        "SHADI_OP_VAULT",
        "SHADI_OP_ACCOUNT",
        "SHADI_OP_BINARY",
        "OP_SERVICE_ACCOUNT_TOKEN",
    ] {
        command.env_remove(key);
    }
}


fn main() -> ExitCode {
    shadi_telemetry::init("shadi-core");
    let cli = Cli::parse();
    run_cli(cli)
}

fn run_named_command(command: Commands) -> ExitCode {
    match command {
        Commands::Config(command) => run_config_command(command),
        Commands::Policy(command) => run_policy_command(command),
        Commands::Memory(command) => run_memory_command(command),
        Commands::Trace(command) => run_trace_command(command),
        Commands::SlimMas(command) => run_slim_mas_command(command),
        Commands::DidFromGpg(command) => run_did_from_gpg_command(command),
        Commands::DidFromGitHub(command) => run_did_from_github_command(command),
        Commands::GetSecret(command) => run_get_secret_command(command),
        Commands::DeriveAgentDid(command) => run_derive_agent_did_command(command),
        Commands::DeriveAgentIdentity(command) => run_derive_agent_identity_command(command),
        Commands::VerifyAgentIdentity(command) => run_verify_agent_identity_command(command),
        Commands::PutKey(command) => run_put_key_command(command),
        Commands::Shell(args) => run_shell_command(args),
    }
}

fn run_cli(mut cli: Cli) -> ExitCode {
    if let Some(command) = cli.subcommand.take() {
        return run_named_command(command);
    }

    if !cli.run_command.is_empty() {
        let mut argv = Vec::with_capacity(cli.run_command.len() + 1);
        argv.push("shadi".to_string());
        argv.extend(cli.run_command.clone());
        if let Ok(parsed) = Cli::try_parse_from(argv) {
            if let Some(command) = parsed.subcommand {
                return run_named_command(command);
            }
        }
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

    if cli.print_policy && cli.run_command.is_empty() {
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

    if cli.run_command.is_empty() {
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

    let cmd_name = cli.run_command.first().map(|cmd| cmd.as_str()).unwrap_or("");
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

    run_sandboxed_command(&cli, &resolved, &file_policy, &cwd)
}

#[cfg(test)]
mod main_tests;
