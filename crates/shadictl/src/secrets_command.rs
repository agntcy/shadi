// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Shell commands for introspecting secret injection configuration.

use std::path::Path;

use crate::cli_types::{PolicyFile, SecretAction};
use crate::policy_helpers::load_policy_file;

/// List available keychain keys, optionally filtered by prefix.
pub(crate) fn secrets_list(prefix: Option<&str>) {
    if let Err(err) = crate::list_keychain(prefix) {
        eprintln!("error listing keychain: {}", err);
    }
}

/// Show the current secret backend configuration.
pub(crate) fn secrets_backend() {
    let selected = std::env::var("SHADI_SECRET_BACKEND").unwrap_or_else(|_| "keychain".to_string());
    println!("Backend: {}", selected);

    match selected.as_str() {
        "1password" | "op" => {
            if let Ok(vault) = std::env::var("SHADI_OP_VAULT") {
                println!("Vault:   {}", vault);
            }
            if let Ok(account) = std::env::var("SHADI_OP_ACCOUNT") {
                println!("Account: {}", account);
            }
        }
        "keychain" => {
            #[cfg(target_os = "macos")]
            println!("Type:    macOS Security Framework");
            #[cfg(all(unix, not(target_os = "macos")))]
            println!("Type:    noop (no native keychain on this platform)");
            #[cfg(windows)]
            println!("Type:    Windows Credential Manager");
        }
        _ => {
            println!("Type:    unknown");
        }
    }
}

/// Show secret delivery rules from a policy file.
pub(crate) fn secrets_rules(policy_path: Option<&str>) {
    let policy = match policy_path {
        Some(path) => match load_policy_file(Path::new(path)) {
            Ok(p) => p,
            Err(err) => {
                eprintln!("failed to load policy: {}", err);
                return;
            }
        },
        None => PolicyFile::default(),
    };

    let has_inject = !policy.process_inject_keychain.is_empty();
    let has_trusted = !policy.process_trusted_secret.is_empty();
    let has_policy = !policy.process_secret_policy.is_empty();

    if !has_inject && !has_trusted && !has_policy {
        println!("no secret delivery rules configured");
        return;
    }

    if has_inject {
        println!("Keychain injection (env var disclosure):");
        println!(
            "  {:<30} {:<25} {}",
            "PROGRAM", "KEY", "ENV"
        );
        for rule in &policy.process_inject_keychain {
            println!(
                "  {:<30} {:<25} {}",
                rule.program, rule.key, rule.env
            );
        }
        println!();
    }

    if has_trusted {
        println!("Trusted secret delivery (brokered, one-shot):");
        println!(
            "  {:<30} {:<20} {:<15} {}",
            "PROGRAM", "KEY", "NAME", "FD_ENV"
        );
        for rule in &policy.process_trusted_secret {
            println!(
                "  {:<30} {:<20} {:<15} {}",
                rule.program,
                rule.key,
                rule.name,
                rule.fd_env,
            );
            if let Some(ref sha) = rule.exec_sha256 {
                println!("    exec_sha256: {}", sha);
            }
        }
        println!();
    }

    if has_policy {
        println!("Process secret policy (declarative rules):");
        println!(
            "  {:<30} {:<20} {}",
            "PROGRAM", "SECRET", "ACTIONS"
        );
        for rule in &policy.process_secret_policy {
            let actions = rule
                .actions
                .iter()
                .map(format_action)
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "  {:<30} {:<20} {}",
                rule.program, rule.secret, actions
            );
            if !rule.children.is_empty() {
                println!(
                    "    children: {}",
                    rule.children.join(", ")
                );
            }
            if !rule.child_sha256.is_empty() {
                for sha in &rule.child_sha256 {
                    println!("    child_sha256: {}", sha);
                }
            }
            if let Some(ref name) = rule.name {
                println!("    name: {}", name);
            }
            if let Some(ref fd_env) = rule.fd_env {
                println!("    fd_env: {}", fd_env);
            }
        }
        println!();
    }
}

fn format_action(action: &SecretAction) -> &'static str {
    match action {
        SecretAction::Disclose => "disclose",
        SecretAction::Use => "use",
        SecretAction::DelegateToChild => "delegate-to-child",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_backend_does_not_panic() {
        secrets_backend();
    }

    #[test]
    fn secrets_rules_with_no_policy_shows_no_rules() {
        secrets_rules(None);
    }

    #[test]
    fn secrets_rules_with_missing_file_prints_error() {
        secrets_rules(Some("/tmp/shadi-nonexistent-policy.json"));
    }

    #[test]
    fn secrets_list_does_not_panic() {
        secrets_list(None);
    }

    #[test]
    fn secrets_list_with_prefix_does_not_panic() {
        secrets_list(Some("SHADI_TEST_"));
    }

    #[test]
    fn format_action_formats_all_variants() {
        assert_eq!(format_action(&SecretAction::Disclose), "disclose");
        assert_eq!(format_action(&SecretAction::Use), "use");
        assert_eq!(format_action(&SecretAction::DelegateToChild), "delegate-to-child");
    }

    #[test]
    fn secrets_rules_with_valid_empty_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        std::fs::write(&path, "{}").expect("write");
        secrets_rules(Some(&path.to_string_lossy()));
    }

    #[test]
    fn secrets_rules_with_inject_keychain_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{
                "process_inject_keychain": [
                    {"program": "python3", "key": "API_KEY", "env": "API_KEY"}
                ]
            }"#,
        )
        .expect("write");
        secrets_rules(Some(&path.to_string_lossy()));
    }

    #[test]
    fn secrets_rules_with_trusted_secret_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{
                "process_trusted_secret": [
                    {"program": "node", "key": "TOKEN", "name": "auth", "fd_env": "TOKEN_FD", "exec_sha256": "abc123"}
                ]
            }"#,
        )
        .expect("write");
        secrets_rules(Some(&path.to_string_lossy()));
    }

    #[test]
    fn secrets_rules_with_process_secret_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{
                "process_secret_policy": [
                    {
                        "program": "agent",
                        "secret": "DB_PASS",
                        "actions": ["delegate-to-child"],
                        "children": ["/usr/bin/psql"],
                        "child_sha256": ["deadbeef"],
                        "name": "db",
                        "fd_env": "DB_FD"
                    }
                ]
            }"#,
        )
        .expect("write");
        secrets_rules(Some(&path.to_string_lossy()));
    }
}
