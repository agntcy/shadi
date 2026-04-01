use super::*;
use crate::policy_watch::query_policy;

#[derive(Serialize)]
struct SecretBackendConfig {
    selected: String,
    op_vault: Option<String>,
    op_account: Option<String>,
}

fn profile_label(profile: Option<LauncherProfile>) -> &'static str {
    match profile.unwrap_or(LauncherProfile::Balanced) {
        LauncherProfile::Strict => "strict",
        LauncherProfile::Balanced => "balanced",
        LauncherProfile::Connected => "connected",
    }
}

fn build_policy_cli(
    profile: Option<LauncherProfile>,
    policy_file: Option<PathBuf>,
    allow: Vec<PathBuf>,
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    net_block: bool,
    net_allow: Vec<String>,
    allow_command: Vec<String>,
) -> Cli {
    Cli {
        profile,
        policy_file,
        allow,
        read,
        write,
        net_block,
        net_allow,
        allow_command,
        inject_keychain: Vec::new(),
        trusted_secret: Vec::new(),
        trusted_secret_exec: Vec::new(),
        trusted_secret_fd_env: Vec::new(),
        list_keychain: false,
        list_prefix: None,
        print_policy: false,
        git_snapshot: false,
        git_snapshot_dir: None,
        git_snapshot_untracked: false,
        watch_policy: false,
        slim_channel: None,
        slim_destination: None,
        slim_timeout: None,
        slim_payload_type: None,
        slim_allow_empty: false,
        session_name: None,
        record_ref: None,
        subcommand: None,
        run_command: Vec::new(),
    }
}

fn load_policy_file_or_default(path: Option<&PathBuf>) -> Result<PolicyFile, String> {
    match path {
        Some(path) => load_policy_file(path)
            .map_err(|err| format!("failed to read policy {}: {}", path.display(), err)),
        None => Ok(PolicyFile::default()),
    }
}

fn resolve_policy_value(resolved: &ResolvedPolicy) -> Result<Value, String> {
    let formatted = format_policy(&resolved.policy, &resolved.blocked, &resolved.allow)?;
    serde_json::from_str(&formatted).map_err(|err| err.to_string())
}

fn secret_backend_from_env() -> SecretBackendConfig {
    let selected = std::env::var("SHADI_SECRET_BACKEND").unwrap_or_else(|_| "keychain".to_string());
    SecretBackendConfig {
        selected,
        op_vault: std::env::var("SHADI_OP_VAULT").ok(),
        op_account: std::env::var("SHADI_OP_ACCOUNT").ok(),
    }
}

pub(crate) fn run_config_command(cli: ConfigCli) -> ExitCode {
    match cli.command {
        ConfigCommand::Show(args) => run_config_show(args),
    }
}

fn run_config_show(args: ConfigShowArgs) -> ExitCode {
    let policy_file_requested = args.policy_file.is_some();
    let file_policy = match load_policy_file_or_default(args.policy_file.as_ref()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let policy_cli = build_policy_cli(
        args.profile,
        args.policy_file.clone(),
        args.allow.clone(),
        args.read.clone(),
        args.write.clone(),
        args.net_block,
        Vec::new(),
        args.allow_command.clone(),
    );

    let resolved = match resolve_policy(&policy_cli, &file_policy) {
        Ok(resolved) => resolved,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let effective_policy = match resolve_policy_value(&resolved) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("failed to format policy: {}", err);
            return ExitCode::from(2);
        }
    };

    let output = json!({
        "profile": profile_label(args.profile),
        "policy_file": args.policy_file.as_ref().map(|p| p.display().to_string()),
        "policy_file_loaded": policy_file_requested,
        "secret_backend": secret_backend_from_env(),
        "overrides": {
            "allow": args.allow.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "read": args.read.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "write": args.write.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "net_block": args.net_block,
            "allow_command": args.allow_command,
        },
        "effective_policy": effective_policy,
    });

    print_output(&output, args.format)
}

pub(crate) fn run_policy_command(cli: PolicyCli) -> ExitCode {
    match cli.command {
        PolicyCommand::Explain(args) => run_policy_explain(args),
        PolicyCommand::Diff(args) => run_policy_diff(args),
        PolicyCommand::Patch(args) => run_policy_patch_command(args),
        PolicyCommand::Query(args) => run_policy_query_command(args),
    }
}

fn run_policy_explain(args: PolicyExplainArgs) -> ExitCode {
    let file_policy = match load_policy_file_or_default(args.policy_file.as_ref()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let policy_cli = build_policy_cli(
        args.profile,
        args.policy_file.clone(),
        args.allow.clone(),
        args.read.clone(),
        args.write.clone(),
        args.net_block,
        Vec::new(),
        args.allow_command.clone(),
    );

    let resolved = match resolve_policy(&policy_cli, &file_policy) {
        Ok(resolved) => resolved,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let effective_policy = match resolve_policy_value(&resolved) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("failed to format policy: {}", err);
            return ExitCode::from(2);
        }
    };

    // If a socket is provided (or auto-detectable), merge the live patched
    // state so the user sees network policy changes applied via `policy patch`.
    let live_state = args.socket
        .as_ref()
        .and_then(|sock| query_policy(sock).ok());

    let output = json!({
        "effective_policy": effective_policy,
        "live_state": live_state,
        "sources": {
            "profile": {
                "name": profile_label(args.profile),
                "defaults": profile_defaults(args.profile),
            },
            "policy_file": {
                "path": args.policy_file.as_ref().map(|p| p.display().to_string()),
                "values": file_policy,
            },
            "cli_overrides": {
                "allow": args.allow.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "read": args.read.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "write": args.write.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "net_block": args.net_block,
                "allow_command": args.allow_command,
            }
        }
    });

    print_output(&output, args.format)
}

fn parse_against_profile(value: &str) -> Option<LauncherProfile> {
    match value.to_ascii_lowercase().as_str() {
        "strict" => Some(LauncherProfile::Strict),
        "balanced" => Some(LauncherProfile::Balanced),
        "connected" => Some(LauncherProfile::Connected),
        _ => None,
    }
}

fn compute_policy_diff(current: &Value, baseline: &Value) -> Value {
    let mut changed = Vec::new();

    if let (Some(current_obj), Some(baseline_obj)) = (current.as_object(), baseline.as_object()) {
        let mut keys = BTreeSet::new();
        keys.extend(current_obj.keys().cloned());
        keys.extend(baseline_obj.keys().cloned());
        for key in keys {
            let current_value = current_obj.get(&key);
            let baseline_value = baseline_obj.get(&key);
            if current_value != baseline_value {
                changed.push(json!({
                    "field": key,
                    "current": current_value,
                    "baseline": baseline_value,
                }));
            }
        }
    }

    json!({
        "equivalent": changed.is_empty(),
        "changed_fields": changed,
    })
}

fn run_policy_diff(args: PolicyDiffArgs) -> ExitCode {
    let current_file_policy = match load_policy_file_or_default(args.policy_file.as_ref()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let current_cli = build_policy_cli(
        args.profile,
        args.policy_file.clone(),
        args.allow.clone(),
        args.read.clone(),
        args.write.clone(),
        args.net_block,
        args.net_allow.clone(),
        args.allow_command.clone(),
    );

    let current_resolved = match resolve_policy(&current_cli, &current_file_policy) {
        Ok(resolved) => resolved,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };
    let current_value = match resolve_policy_value(&current_resolved) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("failed to format policy: {}", err);
            return ExitCode::from(2);
        }
    };

    let (against_label, baseline_profile, baseline_policy_path) =
        if let Some(profile) = args.against.strip_prefix("profile:") {
            let profile = match parse_against_profile(profile) {
                Some(profile) => profile,
                None => {
                    eprintln!("invalid profile target for --against: {}", args.against);
                    return ExitCode::from(2);
                }
            };
            (args.against.clone(), Some(profile), None)
        } else if let Some(path) = args.against.strip_prefix("file:") {
            (args.against.clone(), args.profile, Some(PathBuf::from(path)))
        } else {
            eprintln!(
                "invalid --against value: {} (expected profile:<strict|balanced|connected> or file:<path>)",
                args.against
            );
            return ExitCode::from(2);
        };

    let baseline_file_policy = match load_policy_file_or_default(baseline_policy_path.as_ref()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };

    let baseline_cli = build_policy_cli(
        baseline_profile,
        baseline_policy_path,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
        Vec::new(),
        Vec::new(),
    );

    let baseline_resolved = match resolve_policy(&baseline_cli, &baseline_file_policy) {
        Ok(resolved) => resolved,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };
    let baseline_value = match resolve_policy_value(&baseline_resolved) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("failed to format baseline policy: {}", err);
            return ExitCode::from(2);
        }
    };

    let diff = compute_policy_diff(&current_value, &baseline_value);
    let output = json!({
        "against": against_label,
        "diff": diff,
        "current": current_value,
        "baseline": baseline_value,
    });

    print_output(&output, args.format)
}

fn print_output(value: &Value, format: OutputFormat) -> ExitCode {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(value) {
            Ok(output) => {
                println!("{}", output);
                ExitCode::from(0)
            }
            Err(err) => {
                eprintln!("failed to encode output: {}", err);
                ExitCode::from(2)
            }
        },
        OutputFormat::Text => {
            println!("{}", value);
            ExitCode::from(0)
        }
    }
}

fn run_policy_patch_command(args: PolicyPatchArgs) -> ExitCode {
    use shadi_sandbox::PolicyPatch;

    let mut patch = if let Some(ref path) = args.patch_file {
        match std::fs::read_to_string(path) {
            Ok(data) => match serde_json::from_str::<PolicyPatch>(&data) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("invalid patch file: {}", err);
                    return ExitCode::from(2);
                }
            },
            Err(err) => {
                eprintln!("failed to read patch file {}: {}", path.display(), err);
                return ExitCode::from(2);
            }
        }
    } else {
        PolicyPatch::default()
    };

    // Merge CLI flags on top of patch file.
    patch.add_read.extend(args.add_read);
    patch.add_write.extend(args.add_write);
    patch.add_allow.extend(args.add_allow);
    patch.add_allow_command.extend(args.add_allow_command);
    patch.remove_allow_command.extend(args.remove_allow_command);
    patch.add_block_command.extend(args.add_block_command);
    patch.remove_block_command.extend(args.remove_block_command);
    patch.add_net_allow.extend(args.add_net_allow);
    patch.remove_net_allow.extend(args.remove_net_allow);

    match send_patch(&args.socket, &patch) {
        Ok(result) => {
            let value = serde_json::to_value(&result).unwrap_or_default();
            print_output(&value, args.format)
        }
        Err(err) => {
            eprintln!("patch failed: {}", err);
            ExitCode::from(1)
        }
    }
}

fn run_policy_query_command(args: PolicyQueryArgs) -> ExitCode {
    match query_policy(&args.socket) {
        Ok(value) => print_output(&value, args.format),
        Err(err) => {
            eprintln!("query failed: {}", err);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_against_profile_supports_expected_values() {
        assert!(matches!(
            parse_against_profile("strict"),
            Some(LauncherProfile::Strict)
        ));
        assert!(matches!(
            parse_against_profile("balanced"),
            Some(LauncherProfile::Balanced)
        ));
        assert!(matches!(
            parse_against_profile("connected"),
            Some(LauncherProfile::Connected)
        ));
        assert!(parse_against_profile("unknown").is_none());
        assert!(matches!(
            parse_against_profile("STRICT"),
            Some(LauncherProfile::Strict)
        ));
    }

    #[test]
    fn compute_policy_diff_marks_equivalent_objects() {
        let a = json!({"allow": ["."], "net_block": true});
        let b = json!({"allow": ["."], "net_block": true});
        let diff = compute_policy_diff(&a, &b);
        assert_eq!(diff.get("equivalent"), Some(&Value::Bool(true)));
    }

    #[test]
    fn compute_policy_diff_reports_changed_fields() {
        let a = json!({"allow": ["."], "net_block": true});
        let b = json!({"allow": ["/tmp"], "net_block": false});
        let diff = compute_policy_diff(&a, &b);
        assert_eq!(diff.get("equivalent"), Some(&Value::Bool(false)));
        let changed_fields = diff
            .get("changed_fields")
            .and_then(|value| value.as_array())
            .expect("changed fields");
        assert!(!changed_fields.is_empty());
    }

    #[test]
    fn compute_policy_diff_treats_non_object_values_as_equivalent() {
        let diff = compute_policy_diff(&json!(["a"]), &json!(["b"]));
        assert_eq!(diff.get("equivalent"), Some(&Value::Bool(true)));
        assert_eq!(diff.get("changed_fields"), Some(&json!([])));
    }

    #[test]
    fn run_config_show_returns_success_with_defaults() {
        let code = run_config_show(ConfigShowArgs {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_config_show_supports_text_output_with_connected_profile_and_paths() {
        let dir = tempdir().expect("tempdir");
        let policy_path = dir.path().join("policy.json");
        let allow_path = dir.path().join("allow");
        let read_path = dir.path().join("read");
        let write_path = dir.path().join("write");
        std::fs::write(&policy_path, "{}").expect("write policy");
        std::fs::create_dir(&allow_path).expect("create allow path");
        std::fs::create_dir(&read_path).expect("create read path");
        std::fs::create_dir(&write_path).expect("create write path");

        let code = run_config_show(ConfigShowArgs {
            profile: Some(LauncherProfile::Connected),
            policy_file: Some(policy_path),
            allow: vec![allow_path],
            read: vec![read_path],
            write: vec![write_path],
            net_block: false,
            allow_command: vec!["echo".to_string()],
            format: OutputFormat::Text,
        });

        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_config_show_returns_error_for_invalid_allow_path() {
        let dir = tempdir().expect("tempdir");
        let code = run_config_show(ConfigShowArgs {
            profile: None,
            policy_file: None,
            allow: vec![dir.path().join("missing-allow")],
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_explain_returns_success_with_defaults() {
        let code = run_policy_explain(PolicyExplainArgs {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
            socket: None,
        });
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_policy_explain_supports_text_output_with_strict_profile_and_paths() {
        let dir = tempdir().expect("tempdir");
        let policy_path = dir.path().join("policy.json");
        let allow_path = dir.path().join("allow");
        let read_path = dir.path().join("read");
        let write_path = dir.path().join("write");
        std::fs::write(&policy_path, "{}").expect("write policy");
        std::fs::create_dir(&allow_path).expect("create allow path");
        std::fs::create_dir(&read_path).expect("create read path");
        std::fs::create_dir(&write_path).expect("create write path");

        let code = run_policy_explain(PolicyExplainArgs {
            profile: Some(LauncherProfile::Strict),
            policy_file: Some(policy_path),
            allow: vec![allow_path],
            read: vec![read_path],
            write: vec![write_path],
            net_block: true,
            allow_command: vec!["echo".to_string()],
            format: OutputFormat::Text,
            socket: None,
        });

        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_policy_explain_returns_error_for_invalid_allow_path() {
        let dir = tempdir().expect("tempdir");
        let code = run_policy_explain(PolicyExplainArgs {
            profile: None,
            policy_file: None,
            allow: vec![dir.path().join("missing-allow")],
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
            socket: None,
        });

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_diff_rejects_invalid_against_target() {
        let code = run_policy_diff(PolicyDiffArgs {
            against: "nope".to_string(),
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_diff_supports_file_baseline() {
        let dir = tempdir().expect("tempdir");
        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, r#"{"allow":["."]}"#).expect("write policy");

        let code = run_policy_diff(PolicyDiffArgs {
            against: format!("file:{}", policy_path.display()),
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_policy_diff_returns_error_for_invalid_current_allow_path() {
        let dir = tempdir().expect("tempdir");
        let code = run_policy_diff(PolicyDiffArgs {
            against: "profile:balanced".to_string(),
            profile: None,
            policy_file: None,
            allow: vec![dir.path().join("missing-allow")],
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_config_command_dispatches_show() {
        let code = run_config_command(ConfigCli {
            command: ConfigCommand::Show(ConfigShowArgs {
                profile: None,
                policy_file: None,
                allow: Vec::new(),
                read: Vec::new(),
                write: Vec::new(),
                net_block: false,
                allow_command: Vec::new(),
                format: OutputFormat::Json,
            }),
        });
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_policy_command_dispatches_variants() {
        let explain = run_policy_command(PolicyCli {
            command: PolicyCommand::Explain(PolicyExplainArgs {
                profile: None,
                policy_file: None,
                allow: Vec::new(),
                read: Vec::new(),
                write: Vec::new(),
                net_block: false,
                allow_command: Vec::new(),
                format: OutputFormat::Json,
                socket: None,
            }),
        });
        assert_eq!(explain, ExitCode::SUCCESS);

        let diff = run_policy_command(PolicyCli {
            command: PolicyCommand::Diff(PolicyDiffArgs {
                against: "profile:balanced".to_string(),
                profile: None,
                policy_file: None,
                allow: Vec::new(),
                read: Vec::new(),
                write: Vec::new(),
                net_block: false,
                net_allow: Vec::new(),
                allow_command: Vec::new(),
                format: OutputFormat::Json,
            }),
        });
        assert_eq!(diff, ExitCode::SUCCESS);
    }

    #[test]
    fn run_config_show_returns_error_for_missing_policy_file() {
        let dir = tempdir().expect("tempdir");
        let code = run_config_show(ConfigShowArgs {
            profile: None,
            policy_file: Some(dir.path().join("missing.json")),
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_explain_returns_error_for_missing_policy_file() {
        let dir = tempdir().expect("tempdir");
        let code = run_policy_explain(PolicyExplainArgs {
            profile: None,
            policy_file: Some(dir.path().join("missing.json")),
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            allow_command: Vec::new(),
            format: OutputFormat::Json,
            socket: None,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_diff_rejects_invalid_profile_target() {
        let code = run_policy_diff(PolicyDiffArgs {
            against: "profile:nope".to_string(),
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_diff_rejects_missing_file_target() {
        let dir = tempdir().expect("tempdir");
        let code = run_policy_diff(PolicyDiffArgs {
            against: format!("file:{}", dir.path().join("missing.json").display()),
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn secret_backend_from_env_reads_values() {
        std::env::set_var("SHADI_SECRET_BACKEND", "external-backend");
        std::env::set_var("SHADI_OP_VAULT", "vault-a");
        std::env::set_var("SHADI_OP_ACCOUNT", "account-a");
        let cfg = secret_backend_from_env();
        std::env::remove_var("SHADI_SECRET_BACKEND");
        std::env::remove_var("SHADI_OP_VAULT");
        std::env::remove_var("SHADI_OP_ACCOUNT");

        assert_eq!(cfg.selected, "external-backend");
        assert_eq!(cfg.op_vault.as_deref(), Some("vault-a"));
        assert_eq!(cfg.op_account.as_deref(), Some("account-a"));
    }

    // --- policy patch / query command tests ---

    use crate::policy_watch::{query_policy, start_control_socket, LivePolicy};
    use std::collections::HashSet;

    fn test_live_policy() -> std::sync::Arc<std::sync::Mutex<LivePolicy>> {
        use shadi_sandbox::SandboxPolicy;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32};
        std::sync::Arc::new(std::sync::Mutex::new(LivePolicy {
            policy: SandboxPolicy::new().block_network(true),
            blocked: HashSet::new(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: None,
        }))
    }

    fn wait_for_control_socket_ready_with_timeout(
        sock: &std::path::Path,
        timeout: std::time::Duration,
    ) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if sock.exists() && query_policy(sock).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("control socket did not become ready: {}", sock.display());
    }

    fn wait_for_control_socket_ready(sock: &std::path::Path) {
        wait_for_control_socket_ready_with_timeout(sock, std::time::Duration::from_secs(2));
    }

    #[test]
    #[should_panic(expected = "control socket did not become ready")]
    fn wait_for_control_socket_ready_times_out_on_missing_socket() {
        wait_for_control_socket_ready_with_timeout(
            std::path::Path::new("/tmp/shadi-ctl-nonexistent-never-exists.sock"),
            std::time::Duration::from_millis(1),
        );
    }

    #[test]
    fn run_policy_patch_command_succeeds_via_socket() {
        let live = test_live_policy();
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("ctl.sock");
        let handle = start_control_socket(&sock, live).expect("start socket");
        wait_for_control_socket_ready(&sock);

        let code = run_policy_patch_command(PolicyPatchArgs {
            socket: sock.clone(),
            add_read: vec!["/opt/data".to_string()],
            add_write: vec!["/tmp/out".to_string()],
            add_allow: vec!["/shared".to_string()],
            add_allow_command: vec!["npm".to_string()],
            remove_allow_command: Vec::new(),
            add_block_command: vec!["curl".to_string()],
            remove_block_command: Vec::new(),
            add_net_allow: vec!["cdn.example.com".to_string()],
            remove_net_allow: Vec::new(),
            patch_file: None,
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::SUCCESS);
        drop(handle);
    }

    #[test]
    fn run_policy_patch_command_loads_patch_file() {
        let live = test_live_policy();
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("ctl.sock");
        let handle = start_control_socket(&sock, live).expect("start socket");
        wait_for_control_socket_ready(&sock);

        let patch_path = dir.path().join("patch.json");
        std::fs::write(
            &patch_path,
            r#"{"add_allow_command":["node"]}"#,
        )
        .expect("write patch");

        let code = run_policy_patch_command(PolicyPatchArgs {
            socket: sock.clone(),
            add_read: Vec::new(),
            add_write: Vec::new(),
            add_allow: Vec::new(),
            add_allow_command: Vec::new(),
            remove_allow_command: Vec::new(),
            add_block_command: Vec::new(),
            remove_block_command: Vec::new(),
            add_net_allow: Vec::new(),
            remove_net_allow: Vec::new(),
            patch_file: Some(patch_path),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::SUCCESS);
        drop(handle);
    }

    #[test]
    fn run_policy_patch_command_fails_on_bad_socket() {
        let code = run_policy_patch_command(PolicyPatchArgs {
            socket: PathBuf::from("/tmp/shadi-nonexistent.sock"),
            add_read: Vec::new(),
            add_write: Vec::new(),
            add_allow: Vec::new(),
            add_allow_command: Vec::new(),
            remove_allow_command: Vec::new(),
            add_block_command: Vec::new(),
            remove_block_command: Vec::new(),
            add_net_allow: Vec::new(),
            remove_net_allow: Vec::new(),
            patch_file: None,
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn run_policy_patch_command_fails_on_missing_patch_file() {
        let code = run_policy_patch_command(PolicyPatchArgs {
            socket: PathBuf::from("/tmp/shadi-nonexistent.sock"),
            add_read: Vec::new(),
            add_write: Vec::new(),
            add_allow: Vec::new(),
            add_allow_command: Vec::new(),
            remove_allow_command: Vec::new(),
            add_block_command: Vec::new(),
            remove_block_command: Vec::new(),
            add_net_allow: Vec::new(),
            remove_net_allow: Vec::new(),
            patch_file: Some(PathBuf::from("/tmp/shadi-nonexistent-patch.json")),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_patch_command_fails_on_invalid_patch_file() {
        let dir = tempdir().expect("tempdir");
        let patch_path = dir.path().join("bad.json");
        std::fs::write(&patch_path, "not json").expect("write");

        let code = run_policy_patch_command(PolicyPatchArgs {
            socket: PathBuf::from("/tmp/shadi-nonexistent.sock"),
            add_read: Vec::new(),
            add_write: Vec::new(),
            add_allow: Vec::new(),
            add_allow_command: Vec::new(),
            remove_allow_command: Vec::new(),
            add_block_command: Vec::new(),
            remove_block_command: Vec::new(),
            add_net_allow: Vec::new(),
            remove_net_allow: Vec::new(),
            patch_file: Some(patch_path),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_policy_query_command_succeeds_via_socket() {
        let live = test_live_policy();
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("ctl.sock");
        let handle = start_control_socket(&sock, live).expect("start socket");
        wait_for_control_socket_ready(&sock);

        let code = run_policy_query_command(PolicyQueryArgs {
            socket: sock.clone(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::SUCCESS);
        drop(handle);
    }

    #[test]
    fn run_policy_query_command_fails_on_bad_socket() {
        let code = run_policy_query_command(PolicyQueryArgs {
            socket: PathBuf::from("/tmp/shadi-nonexistent.sock"),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn run_policy_command_dispatches_patch_and_query() {
        // Patch dispatch (fails on connect, but exercises the Patch arm).
        let code = run_policy_command(PolicyCli {
            command: PolicyCommand::Patch(PolicyPatchArgs {
                socket: PathBuf::from("/tmp/shadi-nonexistent.sock"),
                add_read: Vec::new(),
                add_write: Vec::new(),
                add_allow: Vec::new(),
                add_allow_command: Vec::new(),
                remove_allow_command: Vec::new(),
                add_block_command: Vec::new(),
                remove_block_command: Vec::new(),
                add_net_allow: Vec::new(),
                remove_net_allow: Vec::new(),
                patch_file: None,
                format: OutputFormat::Json,
            }),
        });
        assert_eq!(code, ExitCode::from(1));

        // Query dispatch.
        let code = run_policy_command(PolicyCli {
            command: PolicyCommand::Query(PolicyQueryArgs {
                socket: PathBuf::from("/tmp/shadi-nonexistent.sock"),
                format: OutputFormat::Json,
            }),
        });
        assert_eq!(code, ExitCode::from(1));
    }
}
