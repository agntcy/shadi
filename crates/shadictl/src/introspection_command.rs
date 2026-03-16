use super::*;

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
    allow_command: Vec<String>,
) -> Cli {
    Cli {
        profile,
        policy_file,
        allow,
        read,
        write,
        net_block,
        allow_command,
        inject_keychain: Vec::new(),
        list_keychain: false,
        list_prefix: None,
        print_policy: false,
        git_snapshot: false,
        git_snapshot_dir: None,
        git_snapshot_untracked: false,
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
        "effective_policy": effective_policy,
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
        });
        assert_eq!(code, ExitCode::SUCCESS);
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
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::SUCCESS);
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
            allow_command: Vec::new(),
            format: OutputFormat::Json,
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn secret_backend_from_env_reads_values() {
        std::env::set_var("SHADI_SECRET_BACKEND", "onepassword");
        std::env::set_var("SHADI_OP_VAULT", "vault-a");
        std::env::set_var("SHADI_OP_ACCOUNT", "account-a");
        let cfg = secret_backend_from_env();
        std::env::remove_var("SHADI_SECRET_BACKEND");
        std::env::remove_var("SHADI_OP_VAULT");
        std::env::remove_var("SHADI_OP_ACCOUNT");

        assert_eq!(cfg.selected, "onepassword");
        assert_eq!(cfg.op_vault.as_deref(), Some("vault-a"));
        assert_eq!(cfg.op_account.as_deref(), Some("account-a"));
    }
}
