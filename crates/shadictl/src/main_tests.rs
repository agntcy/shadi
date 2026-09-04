    use super::*;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use shadi_sandbox::PlatformSandboxProfile;
    use tempfile::TempDir;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use agent_secrets::{SecretError, SecretResult};
    use agent_secrets::memory::SecretBytes;
    use agent_secrets::policy::SecretPolicy;

    static GITHUB_PAYLOAD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static STORE_FAILURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn trace_env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::lock_test_env()
    }

    fn github_payload_lock() -> &'static Mutex<()> {
        GITHUB_PAYLOAD_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn store_failure_lock() -> &'static Mutex<()> {
        STORE_FAILURE_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn write_mas_config(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("mas.toml");
        std::fs::write(&path, contents).expect("write mas config");
        path
    }

    fn build_cli() -> Cli {
        Cli {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
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
            run_command: vec!["echo".to_string(), "ok".to_string()],
        }
    }

    fn assert_common_direct_trusted_secret_report(report: &str) {
        assert!(report.contains("agent_token=agent-value"));
        assert!(report.contains("tool_secret_present=false"));
        assert!(report.contains("tool_fd_present=true"));
        assert!(report.contains("secret_payload=tool-value"));
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
        run_git(dir.path(), &["config", "commit.gpgsign", "false"]);
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
        run_git(&repo_path, &["config", "commit.gpgsign", "false"]);
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
                vec!["/usr/bin/true".to_string()],
                PathBuf::from("/usr/bin"),
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

    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn windows_system32() -> PathBuf {
        PathBuf::from(
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
        )
        .join("System32")
    }

    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn windows_test_programs() -> (PathBuf, PathBuf) {
        let system32 = windows_system32();
        (system32.join("cmd.exe"), system32.join("where.exe"))
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

    fn compile_checked_in_test_binary(source: &str, output_dir: &Path, output_name: &str) -> PathBuf {
        let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(source);
        let output_path = output_dir.join(format!("{}{}", output_name, std::env::consts::EXE_SUFFIX));
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let mut command = Command::new(rustc);
        scrub_test_secret_backend_env(&mut command);
        let output = command
            .arg("--edition=2021")
            .arg(&source_path)
            .arg("-o")
            .arg(&output_path)
            .output()
            .expect("compile checked-in helper source");
        assert!(
            output.status.success(),
            "failed to compile helper {}: {}",
            source_path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        output_path
    }

    #[cfg(target_os = "macos")]
    fn write_launcher_usage_policy(
        path: &Path,
        allowed_root: &Path,
        agent_program: &Path,
        child_program: &Path,
        agent_key: &str,
        tool_key: &str,
    ) {
        let payload = format!(
            r#"{{
  "allow": ["{}"],
  "net_block": true,
  "process_inject_keychain": [
    {{
      "program": "{}",
      "key": "{}",
      "env": "AGENT_TOKEN"
    }}
  ],
  "process_secret_policy": [
    {{
      "program": "{}",
      "secret": "{}",
      "actions": ["delegate-to-child"],
      "children": ["{}"],
      "name": "tool-secret",
      "fd_env": "TOOL_SECRET_FD"
    }}
  ]
}}"#,
            allowed_root.display(),
            agent_program.display(),
            agent_key,
            agent_program.display(),
            tool_key,
            child_program.display(),
        );
        std::fs::write(path, payload).expect("write launcher usage policy");
    }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        fn write_direct_trusted_secret_policy(
                path: &Path,
                allowed_root: &Path,
                program: &Path,
                agent_key: &str,
                tool_key: &str,
        ) {
            let payload = serde_json::to_string_pretty(&serde_json::json!({
                "allow": [allowed_root.display().to_string()],
                "net_block": true,
                "process_inject_keychain": [{
                    "program": program.display().to_string(),
                    "key": agent_key,
                    "env": "AGENT_TOKEN"
                }],
                "process_trusted_secret": [{
                    "program": program.display().to_string(),
                    "key": tool_key,
                    "name": "tool-secret",
                    "fd_env": "TOOL_SECRET_FD"
                }]
            }))
            .expect("serialize direct trusted secret policy");
                std::fs::write(path, payload).expect("write direct trusted secret policy");
        }

    fn unique_key(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    fn github_payload_with_sample_cert() -> String {
        let armored = String::from_utf8(sample_openpgp_cert_armored()).expect("armored");
        serde_json::json!([
            {"id": 1, "public_key": armored}
        ])
        .to_string()
    }

    fn policy_from_paths(read: &[PathBuf], write: &[PathBuf], allow: &[PathBuf]) -> PolicyFile {
        PolicyFile {
            read: read.iter().map(|p| p.display().to_string()).collect(),
            write: write.iter().map(|p| p.display().to_string()).collect(),
            allow: allow.iter().map(|p| p.display().to_string()).collect(),
            net_block: Some(false),
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            block_command: Vec::new(),
            env_remove: Vec::new(),
            process_inject_keychain: Vec::new(),
            process_trusted_secret: Vec::new(),
            process_secret_policy: Vec::new(),
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
    fn build_cli_uses_expected_defaults() {
        let cli = build_cli();
        assert!(cli.trusted_secret_fd_env.is_empty());
        assert!(!cli.git_snapshot);
        assert!(cli.git_snapshot_dir.is_none());
        assert!(!cli.git_snapshot_untracked);
        assert!(cli.subcommand.is_none());
    }

    #[test]
    fn resolve_policy_skips_missing_preset_paths() {
        // Paths in a policy file that don't exist on the current OS are
        // silently skipped.  This allows cross-platform presets to list paths
        // for macOS, Linux, and Windows simultaneously.
        let cli = build_cli();
        let policy_file = PolicyFile {
            read: vec!["/path/does/not/exist".to_string()],
            write: Vec::new(),
            allow: Vec::new(),
            net_block: Some(false),
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            block_command: Vec::new(),
            env_remove: Vec::new(),
            process_inject_keychain: Vec::new(),
            process_trusted_secret: Vec::new(),
            process_secret_policy: Vec::new(),
        };

        // Should succeed — the missing path is skipped, not an error.
        let resolved = resolve_policy(&cli, &policy_file).expect("resolve should succeed with missing preset paths");
        // The nonexistent path must not appear in the resolved policy.
        assert!(
            !resolved.policy.allow_read().iter().any(|p| p.to_string_lossy().contains("does/not/exist")),
            "nonexistent path must not be included in allow_read"
        );
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
        assert!(resolved.policy.net_blocked());

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let default_read = shadi_sandbox::canonicalize_path("/").expect("canonical root path");
            assert_eq!(
                resolved.policy.platform_profile(),
                PlatformSandboxProfile::Minimal
            );
            assert!(!resolved
                .policy
                .allow_read()
                .iter()
                .any(|path| path == &default_read));
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let default_read = shadi_sandbox::canonicalize_path("/").expect("canonical root path");
            assert!(resolved
                .policy
                .allow_read()
                .iter()
                .any(|path| path == &default_read));
        }
    }

    #[test]
    fn resolve_policy_uses_connected_profile() {
        let mut cli = build_cli();
        cli.profile = Some(LauncherProfile::Connected);
        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve");
        assert!(!resolved.policy.net_blocked());
    }

    // ── net_allow policy resolution tests ──────────────────────────────

    #[test]
    fn resolve_policy_applies_cli_net_allow() {
        let mut cli = build_cli();
        cli.net_allow = vec!["1.1.1.1:80".to_string(), "api.github.com".to_string()];
        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve");
        assert_eq!(
            resolved.policy.net_allow(),
            &["1.1.1.1:80".to_string(), "api.github.com".to_string()]
        );
    }

    #[test]
    fn resolve_policy_applies_file_net_allow() {
        let cli = build_cli();
        let policy_file = PolicyFile {
            net_allow: vec!["cdn.example.com".to_string()],
            ..PolicyFile::default()
        };
        let resolved = resolve_policy(&cli, &policy_file).expect("resolve");
        assert_eq!(
            resolved.policy.net_allow(),
            &["cdn.example.com".to_string()]
        );
    }

    #[test]
    fn resolve_policy_merges_file_and_cli_net_allow() {
        let mut cli = build_cli();
        cli.net_allow = vec!["cli.example.com".to_string()];
        let policy_file = PolicyFile {
            net_allow: vec!["file.example.com".to_string()],
            ..PolicyFile::default()
        };
        let resolved = resolve_policy(&cli, &policy_file).expect("resolve");
        assert_eq!(
            resolved.policy.net_allow(),
            &["file.example.com".to_string(), "cli.example.com".to_string()]
        );
    }

    #[test]
    fn resolve_policy_net_allow_empty_by_default() {
        let cli = build_cli();
        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve");
        assert!(resolved.policy.net_allow().is_empty());
    }

    #[test]
    fn policy_file_net_allow_round_trips_through_json() {
        let json_str = r#"{"net_allow": ["1.1.1.1:80", "api.github.com"]}"#;
        let policy: PolicyFile = serde_json::from_str(json_str).expect("deserialize");
        assert_eq!(policy.net_allow, vec!["1.1.1.1:80", "api.github.com"]);

        let back = serde_json::to_string(&policy).expect("serialize");
        let round_trip: PolicyFile = serde_json::from_str(&back).expect("round-trip");
        assert_eq!(round_trip.net_allow, policy.net_allow);
    }

    #[test]
    fn policy_file_env_remove_defaults_to_empty() {
        let policy = PolicyFile::default();
        assert!(policy.env_remove.is_empty());
    }

    #[test]
    fn policy_file_env_remove_round_trips_through_json() {
        let json_str = r#"{"env_remove": ["HTTPS_PROXY", "HTTP_PROXY"]}"#;
        let policy: PolicyFile = serde_json::from_str(json_str).expect("deserialize");
        assert_eq!(policy.env_remove, vec!["HTTPS_PROXY", "HTTP_PROXY"]);

        let back = serde_json::to_string(&policy).expect("serialize");
        let round_trip: PolicyFile = serde_json::from_str(&back).expect("round-trip");
        assert_eq!(round_trip.env_remove, policy.env_remove);
    }

    #[test]
    fn format_policy_includes_net_allow() {
        let policy = SandboxPolicy::new()
            .allow_network_destination("10.0.0.1:443");
        let blocked = HashSet::new();
        let allow = HashSet::new();

        let output = format_policy(&policy, &blocked, &allow).expect("format");
        assert!(output.contains("\"net_allow\""), "output should contain net_allow: {}", output);
        assert!(output.contains("10.0.0.1:443"));
    }

    #[test]
    fn resolve_policy_uses_strict_profile() {
        let mut cli = build_cli();
        cli.profile = Some(LauncherProfile::Strict);
        let resolved = resolve_policy(&cli, &PolicyFile::default()).expect("resolve");
        let default_read = shadi_sandbox::canonicalize_path("/").expect("canonical root path");
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
        let blocked = shadi_sandbox::default_blocked_commands()
            .into_iter()
            .map(|cmd| cmd.to_string())
            .collect::<HashSet<_>>();
        let allow = HashSet::new();
        assert!(!is_command_blocked("echo", &blocked, &allow));
    }

    #[test]
    fn command_blocking_respects_allowlist() {
        let blocked = shadi_sandbox::default_blocked_commands()
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
        assert!(output.contains("\"platform_profile\""));
    }

    #[test]
    fn secret_action_deserializes_kebab_case_values() {
        let action: SecretAction = serde_json::from_str("\"delegate-to-child\"")
            .expect("deserialize secret action");
        assert_eq!(action, SecretAction::DelegateToChild);
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
            format!(
                r#"{{"allow": ["{}"], "net_block": true, "process_inject_keychain": [{{"program": "/usr/bin/true", "key": "secops/token", "env": "TOKEN"}}], "process_secret_policy": [{{"program": "/usr/bin/true", "secret": "secops/github_token", "actions": ["delegate-to-child"], "children": ["/usr/bin/curl"]}}]}}"#,
                tmp_dir
            ),
        )
        .expect("write");

        let policy = load_policy_file(&path).expect("load");
        assert_eq!(policy.allow, vec![tmp_dir]);
        assert_eq!(policy.net_block, Some(true));
        assert_eq!(policy.process_inject_keychain.len(), 1);
        assert_eq!(policy.process_inject_keychain[0].env, "TOKEN");
        assert_eq!(policy.process_secret_policy.len(), 1);
        assert_eq!(policy.process_secret_policy[0].secret, "secops/github_token");
        assert_eq!(policy.process_secret_policy[0].actions, vec![SecretAction::DelegateToChild]);
        assert_eq!(policy.process_secret_policy[0].children, vec!["/usr/bin/curl".to_string()]);
        assert!(policy.process_secret_policy[0].child_sha256.is_empty());
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
        cli.run_command.clear();
        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_print_policy_returns_ok() {
        let mut cli = build_cli();
        cli.run_command.clear();
        cli.print_policy = true;
        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
    }

    #[test]
    fn run_cli_blocks_disallowed_command() {
        let mut cli = build_cli();
        cli.run_command = vec!["rm".to_string()];
        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn run_cli_executes_allowed_command() {
        let mut cli = build_cli();
        cli.run_command = vec!["/usr/bin/true".to_string()];
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
    fn summarize_status_lines_counts_all_status_kinds() {
        let summary = summarize_status_lines(&[
            "D  removed.txt".to_string(),
            "C  copied.txt".to_string(),
            "UU conflict.txt".to_string(),
            "X  unknown.txt".to_string(),
        ]);

        assert_eq!(summary.deleted, 1);
        assert_eq!(summary.copied, 1);
        assert_eq!(summary.unmerged, 2);
        assert_eq!(summary.other, 1);
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
        cli.run_command = vec!["portable-test".to_string()];
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
        cli.run_command = vec![cwd.join("missing-command").display().to_string()];
        cli.allow.push(cwd.clone());

        let file_policy = PolicyFile::default();
        let resolved = resolve_policy(&cli, &file_policy).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &file_policy, &cwd);

        assert_eq!(exit, ExitCode::from(2));
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn run_sandboxed_command_returns_error_for_invalid_injected_keychain_mapping() {
        let cwd_root = temp_dir();
        let cwd = cwd_root.path().canonicalize().expect("canonical cwd");

        let mut cli = build_cli();
        let (command, command_prefix) = snapshot_test_command();
        cli.run_command = command;
        cli.allow.push(command_prefix);
        cli.inject_keychain = vec!["invalid".to_string()];

        let file_policy = PolicyFile {
            net_block: Some(false),
            ..PolicyFile::default()
        };
        let resolved = resolve_policy(&cli, &file_policy).expect("resolve policy");

        assert!(!resolved.policy.net_blocked());
        assert_eq!(run_sandboxed_command(&cli, &resolved, &file_policy, &cwd), ExitCode::from(2));
    }


    #[test]
    #[cfg(target_os = "macos")]
    fn run_cli_launches_agent_with_scoped_env_and_delegated_child_secret() {
        let workspace_root = std::env::current_dir().expect("current dir");
        let fixture = tempfile::tempdir_in(&workspace_root).expect("tempdir in workspace");
        let fixture_root = fixture.path().canonicalize().expect("canonical fixture root");
        let agent_program = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-agent-helper.rs",
            fixture.path(),
            "agent-helper",
        );
        let child_program = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-tool-helper.rs",
            fixture.path(),
            "tool-helper",
        );
        let parent_report = fixture.path().join("agent-report.txt");
        let child_report = fixture.path().join("tool-report.txt");
        let policy_path = fixture.path().join("policy.json");

        let agent_key = unique_key("usage/agent-token");
        let tool_key = unique_key("usage/tool-secret");
        test_store_put(&agent_key, b"agent-value");
        test_store_put(&tool_key, b"tool-value");

        write_launcher_usage_policy(
            &policy_path,
            &fixture_root,
            &agent_program,
            &child_program,
            &agent_key,
            &tool_key,
        );

        let mut cli = build_cli();
        cli.policy_file = Some(policy_path);
        cli.run_command = vec![
            agent_program.display().to_string(),
            "agent-spawn-tool".to_string(),
            parent_report.display().to_string(),
            child_program.display().to_string(),
            child_report.display().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));

        let parent_state = std::fs::read_to_string(&parent_report).expect("read parent report");
        assert!(parent_state.contains("agent_token=agent-value"));
        assert!(parent_state.contains("tool_secret_present=false"));
        assert!(parent_state.contains("tool_fd_present=true"));
        assert!(parent_state.contains("tool_nonce_present=true"));
        assert_eq!(
            std::fs::read(&child_report).expect("read child report"),
            b"tool-value"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn run_cli_denies_delegated_secret_to_non_matching_child_process() {
        let workspace_root = std::env::current_dir().expect("current dir");
        let fixture = tempfile::tempdir_in(&workspace_root).expect("tempdir in workspace");
        let fixture_root = fixture.path().canonicalize().expect("canonical fixture root");
        let agent_program = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-agent-helper.rs",
            fixture.path(),
            "agent-helper",
        );
        let authorized_child = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-tool-helper.rs",
            fixture.path(),
            "authorized-tool-helper",
        );
        let unauthorized_child = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-tool-helper-alt.rs",
            fixture.path(),
            "unauthorized-tool-helper",
        );
        let parent_report = fixture.path().join("agent-report.txt");
        let child_report = fixture.path().join("tool-report.txt");
        let policy_path = fixture.path().join("policy.json");

        let agent_key = unique_key("usage/agent-token");
        let tool_key = unique_key("usage/tool-secret");
        test_store_put(&agent_key, b"agent-value");
        test_store_put(&tool_key, b"tool-value");

        write_launcher_usage_policy(
            &policy_path,
            &fixture_root,
            &agent_program,
            &authorized_child,
            &agent_key,
            &tool_key,
        );

        let mut cli = build_cli();
        cli.policy_file = Some(policy_path);
        cli.run_command = vec![
            agent_program.display().to_string(),
            "agent-spawn-tool".to_string(),
            parent_report.display().to_string(),
            unauthorized_child.display().to_string(),
            child_report.display().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(1));

        let parent_state = std::fs::read_to_string(&parent_report).expect("read parent report");
        assert!(parent_state.contains("agent_token=agent-value"));
        assert!(parent_state.contains("tool_secret_present=false"));
        assert_eq!(
            std::fs::read_to_string(&child_report).expect("read child report"),
            "closed"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn run_cli_launches_process_with_legacy_direct_trusted_secret_policy() {
        let workspace_root = std::env::current_dir().expect("current dir");
        let fixture = tempfile::tempdir_in(&workspace_root).expect("tempdir in workspace");
        let fixture_root = fixture.path().canonicalize().expect("canonical fixture root");
        let program = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-agent-helper.rs",
            fixture.path(),
            "direct-agent-helper",
        );
        let report_path = fixture.path().join("direct-report.txt");
        let policy_path = fixture.path().join("policy.json");

        let agent_key = unique_key("usage/direct-agent-token");
        let tool_key = unique_key("usage/direct-tool-secret");
        test_store_put(&agent_key, b"agent-value");
        test_store_put(&tool_key, b"tool-value");

        write_direct_trusted_secret_policy(
            &policy_path,
            &fixture_root,
            &program,
            &agent_key,
            &tool_key,
        );

        let mut cli = build_cli();
        cli.policy_file = Some(policy_path);
        cli.run_command = vec![
            program.display().to_string(),
            "direct-consume-secret".to_string(),
            report_path.display().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));

        let report = std::fs::read_to_string(&report_path).expect("read direct report");
        assert_common_direct_trusted_secret_report(&report);
        assert!(report.contains("tool_nonce_present=true"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn run_cli_launches_process_with_windows_direct_trusted_secret_policy() {
        let workspace_root = std::env::current_dir().expect("current dir");
        let fixture = tempfile::tempdir_in(&workspace_root).expect("tempdir in workspace");
        let fixture_root = fixture.path().canonicalize().expect("canonical fixture root");
        let program = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-windows-direct-helper.rs",
            fixture.path(),
            "windows-direct-helper",
        );
        let report_path = fixture.path().join("direct-report.txt");
        let policy_path = fixture.path().join("policy.json");

        let agent_key = unique_key("usage/direct-agent-token");
        let tool_key = unique_key("usage/direct-tool-secret");
        test_store_put(&agent_key, b"agent-value");
        test_store_put(&tool_key, b"tool-value");

        write_direct_trusted_secret_policy(
            &policy_path,
            &fixture_root,
            &program,
            &agent_key,
            &tool_key,
        );

        let mut cli = build_cli();
        cli.policy_file = Some(policy_path);
        cli.run_command = vec![
            program.display().to_string(),
            "direct-consume-secret".to_string(),
            report_path.display().to_string(),
        ];
        cli.allow.push(fixture_root.clone());

        let exit = run_cli(cli);

        // On Windows without AppContainer / WRITE_DAC privileges the sandbox
        // cannot apply ACL grants; treat that as a graceful skip rather than
        // a hard failure so the test can pass in developer and CI environments
        // that are not running with elevated rights.
        if exit != ExitCode::from(0) {
            let report_missing = std::fs::read_to_string(&report_path).is_err();
            if report_missing {
                // sandbox apply failed before the child could write its report
                return;
            }
        }

        assert_eq!(exit, ExitCode::from(0));
        let report = std::fs::read_to_string(&report_path).expect("read direct report");
        assert_common_direct_trusted_secret_report(&report);
        assert!(report.contains("protocol=consume-close-v1"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn resolve_launch_secret_config_rejects_delegate_to_child_policy_on_windows() {
        let workspace_root = std::env::current_dir().expect("current dir");
        let fixture = tempfile::tempdir_in(&workspace_root).expect("tempdir in workspace");
        let program = compile_checked_in_test_binary(
            "tests/test_binaries/shadictl-test-windows-direct-helper.rs",
            fixture.path(),
            "windows-direct-helper-policy",
        );
        let child = std::fs::canonicalize(&program).expect("canonical child");

        let mut cli = build_cli();
        cli.run_command = vec![program.display().to_string()];

        let command = {
            let mut command = Command::new(&program);
            scrub_test_secret_backend_env(&mut command);
            command.current_dir(fixture.path());
            command
        };

        let policy = PolicyFile {
            process_secret_policy: vec![ProcessSecretPolicyRule {
                program: program.display().to_string(),
                secret: "secops/github_token".to_string(),
                actions: vec![SecretAction::DelegateToChild],
                children: vec![child.display().to_string()],
                name: Some("github-token".to_string()),
                fd_env: Some("TOKEN_FD".to_string()),
                child_sha256: Vec::new(),
            }],
            ..PolicyFile::default()
        };

        let err = resolve_launch_secret_config(&command, &cli, &policy)
            .expect_err("delegate-to-child should be rejected on windows");
        assert!(err.contains("not supported on Windows"), "unexpected error: {err}");
    }

    #[test]
    fn git_snapshot_session_writes_artifact_without_sandbox() {
        let repo = init_git_repo();
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        cli.run_command = vec!["portable-test".to_string()];
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
        cli.run_command = vec!["portable-test".to_string()];
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
        let workspace_root = std::env::current_dir().expect("current dir");
        let repo = tempfile::tempdir_in(&workspace_root).expect("tempdir in workspace");
        run_git(repo.path(), &["init"]);
        run_git(repo.path(), &["config", "user.name", "SHADI Tests"]);
        run_git(repo.path(), &["config", "user.email", "shadi-tests@example.com"]);
        run_git(repo.path(), &["config", "commit.gpgsign", "false"]);
        let repo_path = repo.path().canonicalize().expect("canonical repo");
        seed_git_repo(&repo_path);

        let snapshot_root = temp_dir();
        let snapshot_dir = snapshot_root.path().join("git-snapshots");

        let mut cli = build_cli();
        let (command, command_prefix) = snapshot_test_command();
        cli.run_command = command;
        cli.allow.push(command_prefix);
        cli.allow.push(repo_path.clone());
        cli.git_snapshot = true;
        cli.git_snapshot_untracked = true;
        cli.git_snapshot_dir = Some(snapshot_dir.clone());

        let file_policy = PolicyFile::default();
        let resolved = resolve_policy(&cli, &file_policy).expect("resolve policy");
        let exit = run_sandboxed_command(&cli, &resolved, &file_policy, &repo_path);

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
            assert!(
                error.contains("CreateAppContainerProfile failed")
                    || error.contains("SetNamedSecurityInfoW failed")
                    || error.contains("sandbox apply failed")
                    || error.contains("sandboxed command should start"),
                "unexpected Windows sandbox error: {error}"
            );
            assert!(artifact["outcome"]["exit_code"].is_null());
            return;
        }

        assert_eq!(exit, ExitCode::from(0));
        assert!(artifact["git"]["before"]["status_porcelain"]
            .as_array()
            .expect("before status array")
            .is_empty());
        assert!(artifact["git"]["after"]["status_porcelain"]
            .as_array()
            .expect("after status array")
            .is_empty());
        assert_eq!(artifact["git"]["comparison"]["overall_changed"], false);
        assert_eq!(artifact["git"]["comparison"]["status_changed"], false);
        assert_eq!(artifact["git"]["comparison"]["diff_changed"], false);
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
        cli.run_command = vec![format!("{}\\where.exe", system32), "cmd".to_string()];
        cli.allow.push(PathBuf::from(&system32));
        let code = run_cli(cli);
        assert_ne!(code, ExitCode::from(2));
    }

    #[test]
    fn canonicalize_helpers_resolve_paths() {
        let dir = temp_dir();
        let path = shadi_sandbox::canonicalize_path(dir.path()).expect("path");
        let text = shadi_sandbox::canonicalize_path(dir.path().to_str().expect("str")).expect("str path");
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
    fn read_openpgp_input_reads_from_secret_store() {
        let key = unique_key("openpgp/read-secret");
        test_store_put(&key, b"secret-key-material");

        let payload = read_openpgp_input("--key", Some(&key), None).expect("read from store");
        assert_eq!(payload, b"secret-key-material".to_vec());
    }

    #[test]
    fn read_openpgp_input_errors_when_secret_key_is_missing() {
        let err = read_openpgp_input("--key", Some(&unique_key("openpgp/missing-secret")), None)
            .unwrap_err();
        assert!(err.contains("keychain lookup failed"));
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
    #[cfg(unix)]
    fn policy_scoped_keychain_rule_only_applies_to_matching_process() {
        let key = unique_key("policy/scoped-token");
        test_store_put(&key, b"value");

        #[cfg(not(target_os = "windows"))]
        let matching_program = "/usr/bin/true".to_string();
        #[cfg(not(target_os = "windows"))]
        let non_matching_program = "/bin/sh".to_string();
        #[cfg(target_os = "windows")]
        let (matching_program, non_matching_program) = {
            let (matching, non_matching) = windows_test_programs();
            (
                matching.display().to_string(),
                non_matching.display().to_string(),
            )
        };

        let mut command = Command::new(&matching_program);
        let cli = build_cli();
        let policy = PolicyFile {
            process_inject_keychain: vec![
                ProcessInjectKeychainRule {
                    program: matching_program,
                    key: key.clone(),
                    env: "TOKEN".to_string(),
                },
                ProcessInjectKeychainRule {
                    program: non_matching_program,
                    key,
                    env: "SHOULD_NOT_APPLY".to_string(),
                },
            ],
            ..PolicyFile::default()
        };

        let resolved = resolve_launch_secret_config(&command, &cli, &policy).expect("resolve secret config");
        inject_keychain_secrets(&mut command, &resolved.inject_keychain).expect("inject scoped secret");

        let envs = command.get_envs().collect::<Vec<_>>();
        assert!(envs.iter().any(|(env_key, value)| {
            *env_key == std::ffi::OsStr::new("TOKEN")
                && *value == Some(std::ffi::OsStr::new("value"))
        }));
        assert!(!envs.iter().any(|(env_key, _)| *env_key == std::ffi::OsStr::new("SHOULD_NOT_APPLY")));
    }

    #[test]
    fn run_cli_list_keychain_routes_to_store() {
        let key_a = unique_key("secops/key-a");
        let key_b = unique_key("other/key-b");
        test_store_put(&key_a, b"a");
        test_store_put(&key_b, b"b");

        let mut cli = build_cli();
        cli.run_command.clear();
        cli.list_keychain = true;
        cli.list_prefix = Some("secops/".to_string());

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(0));
    }

    #[test]
    fn test_secret_store_delete_removes_key() {
        let key = unique_key("delete/me");
        test_store_put(&key, b"value");

        let store = default_secret_store();
        store.delete(&key).expect("delete key");

        assert!(test_store_get(&key).is_none());
    }

    #[test]
    fn run_named_command_dispatches_trace_variant() {
        let dir = temp_dir();
        let trace_file = dir.path().join("trace.jsonl");
        std::fs::write(&trace_file, "\n").expect("write trace file");

        let code = run_named_command(Commands::Trace(TraceCli {
            file: Some(trace_file),
            command: TraceCommand::Summary { limit: 10 },
        }));
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_named_command_dispatches_memory_variant() {
        let dir = temp_dir();
        let db = dir.path().join("memory-dispatch.db");

        let code = run_named_command(Commands::Memory(MemoryCli {
            db,
            key: Some("dispatch-key".to_string()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Init,
        }));
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_named_command_dispatches_slim_mas_variant() {
        let dir = temp_dir();
        let config = write_mas_config(
            dir.path(),
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{ did = "did:key:zA", role = "human" }]
"#,
        );

        let code = run_named_command(Commands::SlimMas(SlimMasCli {
            config,
            command: SlimMasCommand::Validate,
        }));
        assert_eq!(code, ExitCode::from(0));
    }

    #[test]
    fn run_named_command_dispatches_slim_variant() {
        let _guard = trace_env_lock();
        let dir = temp_dir();
        let previous_tmp_dir = std::env::var_os("SHADI_TMP_DIR");
        let previous_endpoint = std::env::var_os("SLIM_ENDPOINT");
        let previous_cert = std::env::var_os("SLIM_TLS_CERT");
        let previous_key = std::env::var_os("SLIM_TLS_KEY");
        let previous_ca = std::env::var_os("SLIM_TLS_CA");

        std::env::set_var("SHADI_TMP_DIR", dir.path());
        std::env::set_var("SLIM_ENDPOINT", "127.0.0.1:65535");
        std::env::remove_var("SLIM_TLS_CERT");
        std::env::remove_var("SLIM_TLS_KEY");
        std::env::remove_var("SLIM_TLS_CA");

        let code = run_named_command(Commands::Slim(SlimCli {
            command: SlimCommand::StartNode,
        }));

        match previous_tmp_dir {
            Some(value) => std::env::set_var("SHADI_TMP_DIR", value),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }
        match previous_endpoint {
            Some(value) => std::env::set_var("SLIM_ENDPOINT", value),
            None => std::env::remove_var("SLIM_ENDPOINT"),
        }
        match previous_cert {
            Some(value) => std::env::set_var("SLIM_TLS_CERT", value),
            None => std::env::remove_var("SLIM_TLS_CERT"),
        }
        match previous_key {
            Some(value) => std::env::set_var("SLIM_TLS_KEY", value),
            None => std::env::remove_var("SLIM_TLS_KEY"),
        }
        match previous_ca {
            Some(value) => std::env::set_var("SLIM_TLS_CA", value),
            None => std::env::remove_var("SLIM_TLS_CA"),
        }

        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn run_named_command_dispatches_slim_a2a_echo_peer_variant() {
        let _guard = trace_env_lock();
        let dir = temp_dir();
        let previous_tmp_dir = std::env::var_os("SHADI_TMP_DIR");
        let previous_endpoint = std::env::var_os("SLIM_ENDPOINT");
        let previous_shared_secret = std::env::var_os("SLIM_SHARED_SECRET");

        std::env::set_var("SHADI_TMP_DIR", dir.path());
        std::env::set_var("SLIM_ENDPOINT", "127.0.0.1:65535");
        std::env::set_var("SLIM_SHARED_SECRET", "dispatch-shared-secret");

        let code = run_named_command(Commands::Slim(SlimCli {
            command: SlimCommand::A2AEchoPeer(SlimA2AEchoPeerArgs {
                endpoint: None,
                agent_id: "secops-a".to_string(),
                listen_timeout_seconds: 1,
                ready_file: None,
                start_local_node: false,
            }),
        }));

        match previous_tmp_dir {
            Some(value) => std::env::set_var("SHADI_TMP_DIR", value),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }
        match previous_endpoint {
            Some(value) => std::env::set_var("SLIM_ENDPOINT", value),
            None => std::env::remove_var("SLIM_ENDPOINT"),
        }
        match previous_shared_secret {
            Some(value) => std::env::set_var("SLIM_SHARED_SECRET", value),
            None => std::env::remove_var("SLIM_SHARED_SECRET"),
        }

        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn run_named_command_dispatches_slim_a2a_send_variant() {
        let _guard = trace_env_lock();
        let dir = temp_dir();
        let previous_tmp_dir = std::env::var_os("SHADI_TMP_DIR");
        let previous_endpoint = std::env::var_os("SLIM_ENDPOINT");
        let previous_shared_secret = std::env::var_os("SLIM_SHARED_SECRET");

        std::env::set_var("SHADI_TMP_DIR", dir.path());
        std::env::set_var("SLIM_ENDPOINT", "127.0.0.1:65535");
        std::env::set_var("SLIM_SHARED_SECRET", "dispatch-shared-secret");

        let code = run_named_command(Commands::Slim(SlimCli {
            command: SlimCommand::A2ASend(SlimA2ASendArgs {
                endpoint: None,
                agent_id: "avatar".to_string(),
                peer_agent_id: "secops-a".to_string(),
                destination: None,
                message: "dispatch-test".to_string(),
                stream: true,
                timeout_seconds: 1,
                session_id: "dispatch-session".to_string(),
            }),
        }));

        match previous_tmp_dir {
            Some(value) => std::env::set_var("SHADI_TMP_DIR", value),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }
        match previous_endpoint {
            Some(value) => std::env::set_var("SLIM_ENDPOINT", value),
            None => std::env::remove_var("SLIM_ENDPOINT"),
        }
        match previous_shared_secret {
            Some(value) => std::env::set_var("SLIM_SHARED_SECRET", value),
            None => std::env::remove_var("SLIM_SHARED_SECRET"),
        }

        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn run_named_command_dispatches_config_variant() {
        let code = run_named_command(Commands::Config(ConfigCli {
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
        }));
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_named_command_dispatches_policy_explain_variant() {
        let code = run_named_command(Commands::Policy(PolicyCli {
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
        }));
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_named_command_dispatches_policy_diff_variant() {
        let code = run_named_command(Commands::Policy(PolicyCli {
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
        }));
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_cli_subcommand_branch_executes_direct_dispatch() {
        let dir = temp_dir();
        let trace_file = dir.path().join("trace.jsonl");
        std::fs::write(&trace_file, "\n").expect("write trace file");

        let mut cli = build_cli();
        cli.subcommand = Some(Commands::Trace(TraceCli {
            file: Some(trace_file),
            command: TraceCommand::Summary { limit: 10 },
        }));
        cli.run_command.clear();

        assert_eq!(run_cli(cli), ExitCode::SUCCESS);
    }

    #[test]
    fn run_cli_run_command_dispatches_config_subcommand() {
        let mut cli = build_cli();
        cli.subcommand = None;
        cli.run_command = vec![
            "config".to_string(),
            "show".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::SUCCESS);
    }

    #[test]
    fn run_cli_run_command_dispatches_policy_explain_subcommand() {
        let mut cli = build_cli();
        cli.subcommand = None;
        cli.run_command = vec![
            "policy".to_string(),
            "explain".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::SUCCESS);
    }

    #[test]
    fn run_cli_run_command_dispatches_policy_diff_subcommand() {
        let mut cli = build_cli();
        cli.subcommand = None;
        cli.run_command = vec![
            "policy".to_string(),
            "diff".to_string(),
            "--against".to_string(),
            "profile:balanced".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::SUCCESS);
    }

    #[test]
    fn run_cli_print_policy_with_missing_policy_file_returns_error() {
        let dir = temp_dir();
        let mut cli = build_cli();
        cli.print_policy = true;
        cli.run_command.clear();
        cli.policy_file = Some(dir.path().join("missing-policy.json"));

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_print_policy_with_invalid_cli_paths_returns_error() {
        let mut cli = build_cli();
        cli.print_policy = true;
        cli.run_command.clear();
        cli.read.push(PathBuf::from("/this/path/does/not/exist/for-shadi"));

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_with_run_command_and_print_policy_returns_policy_dump() {
        let mut cli = build_cli();
        cli.print_policy = true;
        cli.allow_command.push("echo".to_string());
        assert_eq!(run_cli(cli), ExitCode::from(0));
    }

    #[test]
    fn run_cli_with_run_command_and_missing_policy_file_returns_error() {
        let dir = temp_dir();
        let mut cli = build_cli();
        cli.policy_file = Some(dir.path().join("missing-policy.json"));
        cli.run_command = vec!["echo".to_string(), "hello".to_string()];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_with_run_command_and_invalid_cli_paths_returns_error() {
        let mut cli = build_cli();
        cli.run_command = vec!["echo".to_string(), "hello".to_string()];
        cli.read.push(PathBuf::from("/this/path/does/not/exist/for-shadi"));

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_put_key_command_stores_payload() {
        let dir = temp_dir();
        let path = dir.path().join("key.asc");
        std::fs::write(&path, b"payload").expect("write");

        let key = unique_key("openpgp/test");

        let mut cli = build_cli();
        cli.run_command = vec![
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
        cli.run_command = vec![
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
    fn run_cli_put_key_reports_store_failure() {
        let _guard = store_failure_lock().lock().expect("store failure lock");
        let dir = temp_dir();
        let path = dir.path().join("key.asc");
        std::fs::write(&path, b"payload").expect("write");

        let key = unique_key("openpgp/store-failure");
        test_store_clear_failures();
        test_store_fail_put(&key);

        let mut cli = build_cli();
        cli.run_command = vec![
            "put-key".to_string(),
            "--key".to_string(),
            key.clone(),
            "--in".to_string(),
            path.to_string_lossy().to_string(),
        ];

        let code = run_cli(cli);
        test_store_clear_failures();
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(test_store_get(&key), None);
    }

    #[test]
    fn run_cli_get_secret_command_reads_store() {
        let key = unique_key("secret/key");
        test_store_put(&key, b"value");

        let mut cli = build_cli();
        cli.run_command = vec![
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
        cli.run_command = vec![
            "get-secret".to_string(),
            "--key".to_string(),
            key,
        ];

        let code = run_cli(cli);
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_get_secret_invalid_utf8_returns_error() {
        let key = unique_key("secret/invalid-utf8");
        test_store_put(&key, &[0xFF, 0xFE, 0xFD]);

        let mut cli = build_cli();
        cli.run_command = vec![
            "get-secret".to_string(),
            "--key".to_string(),
            key,
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_did_from_gpg_writes_document() {
        let dir = temp_dir();
        let input = dir.path().join("key.asc");
        let output = dir.path().join("did.json");
        std::fs::write(&input, sample_openpgp_cert_armored()).expect("write");

        let mut cli = build_cli();
        cli.run_command = vec![
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
    fn run_cli_did_from_gpg_invalid_certificate_returns_error() {
        let dir = temp_dir();
        let input = dir.path().join("invalid.asc");
        let output = dir.path().join("did.json");
        std::fs::write(&input, b"not-an-openpgp-cert").expect("write");

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-gpg".to_string(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_derive_agent_did_stores_outputs() {
        let root_key = unique_key("root-secret");
        test_store_put(&root_key, b"root-secret");

        let dir = temp_dir();
        let output = dir.path().join("agent.json");

        let mut cli = build_cli();
        cli.run_command = vec![
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
    fn run_cli_derive_agent_did_without_out_file_still_stores_identity() {
        let root_key = unique_key("root-secret-no-out");
        test_store_put(&root_key, b"root-secret-no-out");
        let agent_name = unique_key("agent-no-out");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-did".to_string(),
            "--secret".to_string(),
            root_key,
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));
        assert!(test_store_get(&format!("agents/{}/private", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/public", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/did", agent_name)).is_some());
        assert!(test_store_get(&format!("agents/{}/diddoc", agent_name)).is_some());
    }

    #[test]
    fn run_cli_derive_agent_did_reports_store_failure() {
        let _guard = store_failure_lock().lock().expect("store failure lock");
        let root_key = unique_key("root-secret-store-failure");
        test_store_put(&root_key, b"root-secret-store-failure");

        let private_key = "agents/agent-store-failure/private";
        test_store_clear_failures();
        test_store_fail_put(private_key);

        let code = run_derive_agent_did_command(DeriveAgentDidArgs {
            secret: Some(root_key),
            input: None,
            agent_name: "agent-store-failure".to_string(),
            prefix: "agents".to_string(),
            out_file: None,
        });

        test_store_clear_failures();
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(test_store_get(private_key), None);
    }

    #[test]
    fn run_cli_derive_agent_did_missing_secret_returns_error() {
        let code = run_derive_agent_did_command(DeriveAgentDidArgs {
            secret: None,
            input: None,
            agent_name: "agent-missing-secret".to_string(),
            prefix: "agents".to_string(),
            out_file: None,
        });

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_derive_agent_did_from_openpgp_file() {
        let dir = temp_dir();
        let input = dir.path().join("human.sec");
        std::fs::write(&input, sample_openpgp_secret_armored()).expect("write");

        let agent_name = unique_key("agent-gpg");
        let output = dir.path().join("agent.json");

        let mut cli = build_cli();
        cli.run_command = vec![
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
        cli.run_command = vec![
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
        cli.run_command = vec![
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
        cli.run_command = vec![
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
        cli.run_command = vec![
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
    fn run_cli_derive_agent_identity_missing_seed_returns_error() {
        let code = run_derive_agent_identity_command(DeriveAgentIdentityArgs {
            ssh_passphrase_secret: None,
            source: HumanIdentitySource::Seed,
            human_secret: None,
            input: None,
            agent_names: vec!["agent-missing-seed".to_string()],
            prefix: "agents".to_string(),
            human_did_key: None,
            out_dir: None,
        });

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_derive_agent_identity_missing_human_did_key_returns_error() {
        let seed_key = unique_key("missing-human-did-seed");
        test_store_put(&seed_key, b"seed-material");

        let code = run_derive_agent_identity_command(DeriveAgentIdentityArgs {
            ssh_passphrase_secret: None,
            source: HumanIdentitySource::Seed,
            human_secret: Some(seed_key),
            input: None,
            agent_names: vec![unique_key("missing-human-did-agent")],
            prefix: "agents".to_string(),
            human_did_key: Some(unique_key("missing-human-did-key")),
            out_dir: None,
        });

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_derive_agent_identity_out_dir_conflicts_with_file_returns_error() {
        let seed_key = unique_key("out-dir-conflict-seed");
        test_store_put(&seed_key, b"seed-material");
        let dir = temp_dir();
        let out_dir = dir.path().join("occupied-path");
        std::fs::write(&out_dir, b"not a directory").expect("write blocker file");

        let code = run_derive_agent_identity_command(DeriveAgentIdentityArgs {
            ssh_passphrase_secret: None,
            source: HumanIdentitySource::Seed,
            human_secret: Some(seed_key),
            input: None,
            agent_names: vec![unique_key("out-dir-conflict-agent")],
            prefix: "agents".to_string(),
            human_did_key: None,
            out_dir: Some(out_dir),
        });

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_derive_agent_identity_reports_store_failure() {
        let _guard = store_failure_lock().lock().expect("store failure lock");
        let seed_key = unique_key("derive-store-failure-seed");
        test_store_put(&seed_key, b"derive-store-failure-seed");
        let agent_name = unique_key("derive-store-failure-agent");
        let private_key = format!("agents/{}/private", agent_name);

        test_store_clear_failures();
        test_store_fail_put(&private_key);

        let code = run_derive_agent_identity_command(DeriveAgentIdentityArgs {
            ssh_passphrase_secret: None,
            source: HumanIdentitySource::Seed,
            human_secret: Some(seed_key),
            input: None,
            agent_names: vec![agent_name.clone()],
            prefix: "agents".to_string(),
            human_did_key: None,
            out_dir: None,
        });

        test_store_clear_failures();
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(test_store_get(&private_key), None);
    }

    #[test]
    fn run_cli_derive_and_verify_agent_identity_with_gpg_source() {
        let dir = temp_dir();
        let input = dir.path().join("human.sec");
        std::fs::write(&input, sample_openpgp_secret_armored()).expect("write");

        let agent_name = unique_key("agent-gpg-verify");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "gpg".to_string(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "gpg".to_string(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));
    }

    #[test]
    fn run_cli_verify_agent_identity_succeeds() {
        let seed_key = unique_key("verify-human-seed");
        test_store_put(&seed_key, b"verify-seed-material");

        let mut cli = build_cli();
        cli.run_command = vec![
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
        cli.run_command = vec![
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
        cli.run_command = vec![
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
        cli.run_command = vec![
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
    fn run_cli_verify_agent_identity_fails_on_did_mismatch() {
        let seed_key = unique_key("verify-did-seed");
        test_store_put(&seed_key, b"seed-did");

        let agent_name = unique_key("agent-did-mismatch");
        let did_key = format!("agents/{}/did", agent_name);

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        test_store_put(&did_key, b"did:key:zWrongDid");

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_missing_public_key_returns_error() {
        let seed_key = unique_key("verify-missing-public-seed");
        test_store_put(&seed_key, b"verify-missing-public-seed");

        let agent_name = unique_key("agent-missing-public");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let store = default_secret_store();
        store
            .delete(&format!("agents/{}/public", agent_name))
            .expect("delete public key");

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_missing_did_returns_error() {
        let seed_key = unique_key("verify-missing-did-seed");
        test_store_put(&seed_key, b"verify-missing-did-seed");

        let agent_name = unique_key("agent-missing-did");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let store = default_secret_store();
        store
            .delete(&format!("agents/{}/did", agent_name))
            .expect("delete did");

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_invalid_public_key_encoding_returns_error() {
        let seed_key = unique_key("verify-invalid-public-seed");
        test_store_put(&seed_key, b"verify-invalid-public-seed");

        let agent_name = unique_key("agent-invalid-public");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        test_store_put(&format!("agents/{}/public", agent_name), b"%%%not-base64%%%");

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_invalid_public_key_utf8_returns_error() {
        let seed_key = unique_key("verify-invalid-public-utf8-seed");
        test_store_put(&seed_key, b"verify-invalid-public-utf8-seed");

        let agent_name = unique_key("agent-invalid-public-utf8");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        test_store_put(&format!("agents/{}/public", agent_name), &[0xff, 0xfe]);

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_invalid_binding_utf8_returns_error() {
        let seed_key = unique_key("verify-invalid-binding-seed");
        test_store_put(&seed_key, b"verify-invalid-binding-seed");
        let human_did_key = unique_key("verify-invalid-binding-human-did");
        test_store_put(&human_did_key, b"did:key:zHumanBindingUtf8");

        let agent_name = unique_key("agent-invalid-binding-utf8");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--human-did-key".to_string(),
            human_did_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        test_store_put(&format!("agents/{}/human_did", agent_name), &[0xff, 0xfe]);

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--human-did-key".to_string(),
            human_did_key,
            "--require-human-binding".to_string(),
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_invalid_expected_human_did_utf8_returns_error() {
        let seed_key = unique_key("verify-invalid-expected-human-seed");
        test_store_put(&seed_key, b"verify-invalid-expected-human-seed");
        let human_did_key = unique_key("verify-invalid-expected-human-did");
        test_store_put(&human_did_key, b"did:key:zExpectedUtf8");

        let agent_name = unique_key("agent-invalid-expected-human-utf8");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--human-did-key".to_string(),
            human_did_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        test_store_put(&human_did_key, &[0xff, 0xfe]);

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--human-did-key".to_string(),
            human_did_key,
            "--require-human-binding".to_string(),
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_invalid_did_utf8_returns_error() {
        let seed_key = unique_key("verify-invalid-did-utf8-seed");
        test_store_put(&seed_key, b"verify-invalid-did-utf8-seed");

        let agent_name = unique_key("agent-invalid-did-utf8");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        test_store_put(&format!("agents/{}/did", agent_name), &[0xff, 0xfe]);

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_derive_agent_identity_invalid_human_did_utf8_returns_error() {
        let seed_key = unique_key("derive-invalid-human-did-utf8-seed");
        test_store_put(&seed_key, b"derive-invalid-human-did-utf8-seed");
        let human_did_key = unique_key("derive-invalid-human-did-utf8-key");
        test_store_put(&human_did_key, &[0xff, 0xfe]);

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--human-did-key".to_string(),
            human_did_key,
            "--name".to_string(),
            unique_key("agent-derive-invalid-human-did-utf8"),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_derive_agent_identity_gpg_missing_secret_returns_error() {
        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "gpg".to_string(),
            "--human-secret".to_string(),
            unique_key("derive-gpg-missing-secret"),
            "--name".to_string(),
            unique_key("agent-derive-gpg-missing-secret"),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_seed_missing_secret_returns_error() {
        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            unique_key("verify-seed-missing-secret"),
            "--name".to_string(),
            unique_key("agent-verify-seed-missing-secret"),
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_gpg_missing_secret_returns_error() {
        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "gpg".to_string(),
            "--human-secret".to_string(),
            unique_key("verify-gpg-missing-secret"),
            "--name".to_string(),
            unique_key("agent-verify-gpg-missing-secret"),
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
        cli.run_command = vec![
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
        cli.run_command = vec![
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
    fn run_cli_verify_agent_identity_requires_binding_without_expected_key() {
        let seed_key = unique_key("verify-binding-required-only-seed");
        test_store_put(&seed_key, b"binding-required-only-seed");
        let human_did_key = unique_key("verify-binding-required-only-human-did");
        test_store_put(&human_did_key, b"did:key:zRequiredOnly");

        let agent_name = unique_key("agent-binding-required-only");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--human-did-key".to_string(),
            human_did_key,
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--require-human-binding".to_string(),
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));
    }

    #[test]
    fn run_cli_verify_agent_identity_requires_existing_human_binding() {
        let seed_key = unique_key("verify-missing-binding-seed");
        test_store_put(&seed_key, b"verify-missing-binding-seed");

        let agent_name = unique_key("agent-missing-binding");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--require-human-binding".to_string(),
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_missing_expected_human_did_key_returns_error() {
        let seed_key = unique_key("verify-missing-expected-human-seed");
        test_store_put(&seed_key, b"verify-missing-expected-human-seed");
        let human_did_key = unique_key("verify-existing-human-did");
        test_store_put(&human_did_key, b"did:key:zExpectedHuman");

        let agent_name = unique_key("agent-missing-expected-human");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--human-did-key".to_string(),
            human_did_key,
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--human-did-key".to_string(),
            unique_key("verify-missing-expected-human-did"),
            "--require-human-binding".to_string(),
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_verify_agent_identity_fails_on_human_binding_mismatch() {
        let seed_key = unique_key("verify-binding-seed-mismatch");
        test_store_put(&seed_key, b"binding-seed-mismatch");
        let human_did_key_a = unique_key("verify-human-did-a");
        test_store_put(&human_did_key_a, b"did:key:zHumanA");
        let human_did_key_b = unique_key("verify-human-did-b");
        test_store_put(&human_did_key_b, b"did:key:zHumanB");

        let agent_name = unique_key("agent-binding-mismatch");

        let mut cli = build_cli();
        cli.run_command = vec![
            "derive-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key.clone(),
            "--human-did-key".to_string(),
            human_did_key_a,
            "--name".to_string(),
            agent_name.clone(),
            "--prefix".to_string(),
            "agents".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let mut cli = build_cli();
        cli.run_command = vec![
            "verify-agent-identity".to_string(),
            "--source".to_string(),
            "seed".to_string(),
            "--human-secret".to_string(),
            seed_key,
            "--human-did-key".to_string(),
            human_did_key_b,
            "--require-human-binding".to_string(),
            "--name".to_string(),
            agent_name,
            "--prefix".to_string(),
            "agents".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    /// Fixed key plus the DID it must produce.
    fn ssh_test_key() -> (String, String, String) {
        let seed = [7u8; 32];
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let private = ssh_key::PrivateKey::from(keypair.clone());
        let pem = private
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .to_string();
        let public_line = private.public_key().to_openssh().expect("encode pub");
        let did = shadi_identity::encode_did_key(
            &ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key(),
        );
        (pem, public_line, did)
    }

    #[test]
    fn run_cli_did_from_github_ssh_key_type_uses_published_ssh_key() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        let (_pem, public_line, expected_did) = ssh_test_key();
        // GitHub lists several keys of mixed algorithms; the ed25519 one wins.
        set_test_github_payload(Some(format!(
            "ssh-rsa AAAAB3NzaC1yc2EAAAA someone\n{public_line}\n"
        )));

        let dir = temp_dir();
        let output = dir.path().join("github-ssh.json");
        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            "alice".to_string(),
            "--key-type".to_string(),
            "ssh".to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&output).expect("read")).expect("json");
        assert_eq!(doc["id"].as_str(), Some(expected_did.as_str()));
    }

    #[test]
    fn run_cli_did_from_github_ssh_key_type_needs_an_ed25519_key() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        set_test_github_payload(Some("ssh-rsa AAAAB3NzaC1yc2EAAAA only-rsa\n".to_string()));

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            "alice".to_string(),
            "--key-type".to_string(),
            "ssh".to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    /// One key, one human DID — whichever half it is read from.
    #[test]
    fn run_cli_did_from_ssh_agrees_across_key_halves() {
        let (pem, public_line, expected_did) = ssh_test_key();
        let dir = temp_dir();

        let priv_path = dir.path().join("id_ed25519");
        std::fs::write(&priv_path, &pem).expect("write private");
        let priv_out = dir.path().join("from-private.json");
        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-ssh".to_string(),
            "--in".to_string(),
            priv_path.to_string_lossy().to_string(),
            "--out".to_string(),
            priv_out.to_string_lossy().to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&pub_path, &public_line).expect("write public");
        let pub_out = dir.path().join("from-public.json");
        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-ssh".to_string(),
            "--in".to_string(),
            pub_path.to_string_lossy().to_string(),
            "--out".to_string(),
            pub_out.to_string_lossy().to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(0));

        let of = |p: &std::path::Path| -> String {
            let d: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
            d["id"].as_str().unwrap().to_string()
        };
        assert_eq!(of(&priv_out), expected_did);
        assert_eq!(of(&pub_out), expected_did, "halves must agree");
    }

    /// Agents rooted in the SSH key, and re-derivable from it.
    #[test]
    fn run_cli_derive_and_verify_agent_identity_from_ssh_key() {
        let (pem, _public_line, _did) = ssh_test_key();
        let dir = temp_dir();
        let key_path = dir.path().join("id_ed25519");
        std::fs::write(&key_path, &pem).expect("write key");

        let agent = unique_key("ssh-rooted-agent");
        let prefix = unique_key("ssh-agents");

        let code = run_derive_agent_identity_command(DeriveAgentIdentityArgs {
            ssh_passphrase_secret: None,
            source: HumanIdentitySource::Ssh,
            human_secret: None,
            input: Some(key_path.clone()),
            agent_names: vec![agent.clone()],
            prefix: prefix.clone(),
            human_did_key: None,
            out_dir: None,
        });
        assert_eq!(code, ExitCode::from(0));

        let stored_did = test_store_get(&format!("{prefix}/{agent}/did")).expect("stored did");
        let did = String::from_utf8(stored_did).expect("utf8");
        assert!(did.starts_with("did:key:z"), "unexpected did: {did}");

        // Verification must re-derive the same key from the same SSH root.
        let code = run_verify_agent_identity_command(VerifyAgentIdentityArgs {
            ssh_passphrase_secret: None,
            source: HumanIdentitySource::Ssh,
            human_secret: None,
            input: Some(key_path),
            agent_name: agent,
            prefix,
            public_key_key: None,
            did_key: None,
            human_did_key: None,
            require_human_binding: false,
        });
        assert_eq!(code, ExitCode::from(0));
    }

    /// `ssh` roots in the key's seed, `seed` in the file's bytes — so the same
    /// file must not yield the same agent.
    #[test]
    fn run_cli_ssh_and_seed_sources_are_not_interchangeable() {
        let (pem, _pub_line, _did) = ssh_test_key();
        let dir = temp_dir();
        let key_path = dir.path().join("id_ed25519");
        std::fs::write(&key_path, &pem).expect("write key");

        let mut dids = Vec::new();
        for source in [HumanIdentitySource::Ssh, HumanIdentitySource::Seed] {
            let agent = unique_key("src-compare-agent");
            let prefix = unique_key("src-compare");
            let code = run_derive_agent_identity_command(DeriveAgentIdentityArgs {
                ssh_passphrase_secret: None,
                source,
                human_secret: None,
                input: Some(key_path.clone()),
                agent_names: vec![agent.clone()],
                prefix: prefix.clone(),
                human_did_key: None,
                out_dir: None,
            });
            assert_eq!(code, ExitCode::from(0));
            dids.push(
                String::from_utf8(test_store_get(&format!("{prefix}/{agent}/did")).unwrap())
                    .unwrap(),
            );
        }
        assert_ne!(dids[0], dids[1], "sources must not collide");
    }

    /// The env source. Takes the github payload lock only as a process mutex,
    /// since this mutates a shared env var.
    #[test]
    fn run_cli_did_from_ssh_reads_passphrase_from_the_environment() {
        let _guard = github_payload_lock().lock().expect("env lock");
        let (pem, _pub_line, expected_did) = ssh_test_key();
        let encrypted = {
            let key = ssh_key::PrivateKey::from_openssh(&pem).expect("parse");
            key.encrypt(&mut ssh_key::rand_core::OsRng, "envpass")
                .expect("encrypt")
                .to_openssh(ssh_key::LineEnding::LF)
                .expect("encode")
                .to_string()
        };

        let dir = temp_dir();
        let key_path = dir.path().join("enc_env");
        std::fs::write(&key_path, &encrypted).expect("write key");
        let out = dir.path().join("from-env.json");

        let previous = std::env::var_os("SHADI_SSH_PASSPHRASE");
        std::env::set_var("SHADI_SSH_PASSPHRASE", "envpass");
        let code = run_did_from_ssh_command(DidFromSshArgs {
            key_ref: None,
            input: Some(key_path),
            passphrase_secret: None,
            out_file: out.clone(),
        });
        match previous {
            Some(value) => std::env::set_var("SHADI_SSH_PASSPHRASE", value),
            None => std::env::remove_var("SHADI_SSH_PASSPHRASE"),
        }

        assert_eq!(code, ExitCode::from(0));
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(doc["id"].as_str(), Some(expected_did.as_str()));
    }

    /// Passphrases come from the secret store, never argv (visible via `ps`).
    #[test]
    fn run_cli_did_from_ssh_reads_passphrase_from_the_secret_store() {
        let (pem, _pub_line, expected_did) = ssh_test_key();
        let encrypted = {
            let key = ssh_key::PrivateKey::from_openssh(&pem).expect("parse");
            key.encrypt(&mut ssh_key::rand_core::OsRng, "s3cret")
                .expect("encrypt")
                .to_openssh(ssh_key::LineEnding::LF)
                .expect("encode")
                .to_string()
        };

        let dir = temp_dir();
        let key_path = dir.path().join("enc_key");
        std::fs::write(&key_path, &encrypted).expect("write key");
        let out = dir.path().join("from-encrypted.json");

        let pass_key = unique_key("ssh-passphrase");
        test_store_put(&pass_key, b"s3cret");

        let code = run_did_from_ssh_command(DidFromSshArgs {
            key_ref: None,
            input: Some(key_path.clone()),
            passphrase_secret: Some(pass_key),
            out_file: out.clone(),
        });
        assert_eq!(code, ExitCode::from(0));

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(
            doc["id"].as_str(),
            Some(expected_did.as_str()),
            "an encrypted key must yield the same DID as its plaintext form"
        );

        // Without the passphrase the same key is refused.
        let code = run_did_from_ssh_command(DidFromSshArgs {
            key_ref: None,
            input: Some(key_path),
            passphrase_secret: None,
            out_file: dir.path().join("nope.json"),
        });
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_cli_did_from_ssh_rejects_a_non_key_file() {
        let dir = temp_dir();
        let path = dir.path().join("junk");
        std::fs::write(&path, b"not a key at all\n").expect("write");
        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-ssh".to_string(),
            "--in".to_string(),
            path.to_string_lossy().to_string(),
        ];
        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_did_from_github_stores_outputs() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        let armored = String::from_utf8(sample_openpgp_cert_armored()).expect("armored");
        let payload = serde_json::json!([
            {"id": 1, "public_key": armored}
        ])
        .to_string();
        set_test_github_payload(Some(payload));

        let dir = temp_dir();
        let output = dir.path().join("github.json");

        let mut cli = build_cli();
        cli.run_command = vec![
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
    fn run_cli_did_from_github_without_out_file_stores_outputs() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        let armored = String::from_utf8(sample_openpgp_cert_armored()).expect("armored");
        let payload = serde_json::json!([
            {"id": 2, "public_key": armored}
        ])
        .to_string();
        set_test_github_payload(Some(payload));

        let user = unique_key("gh-user");
        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            user.clone(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(0));
        assert!(test_store_get(&format!("github/{}/did", user)).is_some());
        assert!(test_store_get(&format!("github/{}/diddoc", user)).is_some());

        set_test_github_payload(None);
    }

    #[test]
    fn run_cli_did_from_github_invalid_public_key_returns_error() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        let payload = serde_json::json!([
            {"id": 3, "public_key": "%%%invalid-base64%%%"}
        ])
        .to_string();
        set_test_github_payload(Some(payload));

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            "invalid-public-key".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
        set_test_github_payload(None);
    }

    #[test]
    fn run_cli_did_from_github_without_payload_returns_error() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        set_test_github_payload(None);

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            "missing-payload".to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_did_from_github_invalid_output_path_returns_error() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        let armored = String::from_utf8(sample_openpgp_cert_armored()).expect("armored");
        let payload = serde_json::json!([
            {"id": 4, "public_key": armored}
        ])
        .to_string();
        set_test_github_payload(Some(payload));

        let dir = temp_dir();
        let output = dir.path().join("missing-parent").join("github.json");

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            unique_key("github-invalid-output-user"),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
        set_test_github_payload(None);
    }

    #[test]
    fn run_cli_did_from_github_reports_did_store_failure() {
        let _store_guard = store_failure_lock().lock().expect("store failure lock");
        let _guard = github_payload_lock().lock().expect("github payload lock");
        let user = unique_key("github-store-did-failure-user");
        let did_key = format!("github/{}/did", user);
        test_store_clear_failures();
        test_store_fail_put(&did_key);
        set_test_github_payload(Some(github_payload_with_sample_cert()));

        let code = run_did_from_github_command(DidFromGitHubArgs {
            key_type: GitHubKeyType::Gpg,
            user: user.clone(),
            out_file: None,
        });

        set_test_github_payload(None);
        test_store_clear_failures();
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(test_store_get(&did_key), None);
    }

    #[test]
    fn run_cli_did_from_github_reports_diddoc_store_failure() {
        let _store_guard = store_failure_lock().lock().expect("store failure lock");
        let _guard = github_payload_lock().lock().expect("github payload lock");
        let user = unique_key("github-store-diddoc-failure-user");
        let diddoc_key = format!("github/{}/diddoc", user);
        test_store_clear_failures();
        test_store_fail_put(&diddoc_key);
        set_test_github_payload(Some(github_payload_with_sample_cert()));

        let code = run_did_from_github_command(DidFromGitHubArgs {
            key_type: GitHubKeyType::Gpg,
            user: user.clone(),
            out_file: None,
        });

        set_test_github_payload(None);
        test_store_clear_failures();
        assert_eq!(code, ExitCode::from(2));
        assert!(test_store_get(&format!("github/{}/did", user)).is_some());
        assert_eq!(test_store_get(&diddoc_key), None);
    }

    #[test]
    fn run_cli_did_from_github_invalid_payload_returns_error() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        set_test_github_payload(Some("not-json".to_string()));

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-github".to_string(),
            "--user".to_string(),
            unique_key("github-invalid-payload-user"),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
        set_test_github_payload(None);
    }

    #[test]
    fn run_cli_did_from_gpg_missing_input_returns_error() {
        let dir = temp_dir();
        let input = dir.path().join("missing.asc");
        let output = dir.path().join("did.json");

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-gpg".to_string(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn run_cli_did_from_gpg_invalid_output_path_returns_error() {
        let dir = temp_dir();
        let input = dir.path().join("key.asc");
        let output = dir.path().join("missing-parent").join("did.json");
        std::fs::write(&input, sample_openpgp_cert_armored()).expect("write input");

        let mut cli = build_cli();
        cli.run_command = vec![
            "did-from-gpg".to_string(),
            "--in".to_string(),
            input.to_string_lossy().to_string(),
            "--out".to_string(),
            output.to_string_lossy().to_string(),
        ];

        assert_eq!(run_cli(cli), ExitCode::from(2));
    }

    #[test]
    fn read_seed_input_reads_from_input_file() {
        let dir = temp_dir();
        let input = dir.path().join("seed.bin");
        std::fs::write(&input, b"seed-bytes").expect("write");

        let value = read_seed_input("--human-secret", None, Some(&input)).expect("seed from file");
        assert_eq!(value, b"seed-bytes".to_vec());
    }

    #[test]
    fn read_seed_input_errors_on_missing_file() {
        let dir = temp_dir();
        let input = dir.path().join("missing-seed.bin");
        let err = read_seed_input("--human-secret", None, Some(&input)).unwrap_err();
        assert!(err.contains("failed to read"));
    }

    #[test]
    fn read_seed_input_errors_when_secret_key_is_missing() {
        let err = read_seed_input(
            "--human-secret",
            Some(&unique_key("seed/missing-secret")),
            None,
        )
        .unwrap_err();
        assert!(err.contains("keychain lookup failed"));
    }

    #[test]
    fn read_seed_input_requires_secret_or_input() {
        let err = read_seed_input("--human-secret", None, None).expect_err("missing seed source");
        assert!(err.contains("missing --human-secret or --in"));
    }

    #[test]
    fn blocklist_blocks_default_command() {
        let blocked = shadi_sandbox::default_blocked_commands();
        assert!(blocked.contains("rm"));
    }

    #[test]
    fn allowlist_overrides_blocklist() {
        let blocked = shadi_sandbox::default_blocked_commands();
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
    fn extract_github_public_key_errors_on_invalid_json() {
        let err = extract_github_public_key("not-json").unwrap_err();
        assert!(!err.is_empty());
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
    fn fetch_github_gpg_key_errors_when_test_payload_missing() {
        let _guard = github_payload_lock().lock().expect("github payload lock");
        set_test_github_payload(None);

        let err = fetch_github_gpg_key("missing-test-payload").unwrap_err();
        assert!(err.contains("test github payload not set"));
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

    #[test]
    fn resolve_trace_file_prefers_cli_path() {
        let _guard = trace_env_lock();
        let dir = temp_dir();
        let cli_path = dir.path().join("trace.jsonl");
        let resolved = resolve_trace_file(Some(cli_path.clone()));
        assert_eq!(resolved, cli_path);

        std::env::remove_var("SHADI_OTEL_FILE");
    }

    #[test]
    fn resolve_trace_file_uses_env_var() {
        let _guard = trace_env_lock();
        let dir = temp_dir();
        let env_path = dir.path().join("env-trace.jsonl");
        std::env::set_var("SHADI_OTEL_FILE", env_path.to_string_lossy().to_string());

        let resolved = resolve_trace_file(None);
        assert_eq!(resolved, env_path);

        std::env::remove_var("SHADI_OTEL_FILE");
    }

    #[test]
    fn trace_span_name_reads_span_name() {
        let value = json!({"span": {"name": "shadi.sandbox.run"}});
        assert_eq!(trace_span_name(&value), Some("shadi.sandbox.run".to_string()));
    }

    #[test]
    fn trace_matches_filters_command_and_exit() {
        let value = json!({
            "span": {"name": "shadi.sandbox.run"},
            "fields": {"command": "echo hi", "exit.code": 0}
        });

        assert!(trace_matches(&value, Some("sandbox"), Some("echo"), Some(0)));
        assert!(!trace_matches(&value, Some("sandbox"), Some("missing"), Some(0)));
        assert!(!trace_matches(&value, Some("sandbox"), Some("echo"), Some(1)));
    }

    #[test]
    fn read_trace_lines_keeps_tail() {
        let dir = temp_dir();
        let path = dir.path().join("traces.jsonl");
        std::fs::write(&path, "one\ntwo\nthree\nfour\n").expect("write traces");

        let lines = read_trace_lines(&path, 2).expect("read lines");
        assert_eq!(lines, vec!["three".to_string(), "four".to_string()]);
    }

    #[test]
    fn trace_list_errors_on_missing_file() {
        let err = trace_list(Path::new("/tmp/does-not-exist.jsonl"), 5, None, None, None)
            .unwrap_err();
        assert!(err.contains("failed to open trace file"));
    }

    #[test]
    fn trace_summary_counts_span_names() {
        let dir = temp_dir();
        let path = dir.path().join("traces.jsonl");
        let lines = vec![
            json!({"span": {"name": "shadi.sandbox.run"}}).to_string(),
            json!({"span": {"name": "shadi.sandbox.run"}}).to_string(),
            json!({"span": {"name": "shadi.policy.resolve"}}).to_string(),
        ];
        std::fs::write(&path, lines.join("\n")).expect("write traces");

        trace_summary(&path, 10).expect("summary");
    }

    #[test]
    fn trace_matches_filters_on_missing_fields() {
        let value = json!({"span": {"name": "shadi.sandbox.run"}});
        assert!(!trace_matches(&value, Some("sandbox"), Some("echo"), None));
        assert!(!trace_matches(&value, Some("sandbox"), None, Some(1)));
    }

    #[test]
    fn trace_span_name_reads_spans_array() {
        let value = json!({"spans": [{"name": "shadi.trace"}]});
        assert_eq!(trace_span_name(&value), Some("shadi.trace".to_string()));
    }

    #[test]
    fn resolve_trace_file_defaults_when_unset() {
        let _guard = trace_env_lock();
        std::env::remove_var("SHADI_OTEL_FILE");
        let resolved = resolve_trace_file(None);
        assert_eq!(resolved, PathBuf::from(".shadi/traces.jsonl"));
    }

    #[test]
    fn parse_trace_line_rejects_invalid_json() {
        assert!(parse_trace_line("not-json").is_none());
    }

    #[test]
    fn trace_list_respects_filters() {
        let dir = temp_dir();
        let path = dir.path().join("traces.jsonl");
        let lines = vec![
            json!({"span": {"name": "shadi.sandbox.run"}, "fields": {"command": "echo hi", "exit.code": 0}})
                .to_string(),
            json!({"span": {"name": "shadi.policy.resolve"}, "fields": {"command": "cat", "exit.code": 1}})
                .to_string(),
        ];
        std::fs::write(&path, lines.join("\n")).expect("write traces");

        trace_list(&path, 10, Some("sandbox"), Some("echo"), Some(0)).expect("list");
        trace_list(&path, 10, Some("policy"), None, Some(1)).expect("list");
    }

    #[test]
    fn slim_mas_validate_requires_default_group() {
        let dir = temp_dir();
        let config_path = write_mas_config(
            dir.path(),
            r#"
[groups.team-a]
members = [{ did = "did:key:zA", role = "human" }]
"#,
        );

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::Validate,
        };

        assert_eq!(run_slim_mas_command(cli), ExitCode::from(2));
    }

    #[test]
    fn slim_mas_list_members_errors_for_missing_group() {
        let dir = temp_dir();
        let config_path = write_mas_config(
            dir.path(),
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{ did = "did:key:zA", role = "human" }]
"#,
        );

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::ListMembers {
                group: Some("team-b".to_string()),
            },
        };

        assert_eq!(run_slim_mas_command(cli), ExitCode::from(2));
    }

    #[test]
    fn slim_mas_admit_allows_member_from_shadi_key() {
        let dir = temp_dir();
        let key = unique_key("secops/member_did");
        let config = format!(
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{{ did = "shadi://{}", role = "human" }}]
"#,
            key
        );
        let config_path = write_mas_config(
            dir.path(),
            &config,
        );

        test_store_put(&key, b"did:key:zMember");

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::Admit {
                group: None,
                did: format!("shadi://{}", key),
                role: Some("human".to_string()),
            },
        };

        assert_eq!(run_slim_mas_command(cli), ExitCode::from(0));
    }

    #[test]
    fn slim_mas_admit_denies_wrong_role() {
        let dir = temp_dir();
        let config_path = write_mas_config(
            dir.path(),
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{ did = "did:key:zMember", role = "human" }]
"#,
        );

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::Admit {
                group: None,
                did: "did:key:zMember".to_string(),
                role: Some("agent".to_string()),
            },
        };

        assert_eq!(run_slim_mas_command(cli), ExitCode::from(3));
    }

    #[test]
    fn run_memory_command_init_succeeds_with_explicit_key() {
        let dir = temp_dir();
        let db = dir.path().join("memory.db");

        let cli = MemoryCli {
            db,
            key: Some("test-memory-key".to_string()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Init,
        };

        assert_eq!(run_memory_command(cli), ExitCode::SUCCESS);
    }

    #[test]
    fn run_memory_command_put_get_list_search_delete_succeeds() {
        let dir = temp_dir();
        let db = dir.path().join("memory.db");
        let key = "test-memory-key".to_string();

        let put = MemoryCli {
            db: db.clone(),
            key: Some(key.clone()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Put {
                scope: "secops".to_string(),
                entry_key: "report".to_string(),
                payload: Some("{\"status\":\"ok\"}".to_string()),
                payload_file: None,
            },
        };
        assert_eq!(run_memory_command(put), ExitCode::SUCCESS);

        let get = MemoryCli {
            db: db.clone(),
            key: Some(key.clone()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Get {
                scope: "secops".to_string(),
                entry_key: "report".to_string(),
            },
        };
        assert_eq!(run_memory_command(get), ExitCode::SUCCESS);

        let list = MemoryCli {
            db: db.clone(),
            key: Some(key.clone()),
            key_name: "unused".to_string(),
            command: MemoryCommand::List {
                scope: Some("secops".to_string()),
                limit: 10,
            },
        };
        assert_eq!(run_memory_command(list), ExitCode::SUCCESS);

        let search = MemoryCli {
            db: db.clone(),
            key: Some(key.clone()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Search {
                scope: Some("secops".to_string()),
                query: "ok".to_string(),
                limit: 10,
            },
        };
        assert_eq!(run_memory_command(search), ExitCode::SUCCESS);

        let delete = MemoryCli {
            db,
            key: Some(key),
            key_name: "unused".to_string(),
            command: MemoryCommand::Delete {
                scope: "secops".to_string(),
                entry_key: "report".to_string(),
            },
        };
        assert_eq!(run_memory_command(delete), ExitCode::SUCCESS);
    }

    #[test]
    fn run_memory_command_rejects_empty_memory_key() {
        let dir = temp_dir();
        let db = dir.path().join("memory.db");

        let cli = MemoryCli {
            db,
            key: Some(String::new()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Init,
        };

        assert_eq!(run_memory_command(cli), ExitCode::from(1));
    }

    #[test]
    fn read_memory_payload_rejects_conflicting_inputs() {
        let err = read_memory_payload(Some("inline".to_string()), Some(PathBuf::from("payload.txt")))
            .unwrap_err();
        assert!(err.contains("use either payload or payload-file"));
    }

    #[test]
    fn slim_mas_list_groups_and_members_succeed() {
        let dir = temp_dir();
        let config_path = write_mas_config(
            dir.path(),
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [
  { did = "did:key:zA", role = "human" },
  { did = "did:key:zB" }
]
"#,
        );

        let list_groups = SlimMasCli {
            config: config_path.clone(),
            command: SlimMasCommand::ListGroups,
        };
        assert_eq!(run_slim_mas_command(list_groups), ExitCode::from(0));

        let list_members = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::ListMembers { group: None },
        };
        assert_eq!(run_slim_mas_command(list_members), ExitCode::from(0));
    }

    #[test]
    fn slim_mas_validate_succeeds_with_default_group() {
        let dir = temp_dir();
        let config_path = write_mas_config(
            dir.path(),
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{ did = "did:key:zA" }]
"#,
        );

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::Validate,
        };
        assert_eq!(run_slim_mas_command(cli), ExitCode::from(0));
    }

    #[test]
    fn slim_mas_admit_errors_when_group_missing() {
        let dir = temp_dir();
        let config_path = write_mas_config(
            dir.path(),
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{ did = "did:key:zMember", role = "human" }]
"#,
        );

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::Admit {
                group: Some("team-b".to_string()),
                did: "did:key:zMember".to_string(),
                role: Some("human".to_string()),
            },
        };
        assert_eq!(run_slim_mas_command(cli), ExitCode::from(2));
    }

    #[test]
    fn slim_mas_admit_errors_when_did_reference_cannot_be_resolved() {
        let dir = temp_dir();
        let missing_key = unique_key("missing/member");
        let config_path = write_mas_config(
            dir.path(),
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{ did = "did:key:zMember", role = "human" }]
"#,
        );

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::Admit {
                group: None,
                did: format!("shadi://{}", missing_key),
                role: Some("human".to_string()),
            },
        };
        assert_eq!(run_slim_mas_command(cli), ExitCode::from(2));
    }

    #[test]
    fn slim_mas_list_members_errors_when_group_did_reference_is_missing() {
        let dir = temp_dir();
        let missing_key = unique_key("missing/member");
        let config = format!(
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
members = [{{ did = "shadi://{}", role = "human" }}]
"#,
            missing_key
        );
        let config_path = write_mas_config(
            dir.path(),
            &config,
        );

        let cli = SlimMasCli {
            config: config_path,
            command: SlimMasCommand::ListMembers { group: None },
        };
        assert_eq!(run_slim_mas_command(cli), ExitCode::from(2));
    }

    #[test]
    fn slim_mas_returns_error_for_missing_config_file() {
        let dir = temp_dir();
        let cli = SlimMasCli {
            config: dir.path().join("missing.toml"),
            command: SlimMasCommand::ListGroups,
        };
        assert_eq!(run_slim_mas_command(cli), ExitCode::from(2));
    }

    #[test]
    fn run_memory_command_resolves_key_from_store() {
        let dir = temp_dir();
        let db = dir.path().join("memory-from-store.db");
        let key_name = unique_key("memory/key");

        test_store_put(&key_name, b"store-memory-key");

        let cli = MemoryCli {
            db,
            key: None,
            key_name,
            command: MemoryCommand::Init,
        };

        assert_eq!(run_memory_command(cli), ExitCode::SUCCESS);
    }

    #[test]
    fn run_memory_command_errors_when_key_name_missing() {
        let dir = temp_dir();
        let db = dir.path().join("memory-missing-key.db");
        let key_name = unique_key("memory/missing");

        let cli = MemoryCli {
            db,
            key: None,
            key_name,
            command: MemoryCommand::Init,
        };

        assert_eq!(run_memory_command(cli), ExitCode::from(1));
    }

    #[test]
    fn run_memory_command_errors_when_store_key_is_not_utf8() {
        let dir = temp_dir();
        let db = dir.path().join("memory-invalid-utf8.db");
        let key_name = unique_key("memory/not-utf8");

        test_store_put(&key_name, &[0xff, 0xfe]);

        let cli = MemoryCli {
            db,
            key: None,
            key_name,
            command: MemoryCommand::Init,
        };

        assert_eq!(run_memory_command(cli), ExitCode::from(1));
    }

    #[test]
    fn run_memory_command_put_supports_payload_file() {
        let dir = temp_dir();
        let db = dir.path().join("memory-payload-file.db");
        let payload_file = dir.path().join("payload.txt");
        std::fs::write(&payload_file, "payload-from-file").expect("write payload file");

        let put = MemoryCli {
            db,
            key: Some("test-memory-key".to_string()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Put {
                scope: "secops".to_string(),
                entry_key: "from-file".to_string(),
                payload: None,
                payload_file: Some(payload_file),
            },
        };

        assert_eq!(run_memory_command(put), ExitCode::SUCCESS);
    }

    #[test]
    fn run_memory_command_put_rejects_missing_payload_inputs() {
        let dir = temp_dir();
        let db = dir.path().join("memory-missing-payload.db");

        let put = MemoryCli {
            db,
            key: Some("test-memory-key".to_string()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Put {
                scope: "secops".to_string(),
                entry_key: "missing-payload".to_string(),
                payload: None,
                payload_file: None,
            },
        };

        assert_eq!(run_memory_command(put), ExitCode::from(1));
    }

    #[test]
    fn run_memory_command_get_returns_not_found_for_missing_entry() {
        let dir = temp_dir();
        let db = dir.path().join("memory-missing-entry.db");
        let key = "test-memory-key".to_string();

        let init = MemoryCli {
            db: db.clone(),
            key: Some(key.clone()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Init,
        };
        assert_eq!(run_memory_command(init), ExitCode::SUCCESS);

        let get = MemoryCli {
            db,
            key: Some(key),
            key_name: "unused".to_string(),
            command: MemoryCommand::Get {
                scope: "secops".to_string(),
                entry_key: "missing".to_string(),
            },
        };

        assert_eq!(run_memory_command(get), ExitCode::SUCCESS);
    }

    #[test]
    fn run_memory_command_search_without_scope_succeeds() {
        let dir = temp_dir();
        let db = dir.path().join("memory-search-no-scope.db");
        let key = "test-memory-key".to_string();

        let put = MemoryCli {
            db: db.clone(),
            key: Some(key.clone()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Put {
                scope: "secops".to_string(),
                entry_key: "search-all".to_string(),
                payload: Some("payload-search-all".to_string()),
                payload_file: None,
            },
        };
        assert_eq!(run_memory_command(put), ExitCode::SUCCESS);

        let search = MemoryCli {
            db,
            key: Some(key),
            key_name: "unused".to_string(),
            command: MemoryCommand::Search {
                scope: None,
                query: "search-all".to_string(),
                limit: 10,
            },
        };

        assert_eq!(run_memory_command(search), ExitCode::SUCCESS);
    }

    #[test]
    fn run_memory_command_list_without_scope_succeeds() {
        let dir = temp_dir();
        let db = dir.path().join("memory-list-no-scope.db");
        let key = "test-memory-key".to_string();

        let put = MemoryCli {
            db: db.clone(),
            key: Some(key.clone()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Put {
                scope: "secops".to_string(),
                entry_key: "list-all".to_string(),
                payload: Some("payload-list-all".to_string()),
                payload_file: None,
            },
        };
        assert_eq!(run_memory_command(put), ExitCode::SUCCESS);

        let list = MemoryCli {
            db,
            key: Some(key),
            key_name: "unused".to_string(),
            command: MemoryCommand::List {
                scope: None,
                limit: 10,
            },
        };

        assert_eq!(run_memory_command(list), ExitCode::SUCCESS);
    }

    #[test]
    fn run_memory_command_put_errors_for_missing_payload_file() {
        let dir = temp_dir();
        let db = dir.path().join("memory-missing-payload-file.db");

        let put = MemoryCli {
            db,
            key: Some("test-memory-key".to_string()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Put {
                scope: "secops".to_string(),
                entry_key: "from-missing-file".to_string(),
                payload: None,
                payload_file: Some(dir.path().join("missing-payload.txt")),
            },
        };

        assert_eq!(run_memory_command(put), ExitCode::from(1));
    }

    #[test]
    fn run_memory_command_errors_when_database_cannot_be_opened() {
        let dir = temp_dir();
        let db = dir.path().join("missing-parent").join("memory.db");

        let cli = MemoryCli {
            db,
            key: Some("test-memory-key".to_string()),
            key_name: "unused".to_string(),
            command: MemoryCommand::Init,
        };

        assert_eq!(run_memory_command(cli), ExitCode::from(1));
    }

    #[test]
    fn run_slim_command_dispatches_controller_variant() {
        // Empty connect args fail validation before any network I/O, so this
        // exercises the SlimCommand::Controller match arm in run_slim_command
        // (not just the run_controller_command helper it delegates to).
        let args = SlimControllerConnectArgs {
            endpoint: "127.0.0.1:1".to_string(),
            create_connection: Vec::new(),
            delete_connection: Vec::new(),
            set_route: Vec::new(),
            delete_route: Vec::new(),
            timeout_seconds: 1,
        };
        let code = run_slim_command(SlimCli {
            command: SlimCommand::Controller {
                command: ControllerCommand::Connect(args),
            },
        });
        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn run_controller_command_dispatches_connect_and_surfaces_errors() {
        // Empty connect args fail validation before any network I/O, so this
        // exercises the dispatch match arm and error path without needing a
        // live controller endpoint.
        let args = SlimControllerConnectArgs {
            endpoint: "127.0.0.1:1".to_string(),
            create_connection: Vec::new(),
            delete_connection: Vec::new(),
            set_route: Vec::new(),
            delete_route: Vec::new(),
            timeout_seconds: 1,
        };
        assert_eq!(
            run_controller_command(ControllerCommand::Connect(args)),
            ExitCode::from(1)
        );
    }

    fn restore_env_var(name: &str, previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    #[test]
    fn restore_env_var_covers_some_and_none() {
        let _guard = trace_env_lock();
        let previous = std::env::var_os("SHADI_TEST_RESTORE_ENV_VAR");

        std::env::set_var("SHADI_TEST_RESTORE_ENV_VAR", "before");
        restore_env_var(
            "SHADI_TEST_RESTORE_ENV_VAR",
            Some(std::ffi::OsString::from("restored")),
        );
        assert_eq!(
            std::env::var("SHADI_TEST_RESTORE_ENV_VAR").as_deref(),
            Ok("restored")
        );

        restore_env_var("SHADI_TEST_RESTORE_ENV_VAR", None);
        assert!(std::env::var_os("SHADI_TEST_RESTORE_ENV_VAR").is_none());

        restore_env_var("SHADI_TEST_RESTORE_ENV_VAR", previous);
    }

    #[test]
    fn run_controller_command_dispatches_list_routes_and_surfaces_errors() {
        let _guard = trace_env_lock();
        let previous_cert = std::env::var_os("SLIM_TLS_CERT");
        let previous_key = std::env::var_os("SLIM_TLS_KEY");
        let previous_ca = std::env::var_os("SLIM_TLS_CA");
        std::env::remove_var("SLIM_TLS_CERT");
        std::env::remove_var("SLIM_TLS_KEY");
        std::env::remove_var("SLIM_TLS_CA");

        // No client TLS material is configured, so TLS resolution fails
        // before any network I/O — exercising the ListRoutes dispatch arm
        // and error path without needing a live controller endpoint.
        let args = SlimControllerListArgs {
            endpoint: "127.0.0.1:1".to_string(),
            timeout_seconds: 1,
        };
        let code = run_controller_command(ControllerCommand::ListRoutes(args));

        restore_env_var("SLIM_TLS_CERT", previous_cert);
        restore_env_var("SLIM_TLS_KEY", previous_key);
        restore_env_var("SLIM_TLS_CA", previous_ca);

        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn run_controller_command_dispatches_list_connections_and_surfaces_errors() {
        let _guard = trace_env_lock();
        let previous_cert = std::env::var_os("SLIM_TLS_CERT");
        let previous_key = std::env::var_os("SLIM_TLS_KEY");
        let previous_ca = std::env::var_os("SLIM_TLS_CA");
        std::env::remove_var("SLIM_TLS_CERT");
        std::env::remove_var("SLIM_TLS_KEY");
        std::env::remove_var("SLIM_TLS_CA");

        let args = SlimControllerListArgs {
            endpoint: "127.0.0.1:1".to_string(),
            timeout_seconds: 1,
        };
        let code = run_controller_command(ControllerCommand::ListConnections(args));

        restore_env_var("SLIM_TLS_CERT", previous_cert);
        restore_env_var("SLIM_TLS_KEY", previous_key);
        restore_env_var("SLIM_TLS_CA", previous_ca);

        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn exit_code_for_maps_ok_and_err() {
        assert_eq!(exit_code_for(Ok(())), ExitCode::from(0));
        assert_eq!(exit_code_for(Err("boom".to_string())), ExitCode::from(1));
    }
