// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(target_os = "macos", not(feature = "coverage")))]
mod macos_integration {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    use shadi_sandbox::{spawn_sandboxed, SandboxPolicy};

    fn unique_test_root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::current_dir()
            .expect("current dir")
            .join(".tmp")
            .join(format!("macos-sandbox-test-{}-{}", std::process::id(), suffix))
    }

    fn compile_read_stdout_helper(dir: &Path) -> PathBuf {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_support/read_stdout_helper.rs");
        let binary = dir.join("read-stdout-helper");

        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let output = Command::new(rustc)
            .arg("--edition=2021")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .stderr(Stdio::piped())
            .output()
            .expect("compile checked-in stdout helper");
        assert!(
            output.status.success(),
            "failed to compile stdout helper {}: {}",
            source.display(),
            String::from_utf8_lossy(&output.stderr)
        );

        binary
    }

    #[test]
    fn minimal_profile_blocks_disallowed_user_file_reads() {
        let root = unique_test_root();
        let allowed_dir = root.join("allowed");
        let synthetic_home = root.join("home");
        let disallowed_dir = synthetic_home.join("Library");
        let baseline_output = allowed_dir.join("baseline.txt");
        let minimal_output = allowed_dir.join("minimal.txt");

        fs::create_dir_all(&allowed_dir).expect("create allowed dir");
        fs::create_dir_all(&disallowed_dir).expect("create disallowed dir");

        let disallowed_file = disallowed_dir.join("secret.txt");
        fs::write(&disallowed_file, b"top-secret").expect("write disallowed file");
        let helper = compile_read_stdout_helper(&allowed_dir);

        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &synthetic_home);

        let minimal_policy = SandboxPolicy::new()
            .use_minimal_platform_profile()
            .allow_read_path(&allowed_dir)
            .allow_write_path(&allowed_dir)
            .block_network(true);

        let baseline_stdout = fs::File::create(&baseline_output).expect("create baseline output");
        let baseline_status = Command::new(&helper)
            .arg(&disallowed_file)
            .current_dir(&allowed_dir)
            .stdout(Stdio::from(baseline_stdout))
            .stderr(Stdio::null())
            .status()
            .expect("run baseline helper");

        let minimal_stdout = fs::File::create(&minimal_output).expect("create minimal output");
        let mut minimal_command = Command::new(&helper);
        minimal_command.arg(&disallowed_file);
        minimal_command.current_dir(&allowed_dir);
        minimal_command.stdout(Stdio::from(minimal_stdout));
        minimal_command.stderr(Stdio::null());

        let mut minimal_child = spawn_sandboxed(&mut minimal_command, &minimal_policy)
            .expect("spawn minimal helper");
        let minimal_status = minimal_child.wait().expect("wait for minimal helper");

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }

        assert!(baseline_status.success(), "baseline helper should read the file outside the sandbox");
        assert_eq!(fs::read(&baseline_output).expect("read baseline output"), b"top-secret");

        assert!(!minimal_status.success(), "minimal profile should block the user Library read");
        assert!(fs::read(&minimal_output).expect("read minimal output").is_empty());

        let _ = fs::remove_dir_all(&root);
    }
}