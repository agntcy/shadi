// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(target_os = "linux", not(feature = "coverage")))]
mod linux_integration {
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
            .join(format!("linux-sandbox-test-{}-{}", std::process::id(), suffix))
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
    fn landlock_blocks_disallowed_file_reads() {
        let root = unique_test_root();
        let allowed_dir = root.join("allowed");
        let disallowed_dir = root.join("disallowed");
        let baseline_output = allowed_dir.join("baseline.txt");
        let sandbox_output = allowed_dir.join("sandbox.txt");

        fs::create_dir_all(&allowed_dir).expect("create allowed dir");
        fs::create_dir_all(&disallowed_dir).expect("create disallowed dir");

        let disallowed_file = disallowed_dir.join("secret.txt");
        fs::write(&disallowed_file, b"top-secret").expect("write disallowed file");
        let helper = compile_read_stdout_helper(&allowed_dir);

        // Baseline: reading the file without sandbox should succeed.
        let baseline_stdout =
            fs::File::create(&baseline_output).expect("create baseline output");
        let baseline_status = Command::new(&helper)
            .arg(&disallowed_file)
            .current_dir(&allowed_dir)
            .stdout(Stdio::from(baseline_stdout))
            .stderr(Stdio::null())
            .status()
            .expect("run baseline helper");

        assert!(
            baseline_status.success(),
            "baseline helper should read the file outside the sandbox"
        );
        assert_eq!(
            fs::read(&baseline_output).expect("read baseline output"),
            b"top-secret"
        );

        // Sandboxed: only allow_read on `allowed_dir` — disallowed_dir should
        // be blocked by Landlock.
        let policy = SandboxPolicy::new()
            .use_minimal_platform_profile()
            .allow_read_path(&allowed_dir)
            .allow_write_path(&allowed_dir)
            .block_network(true);

        let sandbox_stdout =
            fs::File::create(&sandbox_output).expect("create sandbox output");
        let mut sandbox_command = Command::new(&helper);
        sandbox_command.arg(&disallowed_file);
        sandbox_command.current_dir(&allowed_dir);
        sandbox_command.stdout(Stdio::from(sandbox_stdout));
        sandbox_command.stderr(Stdio::null());

        let mut sandbox_child =
            spawn_sandboxed(&mut sandbox_command, &policy).expect("spawn sandboxed helper");
        let sandbox_status = sandbox_child.wait().expect("wait for sandboxed helper");

        // The sandboxed process should fail because it cannot read the disallowed path.
        assert!(
            !sandbox_status.success(),
            "sandboxed helper should fail when reading a disallowed path"
        );

        // Clean up.
        let _ = fs::remove_dir_all(&root);
    }
}
