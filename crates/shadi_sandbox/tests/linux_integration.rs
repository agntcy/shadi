// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(target_os = "linux", not(feature = "coverage")))]
mod linux_integration {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use shadi_sandbox::{spawn_sandboxed, SandboxPolicy};

    fn unique_test_root() -> PathBuf {
        // The tests run in parallel and the clock can read the same for both
        // (macOS ticks in microseconds), so a counter keeps each root apart.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::current_dir()
            .expect("current dir")
            .join(".tmp")
            .join(format!("linux-sandbox-test-{}-{suffix}-{n}", std::process::id()))
    }

    fn compile_helper(dir: &Path, name: &str) -> PathBuf {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_support")
            .join(format!("{name}.rs"));
        let binary = dir.join(name);

        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let output = Command::new(rustc)
            .arg("--edition=2021")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .stderr(Stdio::piped())
            .output()
            .expect("compile checked-in helper");
        assert!(
            output.status.success(),
            "failed to compile helper {}: {}",
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
        let helper = compile_helper(&allowed_dir, "read_stdout_helper");

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

    #[test]
    fn a_network_blocking_sandbox_refuses_the_confinement_probe() {
        let root = unique_test_root();
        fs::create_dir_all(&root).expect("create test root");
        let probe = compile_helper(&root, "confinement_probe_helper");

        let outside = Command::new(&probe)
            .status()
            .expect("run probe outside the sandbox");

        let policy = SandboxPolicy::new()
            .allow_read_path(&root)
            .block_network(true);
        let mut command = Command::new(&probe);
        let mut child = spawn_sandboxed(&mut command, &policy).expect("spawn probe");
        let inside = child.wait().expect("wait for probe");

        let _ = fs::remove_dir_all(&root);
        assert!(
            !outside.success(),
            "outside a sandbox the kernel should not refuse the probe"
        );
        assert!(
            inside.success(),
            "a network-blocking sandbox must refuse the probe with a permission error"
        );
    }
}
