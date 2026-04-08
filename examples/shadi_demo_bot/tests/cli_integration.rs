use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

fn demo_bot_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_shadi_demo_bot") {
        return PathBuf::from(path);
    }

    let mut path = std::env::current_exe().expect("resolve integration test executable path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push(format!("shadi_demo_bot{}", std::env::consts::EXE_SUFFIX));
    path
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        stdout_text(output),
        stderr_text(output)
    );
}

fn assert_feature_bot_runtime_expectations(output: &Output, expect_slim: bool) {
    let stdout = stdout_text(output);
    let stderr = stderr_text(output);
    let macos_coverage_stubbed_sandbox =
        cfg!(target_os = "macos") && std::env::var_os("LLVM_PROFILE_FILE").is_some();

    if macos_coverage_stubbed_sandbox {
        assert!(
            !output.status.success(),
            "expected macOS coverage-mode sandbox checks to fail, stdout:\n{}\n\nstderr:\n{}",
            stdout,
            stderr
        );
        assert!(stdout.contains("[FAIL] sandbox blocked read"), "{stdout}");
        assert!(stdout.contains("[FAIL] sandbox blocked network"), "{stdout}");
        assert!(
            stderr.contains("error: one or more SHADI feature checks failed"),
            "stdout:\n{stdout}\n\nstderr:\n{stderr}"
        );
    } else {
        assert_success(output);
        assert!(!stdout.contains("[FAIL]"), "{stdout}");
    }

    assert!(stdout.contains("[PASS] session-gated secrets"), "{stdout}");
    assert!(stdout.contains("[PASS] encrypted memory"), "{stdout}");
    assert!(stdout.contains("[shadi-demo-bot] summary:"), "{stdout}");
    if expect_slim {
        assert!(stdout.contains("[PASS] SLIM messaging"), "{stdout}");
    } else {
        assert!(stdout.contains("[SKIP] SLIM messaging"), "{stdout}");
    }
}

#[test]
fn feature_bot_no_slim_succeeds_with_existing_memory_db() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let work_dir = temp_dir.path().join("demo-work");
    fs::create_dir_all(&work_dir).expect("create work dir");

    let memory_db = work_dir.join("memory.db");
    fs::write(&memory_db, b"stale database placeholder").expect("seed memory db");

    let output = Command::new(demo_bot_binary())
        .arg("feature-bot")
        .arg("--shadi-tmp-dir")
        .arg(&work_dir)
        .arg("--memory-db")
        .arg(&memory_db)
        .arg("--slim-endpoint")
        .arg("127.0.0.1:4444")
        .arg("--slim-timeout-seconds")
        .arg("5")
        .arg("--no-slim")
        .output()
        .expect("run feature-bot --no-slim");

    assert_feature_bot_runtime_expectations(&output, false);
    assert!(memory_db.exists(), "expected memory db to be recreated");
}

#[cfg(unix)]
#[test]
fn default_command_runs_full_feature_bot_flow() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let work_dir = temp_dir.path().join("demo-work");
    fs::create_dir_all(&work_dir).expect("create work dir");

    let output = Command::new(demo_bot_binary())
        .env("SHADI_TMP_DIR", &work_dir)
        .output()
        .expect("run default feature-bot command");

    assert_feature_bot_runtime_expectations(&output, true);
}

#[test]
fn feature_bot_surfaces_memory_path_errors() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let work_dir = temp_dir.path().join("demo-work");
    fs::create_dir_all(&work_dir).expect("create work dir");

    let bad_parent = temp_dir.path().join("not-a-directory");
    fs::write(&bad_parent, b"file").expect("create blocking file");
    let bad_memory_db = bad_parent.join("memory.db");

    let output = Command::new(demo_bot_binary())
        .arg("feature-bot")
        .arg("--shadi-tmp-dir")
        .arg(&work_dir)
        .arg("--memory-db")
        .arg(&bad_memory_db)
        .arg("--slim-timeout-seconds")
        .arg("5")
        .arg("--no-slim")
        .output()
        .expect("run feature-bot with invalid memory path");

    assert!(
        !output.status.success(),
        "expected failure, stdout:\n{}\n\nstderr:\n{}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let stdout = stdout_text(&output);
    let stderr = stderr_text(&output);
    assert!(stdout.contains("[FAIL] encrypted memory"), "{stdout}");
    assert!(
        stderr.contains("error: one or more SHADI feature checks failed"),
        "stdout:\n{stdout}\n\nstderr:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn shell_ticker_handles_sigterm() {
    let child = Command::new(demo_bot_binary())
        .arg("shell-ticker")
        .arg("--tick-seconds")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shell ticker");

    thread::sleep(Duration::from_millis(750));

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM to shell ticker");
    assert!(status.success(), "failed to send SIGTERM");

    let output = child.wait_with_output().expect("wait for shell ticker output");
    assert_success(&output);

    let stdout = stdout_text(&output);
    assert!(stdout.contains("[demo-agent] starting"), "{stdout}");
    assert!(stdout.contains("[demo-agent] tick"), "{stdout}");
    assert!(stdout.contains("[demo-agent] shutting down"), "{stdout}");
}