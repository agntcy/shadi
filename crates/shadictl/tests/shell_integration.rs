// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `shadictl shell` — verifies actual stdout/stderr
//! output by piping commands to the compiled binary.
//!
//! Tests in the "attached session" section spin up a mock sandbox control
//! socket so the shell can attach and exercise policy query / patch commands
//! against a live endpoint.
//!
//! These tests require Unix domain sockets and are skipped on Windows.
#![cfg(unix)]

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use shadi_sandbox::{
    ControlMessage, ControlResponse, PatchAxisStatus, PolicyPatch, PolicyPatchResponse,
};

// ── mock sandbox ─────────────────────────────────────────────

/// Minimal mutable state for the mock sandbox.
struct MockState {
    blocked: HashSet<String>,
    allow: HashSet<String>,
    staged_read: Vec<String>,
    staged_net_allow: Vec<String>,
    terminated: bool,
}

/// A mock sandbox that listens on a Unix socket and responds to the SHADI
/// control protocol.  Drop it to shut down.
struct MockSandbox {
    sock_path: PathBuf,
    state: Arc<Mutex<MockState>>,
    _thread: thread::JoinHandle<()>,
}

impl MockSandbox {
    fn start(dir: &Path) -> Self {
        let sock_path = dir.join("mock-sandbox.sock");
        let _ = std::fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path).expect("bind mock socket");
        listener.set_nonblocking(true).expect("set nonblocking");

        let path_clone = sock_path.clone();
        let state = Arc::new(Mutex::new(MockState {
            blocked: ["rm", "sudo"].iter().map(|s| s.to_string()).collect(),
            allow: HashSet::new(),
            staged_read: Vec::new(),
            staged_net_allow: Vec::new(),
            terminated: false,
        }));

        let state_for_thread = Arc::clone(&state);
        let handle = thread::spawn(move || {
            mock_accept_loop(&listener, &state_for_thread, &path_clone);
        });

        // Wait until the socket can complete a real request/response round-trip.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut ready = false;
        while std::time::Instant::now() < deadline {
            if sock_path.exists() && probe_mock_socket(&sock_path).is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(ready, "mock sandbox socket did not become ready in time");

        MockSandbox {
            sock_path,
            state,
            _thread: handle,
        }
    }

    fn socket_path(&self) -> &str {
        self.sock_path.to_str().expect("socket path is utf-8")
    }

    fn terminated(&self) -> bool {
        self.state.lock().expect("lock state").terminated
    }
}

impl Drop for MockSandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.sock_path);
    }
}

fn mock_accept_loop(listener: &UnixListener, state: &Arc<Mutex<MockState>>, sock_path: &Path) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("set blocking mock stream");
                // Spawn a thread per connection so the listener is never
                // blocked while handling a client; this prevents the race
                // where a short-lived probe connect holds the accept loop
                // while the real shell attach arrives.
                let state_clone = Arc::clone(state);
                thread::spawn(move || mock_handle_stream(stream, &state_clone));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
                if !sock_path.exists() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn mock_handle_stream(
    stream: std::os::unix::net::UnixStream,
    state: &Arc<Mutex<MockState>>,
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }

        if line.trim().is_empty() {
            continue;
        }

        let msg: ControlMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                let resp = ControlResponse::Error {
                    message: format!("invalid message: {}", e),
                };
                let _ = write_mock_response(reader.get_mut(), &resp);
                continue;
            }
        };

        let resp = match msg {
            ControlMessage::QueryPolicy => mock_query(state),
            ControlMessage::Patch(patch) => mock_patch(state, patch),
            ControlMessage::Terminate => mock_terminate(state),
            ControlMessage::QueryResources => ControlResponse::Resources(
                shadi_sandbox::ProcessResources {
                    pid: std::process::id(),
                    rss_bytes: Some(1024 * 1024),
                    virtual_bytes: Some(128 * 1024 * 1024),
                    cpu_user_ms: Some(100),
                    cpu_system_ms: Some(50),
                    thread_count: Some(2),
                },
            ),
        };

        if write_mock_response(reader.get_mut(), &resp).is_err() {
            break;
        }
    }
}

fn write_mock_response(
    writer: &mut impl Write,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    let json = serde_json::to_string(resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn probe_mock_socket(sock_path: &Path) -> std::io::Result<()> {
    let mut stream = std::os::unix::net::UnixStream::connect(sock_path)?;
    let message = serde_json::to_string(&ControlMessage::QueryPolicy)
        .map_err(std::io::Error::other)?;
    stream.write_all(message.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "mock sandbox probe received empty response",
        ));
    }

    let _response: ControlResponse = serde_json::from_str(&line).map_err(std::io::Error::other)?;
    Ok(())
}

fn mock_query(state: &Arc<Mutex<MockState>>) -> ControlResponse {
    let guard = state.lock().unwrap();
    let policy = serde_json::json!({
        "allow_read": ["/usr/local/bin"],
        "allow_write": ["/tmp"],
        "net_blocked": true,
        "allow_command": guard.allow.iter().cloned().collect::<Vec<_>>(),
        "block_command": guard.blocked.iter().cloned().collect::<Vec<_>>(),
        "staged_read": guard.staged_read,
        "staged_net_allow": guard.staged_net_allow,
    });
    ControlResponse::Policy { policy }
}

fn mock_patch(state: &Arc<Mutex<MockState>>, patch: PolicyPatch) -> ControlResponse {
    let mut guard = state.lock().unwrap();

    let mut cmd_status = PatchAxisStatus::Unchanged;
    let mut fs_status = PatchAxisStatus::Unchanged;
    let mut net_status = PatchAxisStatus::Unchanged;
    let mut pending_restart = Vec::new();

    let has_cmd = !patch.add_allow_command.is_empty()
        || !patch.remove_allow_command.is_empty()
        || !patch.add_block_command.is_empty()
        || !patch.remove_block_command.is_empty();

    if has_cmd {
        for cmd in &patch.add_allow_command {
            guard.allow.insert(cmd.clone());
        }
        for cmd in &patch.remove_allow_command {
            guard.allow.remove(cmd);
        }
        for cmd in &patch.add_block_command {
            guard.blocked.insert(cmd.clone());
        }
        for cmd in &patch.remove_block_command {
            guard.blocked.remove(cmd);
        }
        cmd_status = PatchAxisStatus::Applied;
    }

    if !patch.add_read.is_empty() || !patch.add_write.is_empty() || !patch.add_allow.is_empty() {
        guard.staged_read.extend(patch.add_read);
        fs_status = PatchAxisStatus::PendingRestart;
        pending_restart.push("filesystem".to_string());
    }

    if !patch.add_net_allow.is_empty() || !patch.remove_net_allow.is_empty() {
        for dest in &patch.add_net_allow {
            if !guard.staged_net_allow.contains(dest) {
                guard.staged_net_allow.push(dest.clone());
            }
        }
        for dest in &patch.remove_net_allow {
            guard.staged_net_allow.retain(|d| d != dest);
        }
        net_status = PatchAxisStatus::PendingRestart;
        pending_restart.push("network".to_string());
    }

    let message = if pending_restart.is_empty() {
        "patch applied".to_string()
    } else {
        format!(
            "patch accepted; restarting sandboxed process to apply {}",
            pending_restart.join(", ")
        )
    };

    ControlResponse::PatchResult(PolicyPatchResponse {
        accepted: true,
        filesystem: fs_status,
        commands: cmd_status,
        network: net_status,
        message,
        pending_restart,
    })
}

fn mock_terminate(state: &Arc<Mutex<MockState>>) -> ControlResponse {
    let mut guard = state.lock().unwrap();
    guard.terminated = true;
    ControlResponse::Ack {
        message: "termination requested".to_string(),
    }
}

fn run_shell(input: &str) -> ShellOutput {
    run_shell_with_env(input, &[], &[])
}

fn run_shell_with_args(input: &str, extra_args: &[&str]) -> ShellOutput {
    run_shell_with_env(input, extra_args, &[])
}

fn run_shell_with_env(
    input: &str,
    extra_args: &[&str],
    env_vars: &[(&str, &str)],
) -> ShellOutput {
    // These tests drive the compiled shell through piped stdin while also
    // standing up per-test Unix socket servers. Running multiple shell
    // subprocesses in parallel is flaky on macOS CI, so keep the harness
    // single-file deterministic.
    static SHELL_SUBPROCESS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = SHELL_SUBPROCESS_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("lock shell integration subprocesses");

    let bin = env!("CARGO_BIN_EXE_shadictl");
    let mut cmd = Command::new(bin);
    cmd.arg("shell");
    for arg in extra_args {
        cmd.arg(arg);
    }
    for (key, val) in env_vars {
        cmd.env(key, val);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch shadictl shell");

    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("child stdin available");
        stdin.write_all(input.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    let output = child.wait_with_output().expect("failed to wait on shadictl");
    ShellOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        success: output.status.success(),
    }
}

struct ShellOutput {
    stdout: String,
    stderr: String,
    success: bool,
}

impl ShellOutput {
    fn stdout_contains(&self, needle: &str) -> &Self {
        assert!(
            self.stdout.contains(needle),
            "expected stdout to contain {needle:?}, got stdout:\n{}\n--- stderr ---\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    fn stderr_contains(&self, needle: &str) -> &Self {
        assert!(
            self.stderr.contains(needle),
            "expected stderr to contain {needle:?}, got:\n{}",
            self.stderr
        );
        self
    }

    fn assert_success(&self) -> &Self {
        assert!(
            self.success,
            "expected exit code 0, got stdout:\n{}\n--- stderr ---\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    fn stderr_is_empty(&self) -> &Self {
        assert!(
            self.stderr.is_empty(),
            "expected stderr to be empty, got:\n{}",
            self.stderr
        );
        self
    }
}

/// Create a mock OTEL traces.jsonl file with realistic entries.
fn write_mock_traces(dir: &Path) -> PathBuf {
    let path = dir.join("traces.jsonl");
    let traces = r#"{"span":{"name":"shadi.sandbox.spawn","attributes":{"command":"python agent.py"}},"exit_code":0}
{"span":{"name":"shadi.policy.patch","attributes":{"patch.add_commands":1}},"exit_code":0}
{"span":{"name":"shadi.sandbox.spawn","attributes":{"command":"node index.js"}},"exit_code":1}
{"span":{"name":"shadi.secret.deliver","attributes":{"secret_count":2}},"exit_code":0}
{"span":{"name":"shadi.sandbox.spawn","attributes":{"command":"cargo build"}},"exit_code":0}
"#;
    std::fs::write(&path, traces).expect("write mock traces");
    path
}

// ── navigation ───────────────────────────────────────────────

#[test]
fn given_shell_when_help_then_output_lists_all_commands() {
    run_shell("/help\n/exit\n")
        .assert_success()
        .stdout_contains("SHADI interactive shell commands")
        .stdout_contains("/help")
        .stdout_contains("/policy query")
        .stdout_contains("/trace list")
        .stdout_contains("/sessions")
        .stdout_contains("/config");
}

#[test]
fn given_shell_when_unknown_command_then_stderr_shows_hint() {
    run_shell("/bogus\n/exit\n")
        .assert_success()
        .stderr_contains("unknown command")
        .stderr_contains("/help");
}

#[test]
fn given_shell_when_exit_then_exits_cleanly() {
    run_shell("/exit\n").assert_success();
}

// ── session management ───────────────────────────────────────

#[test]
fn given_shell_when_status_not_attached_then_shows_not_attached() {
    run_shell("/status\n/exit\n")
        .assert_success()
        .stdout_contains("not attached");
}

#[test]
fn given_shell_when_detach_not_attached_then_shows_not_attached() {
    run_shell("/detach\n/exit\n")
        .assert_success()
        .stdout_contains("not attached");
}

#[test]
fn given_shell_when_attach_nonexistent_then_stderr_shows_error() {
    run_shell("/attach /tmp/nonexistent-shadi-bdd.sock\n/exit\n")
        .assert_success()
        .stderr_contains("session not found");
}

#[test]
fn given_shell_when_attach_nonexistent_name_then_stderr_shows_error() {
    // Named session that doesn't exist should also surface a friendly message.
    run_shell("/attach no-such-session-bdd\n/exit\n")
        .assert_success()
        .stderr_contains("session not found");
}

#[test]
fn given_shell_when_attach_no_path_then_stderr_shows_usage() {
    run_shell("/attach\n/exit\n")
        .assert_success()
        .stderr_contains("usage: /attach");
}

// ── config & policy ──────────────────────────────────────────

#[test]
fn given_shell_when_config_then_output_contains_effective_policy() {
    run_shell("/config\n/exit\n")
        .assert_success()
        .stdout_contains("effective_policy")
        .stdout_contains("profile");
}

#[test]
fn given_shell_when_policy_explain_then_output_contains_sources() {
    run_shell("/policy explain\n/exit\n")
        .assert_success()
        .stdout_contains("effective_policy")
        .stdout_contains("sources");
}

#[test]
fn given_shell_when_policy_query_not_attached_then_stderr_shows_error() {
    run_shell("/policy query\n/exit\n")
        .assert_success()
        .stderr_contains("not attached");
}

#[test]
fn given_shell_when_bare_policy_then_stderr_shows_usage() {
    run_shell("/policy\n/exit\n")
        .assert_success()
        .stderr_contains("usage: /policy");
}

#[test]
fn given_shell_when_policy_diff_no_baseline_then_stderr_shows_usage() {
    run_shell("/policy diff\n/exit\n")
        .assert_success()
        .stderr_contains("usage: /policy diff");
}

// ── trace ────────────────────────────────────────────────────

#[test]
fn given_shell_when_trace_list_no_file_then_stderr_shows_error() {
    run_shell("/trace list\n/exit\n")
        .assert_success()
        .stderr_contains("traces.jsonl");
}

#[test]
fn given_shell_when_bare_trace_then_stderr_shows_usage() {
    run_shell("/trace\n/exit\n")
        .assert_success()
        .stderr_contains("usage: /trace");
}

// ── full walkthrough (detached) ──────────────────────────────

#[test]
fn given_shell_when_full_walkthrough_then_output_covers_all_commands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trace_file = write_mock_traces(dir.path());

    let out = run_shell_with_env(
        "/help\n\
         /status\n\
         /sessions\n\
         /config\n\
         /policy explain\n\
         /policy diff profile:strict\n\
         /trace list\n\
         /trace summary\n\
         /secrets backend\n\
         /secrets rules\n\
         /detach\n\
         /clear\n\
         /exit\n",
        &[],
        &[("SHADI_OTEL_FILE", trace_file.to_str().unwrap())],
    );

    out.assert_success()
        .stderr_is_empty()
        .stdout_contains("SHADI interactive shell commands")
        .stdout_contains("not attached")
        .stdout_contains("effective_policy")
        .stdout_contains("sources")
        .stdout_contains("shadi.sandbox.spawn")
        .stdout_contains("shadi.policy.patch")
        .stdout_contains("Backend:");
}

// ── attached session (mock sandbox) ──────────────────────────

#[test]
fn given_mock_sandbox_when_attach_then_shows_attached() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let input = format!("/attach {}\n/status\n/exit\n", mock.socket_path());
    let out = run_shell(&input);

    out.assert_success()
        .stdout_contains("attached to")
        .stdout_contains("connected");
}

#[test]
fn given_attached_session_when_policy_query_then_shows_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let input = format!(
        "/attach {}\n/policy query\n/exit\n",
        mock.socket_path()
    );
    let out = run_shell(&input);

    out.assert_success()
        .stdout_contains("allow_read")
        .stdout_contains("block_command")
        .stdout_contains("net_blocked");
}

#[test]
fn given_attached_session_when_policy_patch_command_then_shows_applied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let input = format!(
        "/attach {}\n/policy patch --force --add-allow-command npm\n/exit\n",
        mock.socket_path()
    );
    let out = run_shell(&input);

    out.assert_success()
        .stdout_contains("\"accepted\": true")
        .stdout_contains("\"applied\"");
}

#[test]
fn given_attached_session_when_policy_patch_fs_then_shows_pending_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let input = format!(
        "/attach {}\n/policy patch --force --add-read /opt/data\n/exit\n",
        mock.socket_path()
    );
    let out = run_shell(&input);

    out.assert_success()
        .stdout_contains("\"accepted\": true")
        .stdout_contains("pending_restart")
        .stdout_contains("filesystem");
}

#[test]
fn given_attached_session_when_policy_patch_net_then_shows_pending_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let input = format!(
        "/attach {}\n/policy patch --force --add-net-allow api.github.com\n/exit\n",
        mock.socket_path()
    );
    let out = run_shell(&input);

    out.assert_success()
        .stdout_contains("\"accepted\": true")
        .stdout_contains("pending_restart")
        .stdout_contains("network");
}

#[test]
fn given_attached_session_when_detach_then_status_shows_not_attached() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let out = run_shell_with_args(
        "/detach\n/status\n/exit\n",
        &["--socket", mock.socket_path()],
    );

    out.assert_success()
        .stdout_contains("detached")
        .stdout_contains("not attached");
}

#[test]
fn given_attached_session_when_kill_then_termination_is_requested() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let out = run_shell_with_args("/kill\n/exit\n", &["--socket", mock.socket_path()]);

    out.assert_success().stdout_contains("termination requested");
    assert!(mock.terminated(), "expected terminate request to reach mock sandbox");
}

#[test]
fn given_socket_arg_when_shell_starts_then_pre_attached() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());

    let out = run_shell_with_args(
        "/status\n/policy query\n/exit\n",
        &["--socket", mock.socket_path()],
    );

    out.assert_success()
        .stdout_contains("attached")
        .stdout_contains("allow_read");
}

#[test]
fn given_attached_session_when_full_walkthrough_then_all_operations_succeed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mock = MockSandbox::start(dir.path());
    let trace_file = write_mock_traces(dir.path());

    let input = format!(
        "/help\n\
         /status\n\
         /sessions\n\
         /config\n\
         /policy explain\n\
         /policy diff profile:strict\n\
         /trace list\n\
         /trace summary\n\
         /attach {sock}\n\
         /status\n\
         /policy query\n\
         /policy patch --force --add-allow-command node\n\
         /policy patch --force --add-read /opt/tools\n\
         /policy patch --force --add-net-allow api.github.com\n\
         /policy query\n\
         /resources\n\
         /secrets backend\n\
         /secrets rules\n\
         /detach\n\
         /status\n\
         /exit\n",
        sock = mock.socket_path()
    );
    let out = run_shell_with_env(
        &input,
        &[],
        &[("SHADI_OTEL_FILE", trace_file.to_str().unwrap())],
    );

    out.assert_success()
        .stderr_is_empty()
        // help
        .stdout_contains("SHADI interactive shell commands")
        // status before attach
        .stdout_contains("not attached")
        // config & policy explain
        .stdout_contains("effective_policy")
        .stdout_contains("sources")
        // traces
        .stdout_contains("shadi.sandbox.spawn")
        .stdout_contains("shadi.policy.patch")
        // attach + connected status
        .stdout_contains("attached to")
        .stdout_contains("connected")
        // policy query
        .stdout_contains("allow_read")
        .stdout_contains("block_command")
        // policy patches
        .stdout_contains("\"accepted\": true")
        .stdout_contains("\"applied\"")
        .stdout_contains("pending_restart")
        // resources
        .stdout_contains("Process: PID")
        .stdout_contains("RSS:")
        .stdout_contains("Threads:")
        // secrets
        .stdout_contains("Backend:")
        // detach
        .stdout_contains("detached");
}
