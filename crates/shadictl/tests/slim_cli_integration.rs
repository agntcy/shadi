// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shadi-slim-cli-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn given_missing_server_material_when_start_node_runs_then_error_is_reported() {
    let dir = TestDir::new("missing-server-material");
    let output = Command::new(env!("CARGO_BIN_EXE_shadictl"))
        .args(["slim", "start-node"])
        .env("SHADI_TMP_DIR", dir.path())
        .env_remove("SLIM_TLS_CERT")
        .env_remove("SLIM_TLS_KEY")
        .env_remove("SLIM_TLS_CA")
        .output()
        .expect("run shadictl slim start-node");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("SLIM server certificate not found")
    );
}

#[test]
fn given_generated_mtls_assets_when_a2a_peer_and_sender_run_then_streaming_round_trip_succeeds() {
    let dir = TestDir::new("a2a-roundtrip");
    let endpoint = reserve_endpoint();
    let ready_file = dir.path().join("a2a-peer.ready");
    let tls_dir = dir.path().join("shadi-slim-mtls");
    generate_mtls_assets(&tls_dir);

    let mut peer = Command::new(env!("CARGO_BIN_EXE_shadictl"))
        .args([
            "slim",
            "a2a-echo-peer",
            "--endpoint",
            &endpoint,
            "--agent-id",
            "secops-a",
            "--start-local-node",
            "--ready-file",
            ready_file.to_str().expect("ready file path"),
            "--listen-timeout-seconds",
            "40",
        ])
        .env("SHADI_TMP_DIR", dir.path())
        .env("SLIM_SHARED_SECRET", "my_shared_secret_for_testing_purposes_only")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shadictl slim a2a-echo-peer");

    wait_for_file(&ready_file, Duration::from_secs(10));

    let sender = Command::new(env!("CARGO_BIN_EXE_shadictl"))
        .args([
            "slim",
            "a2a-send",
            "--endpoint",
            &endpoint,
            "--agent-id",
            "avatar",
            "--peer-agent-id",
            "secops-a",
            "--message",
            "hello from integration test",
            "--stream",
            "--timeout-seconds",
            "15",
        ])
        .env("SHADI_TMP_DIR", dir.path())
        .env("SLIM_SHARED_SECRET", "my_shared_secret_for_testing_purposes_only")
        .output()
        .expect("run shadictl slim a2a-send");

    if !sender.status.success() {
        let _ = peer.kill();
        let _ = peer.wait();
    }

    let (peer_status, peer_stdout, peer_stderr) =
        wait_for_child_output(&mut peer, Duration::from_secs(20));

    assert_eq!(sender.status.code(), Some(0), "sender stderr={} stdout={}", String::from_utf8_lossy(&sender.stderr), String::from_utf8_lossy(&sender.stdout));
    let sender_stdout = String::from_utf8_lossy(&sender.stdout);
    assert!(sender_stdout.contains("stream [status Working, task "), "sender stdout={sender_stdout}");
    assert!(sender_stdout.contains("echo:agntcy/shadi/secops-a:hello from integration test"), "sender stdout={sender_stdout}");

    assert_eq!(peer_status.code(), Some(0), "peer stderr={} stdout={}", peer_stderr, peer_stdout);
    assert!(peer_stdout.contains("[shadictl a2a-peer] ready as agntcy/shadi/secops-a"), "peer stdout={peer_stdout}");
}

fn reserve_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve local port");
    let address = listener.local_addr().expect("listener addr");
    drop(listener);
    format!("127.0.0.1:{}", address.port())
}

fn generate_mtls_assets(target_dir: &Path) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/generate_slim_mtls_certs.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg(target_dir)
        .output()
        .expect("run cert generation script");

    assert_eq!(
        output.status.code(),
        Some(0),
        "cert generation stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
}

fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }

    panic!("timed out waiting for {}", path.display());
}

fn wait_for_child_output(child: &mut Child, timeout: Duration) -> (std::process::ExitStatus, String, String) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child status") {
            let stdout = read_child_pipe(child.stdout.take());
            let stderr = read_child_pipe(child.stderr.take());
            return (status, stdout, stderr);
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().expect("wait after kill");
            let stdout = read_child_pipe(child.stdout.take());
            let stderr = read_child_pipe(child.stderr.take());
            panic!(
                "timed out waiting for child exit; status={:?} stdout={} stderr={}",
                status.code(),
                stdout,
                stderr
            );
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn read_child_pipe(pipe: Option<impl Read>) -> String {
    let mut output = String::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_string(&mut output).expect("read child pipe");
    }
    output
}