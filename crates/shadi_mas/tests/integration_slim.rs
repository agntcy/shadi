//! Integration tests that require a running SLIM node.
//!
//! Tests start a SLIM node with mTLS via `slimctl slim start -c <yaml>` and
//! connect using the pre-generated certificates in `.tmp/shadi-slim-mtls/`.
//!
//! Prerequisites:
//!   • `slimctl` in PATH
//!   • run `tools/generate_slim_mtls_certs.sh` at least once
//!
//! Run with a single thread to avoid port conflicts:
//!   cargo test -p agntcy-shadi-mas --test integration_slim -- --test-threads=1

use shadi_mas::{MessagingAdapter, TaskAdapter, TaskEnvelope};
use shadi_mas::experiments::{
    LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig, LiveSlimGroupConfig, LiveSlimMessagingAdapter,
};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// ─── Constants ────────────────────────────────────────────────────────────────

const SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";
const CLIENT_AGENT_ID: &str = "avatar";

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repo root")
}

fn cert_dir() -> PathBuf {
    repo_root().join(".tmp").join("shadi-slim-mtls")
}

/// Bind to :0, release, return port — racey but fine for tests.
fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn wait_tcp(endpoint: &str, timeout: Duration) {
    let addr: std::net::SocketAddr = endpoint.parse().expect("parse endpoint");
    let deadline = Instant::now() + timeout;
    while TcpListener::bind(addr).is_ok() {
        // port is free — not yet occupied
        if Instant::now() >= deadline {
            panic!("SLIM node on {endpoint} did not start in time");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // now port is bound by the server
}

// ─── SlimNode fixture ─────────────────────────────────────────────────────────

struct SlimNode {
    child: Child,
    pub endpoint: String,
    _config_file: tempfile::NamedTempFile,
}

impl SlimNode {
    /// Spawn `slimctl slim start -c <yaml>` with mTLS using the pre-generated certs.
    /// Panics if `slimctl` is not in PATH or if the certs are missing.
    fn start() -> Self {
        // Guard: slimctl must be available.
        if Command::new("slimctl").arg("--help").output().is_err() {
            panic!("slimctl not found in PATH");
        }
        let cdir = cert_dir();
        assert!(
            cdir.join("server.crt").exists(),
            "Server cert not found at {}. Run tools/generate_slim_mtls_certs.sh first.",
            cdir.display()
        );
        assert!(
            cdir.join(format!("client-{CLIENT_AGENT_ID}.crt")).exists(),
            "Client cert for {CLIENT_AGENT_ID} not found. Run tools/generate_slim_mtls_certs.sh first.",
        );

        let port = reserve_port();
        let endpoint = format!("127.0.0.1:{port}");

        // Write YAML config to a temp file.
        let config_file = tempfile::NamedTempFile::new().expect("create temp config");
        let yaml = format!(
            r#"
services:
  slim/0:
    dataplane:
      servers:
        - endpoint: "{endpoint}"
          tls:
            source:
              type: file
              cert: "{cert_dir}/server.crt"
              key: "{cert_dir}/server.key"
            include_system_ca_certs_pool: false
"#,
            endpoint = endpoint,
            cert_dir = cdir.display(),
        );
        fs::write(config_file.path(), yaml.as_bytes()).expect("write config");

        let child = Command::new("slimctl")
            .args(["slim", "start", "-c", config_file.path().to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn slimctl slim start");

        // Wait until the port is occupied.
        wait_tcp(&endpoint, Duration::from_secs(10));

        Self {
            child,
            endpoint,
            _config_file: config_file,
        }
    }
}

impl Drop for SlimNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Set env vars read by `resolve_client_tls_material_for_agent` and
/// `NativeSlimSession::from_env`.
fn set_slim_client_env(endpoint: &str) {
    let cdir = cert_dir();
    std::env::set_var("SLIM_ENDPOINT", endpoint);
    std::env::set_var("SLIM_SHARED_SECRET", SHARED_SECRET);
    std::env::set_var("SHADI_AGENT_ID", CLIENT_AGENT_ID);
    std::env::set_var(
        "SHADI_SLIM_LOCAL_NAME",
        format!("agntcy/shadi/{CLIENT_AGENT_ID}-slim"),
    );
    std::env::set_var("SLIM_TLS_CERT", cdir.join(format!("client-{CLIENT_AGENT_ID}.crt")));
    std::env::set_var("SLIM_TLS_KEY", cdir.join(format!("client-{CLIENT_AGENT_ID}.key")));
    std::env::set_var("SLIM_TLS_CA", cdir.join("ca.crt"));
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Group adapter construction rejects an empty participants list immediately
/// (no SLIM node required).
#[test]
fn live_slim_group_rejects_empty_participants() {
    let config = LiveSlimGroupConfig {
        endpoint: "127.0.0.1:47357".to_string(),
        agent_id: "test-agent".to_string(),
        local_name: "agntcy/shadi/test-slim".to_string(),
        shared_secret: SHARED_SECRET.to_string(),
        channel: "agntcy/shadi/test-channel".to_string(),
        participants: vec![],
        receipt_files: vec![],
        receipt_timeout: Duration::from_secs(1),
    };
    let result = LiveSlimMessagingAdapter::group(config);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("participant"), "unexpected error: {err}");
}

/// Group adapter construction rejects mismatched participant / receipt-file counts.
#[test]
fn live_slim_group_rejects_mismatched_receipt_files() {
    let config = LiveSlimGroupConfig {
        endpoint: "127.0.0.1:47357".to_string(),
        agent_id: "test-agent".to_string(),
        local_name: "agntcy/shadi/test-slim".to_string(),
        shared_secret: SHARED_SECRET.to_string(),
        channel: "agntcy/shadi/test-channel".to_string(),
        participants: vec!["agntcy/shadi/peer-a".to_string()],
        receipt_files: vec![],
        receipt_timeout: Duration::from_secs(1),
    };
    let result = LiveSlimMessagingAdapter::group(config);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("receipt"), "unexpected error: {err}");
}

/// `LiveSlimMessagingAdapter::point_to_point()` is called against a running
/// SLIM node. The session establishment fails gracefully when the destination
/// is not listening — the key coverage goal is that the constructor code path
/// is exercised end-to-end (rather than asserting success, which would require
/// a peer subprocess).
#[test]
fn live_slim_point_to_point_constructor_path_with_node() {
    let node = SlimNode::start();
    set_slim_client_env(&node.endpoint);

    // The destination "nonexistent-dest" is not registered on the SLIM node.
    // NativeSlimSession::from_env → create_session_and_wait → retries → Err.
    // This exercises: point_to_point() entry, from_env call, TLS connection to
    // the node, and the error propagation path.
    let result = LiveSlimMessagingAdapter::point_to_point(
        "agntcy/shadi/nonexistent-slim-dest",
    );
    // Either outcome is valid: success (if SLIM is lenient) or a clear error.
    // What must NOT happen is a panic.
    match result {
        Ok(adapter) => {
            // Succeeded — verify accessors work.
            assert!(adapter.published_messages().unwrap().is_empty());
            assert!(adapter.acknowledgements().unwrap().is_empty());
            assert!(adapter.exchanges().unwrap().is_empty());
        }
        Err(e) => {
            // Expected when destination is not present.
            assert!(!e.is_empty(), "error message should be non-empty");
        }
    }
}

/// `LiveA2ATaskAdapter::dispatch()` returns an error (not a panic) when the
/// configured peer is not present on the SLIM node.
#[test]
fn live_a2a_adapter_dispatch_returns_error_without_peer() {
    let node = SlimNode::start();
    set_slim_client_env(&node.endpoint);

    let config = LiveA2ATaskAdapterConfig {
        endpoint: node.endpoint.clone(),
        agent_id: CLIENT_AGENT_ID.to_string(),
        local_name: Some(format!("agntcy/shadi/{CLIENT_AGENT_ID}-a2a")),
        peer_agent_id: "nonexistent".to_string(),
        destination: Some("agntcy/shadi/nonexistent-a2a".to_string()),
        shared_secret: SHARED_SECRET.to_string(),
    };
    let adapter = LiveA2ATaskAdapter::new(config);

    use shadi_mas::{Epoch, PatternKind};
    let task = TaskEnvelope {
        task_id: "no-peer-task".to_string(),
        pattern: PatternKind::Development,
        epoch: Epoch(0),
        correlation_id: None,
        body: b"test".to_vec(),
    };

    let result = adapter.dispatch(task);
    assert!(result.is_err(), "expected error when peer is absent, got Ok");
}
