// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(windows))]
use std::collections::HashMap;
use std::fs;
#[cfg(not(windows))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(not(windows))]
use std::sync::mpsc;
#[cfg(not(windows))]
use std::thread;
#[cfg(not(windows))]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(windows))]
const TEST_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";

#[cfg(not(windows))]
#[derive(Clone)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

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
            "shadi-slim-bridge-bin-{label}-{}-{unique}",
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

fn bridge_bin() -> &'static str {
    env!("CARGO_BIN_EXE_slim-stdio-bridge")
}

#[cfg(not(windows))]
fn generate_test_tls_dir(base_dir: &Path) -> PathBuf {
    let tls_dir = base_dir.join("shadi-slim-mtls");
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tools")
        .join("generate_slim_mtls_certs.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg(&tls_dir)
        .output()
        .expect("run SLIM cert generator");

    assert!(
        output.status.success(),
        "failed to generate SLIM test certs: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    tls_dir
}

#[cfg(not(windows))]
fn client_tls_material(base_dir: &Path, agent_id: &str) -> TlsMaterial {
    TlsMaterial {
        cert: base_dir.join(format!("client-{agent_id}.crt")),
        key: base_dir.join(format!("client-{agent_id}.key")),
        ca: base_dir.join("ca.crt"),
    }
}

#[cfg(not(windows))]
fn server_tls_material(base_dir: &Path) -> TlsMaterial {
    TlsMaterial {
        cert: base_dir.join("server.crt"),
        key: base_dir.join("server.key"),
        ca: base_dir.join("ca.crt"),
    }
}

#[cfg(not(windows))]
fn build_client_config(endpoint: &str, tls: &TlsMaterial) -> slim_bindings::ClientConfig {
    let mut config = slim_bindings::ClientConfig::default();
    config.endpoint = format!("https://{endpoint}");
    config.tls = slim_bindings::TlsClientConfig {
        insecure: false,
        insecure_skip_verify: false,
        source: slim_bindings::TlsSource::File {
            cert: tls.cert.display().to_string(),
            key: tls.key.display().to_string(),
        },
        ca_source: slim_bindings::CaSource::File {
            path: tls.ca.display().to_string(),
        },
        include_system_ca_certs_pool: false,
        tls_version: "tls1.3".to_string(),
    };
    config
}

#[cfg(not(windows))]
fn build_server_config(endpoint: &str, tls: &TlsMaterial) -> slim_bindings::ServerConfig {
    let mut config = slim_bindings::ServerConfig::default();
    config.endpoint = endpoint.to_string();
    config.tls = slim_bindings::TlsServerConfig {
        insecure: false,
        source: slim_bindings::TlsSource::File {
            cert: tls.cert.display().to_string(),
            key: tls.key.display().to_string(),
        },
        client_ca: slim_bindings::CaSource::File {
            path: tls.ca.display().to_string(),
        },
        include_system_ca_certs_pool: Some(false),
        tls_version: Some("tls1.3".to_string()),
        reload_client_ca_file: Some(false),
    };
    config
}

#[cfg(not(windows))]
fn reserve_test_endpoint() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let endpoint = listener.local_addr().expect("local addr").to_string();
    drop(listener);
    endpoint
}

#[cfg(not(windows))]
fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

#[test]
fn given_help_flag_when_bridge_bin_runs_then_usage_is_printed() {
    let output = Command::new(bridge_bin())
        .arg("--help")
        .output()
        .expect("run bridge help");

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Usage: slim-stdio-bridge")
    );
}

#[test]
fn given_invalid_argument_when_bridge_bin_runs_then_parse_error_is_reported() {
    let output = Command::new(bridge_bin())
        .arg("--bogus")
        .output()
        .expect("run bridge invalid arg");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown argument"));
    assert!(stderr.contains("Usage: slim-stdio-bridge"));
}

#[test]
fn given_missing_runtime_material_when_bridge_bin_runs_then_runtime_error_is_reported() {
    let dir = TestDir::new("missing-runtime-material");
    let output = Command::new(bridge_bin())
        .args(["--destination", "agntcy/shadi/avatar"])
        .env("SHADI_TMP_DIR", dir.path())
        .env("SLIM_SHARED_SECRET", "shared-secret")
        .env_remove("SLIM_TLS_CERT")
        .env_remove("SLIM_TLS_KEY")
        .env_remove("SLIM_TLS_CA")
        .output()
        .expect("run bridge runtime error");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no SLIM client certificate found")
    );
}

#[cfg(not(windows))]
#[test]
fn given_generated_assets_when_bridge_bin_runs_then_stdio_bridge_completes_successfully() {
    let dir = TestDir::new("bridge-bin-success");
    let tls_dir = generate_test_tls_dir(dir.path());
    let endpoint = reserve_test_endpoint();
    let server_tls = server_tls_material(&tls_dir);
    let participant_tls = client_tls_material(&tls_dir, "secops-a");

    let node_service = slim_bindings::Service::new(format!("slim-bridge-bin-test-node-{}", std::process::id()));
    node_service
        .run_server(build_server_config(&endpoint, &server_tls))
        .expect("start local SLIM node");
    thread::sleep(Duration::from_millis(250));

    let (ready_tx, ready_rx) = mpsc::channel();
    let endpoint_for_participant = endpoint.clone();
    let participant_handle = thread::spawn(move || -> Result<Vec<u8>, String> {
        let participant_service = slim_bindings::Service::new(format!(
            "slim-bridge-bin-test-participant-{}",
            std::process::id()
        ));
        let participant_name = slim_bindings::Name::from_string("agntcy/shadi/secops-a".to_string())
            .map_err(format_slim_error)?;
        let connection_id = participant_service
            .connect(build_client_config(&endpoint_for_participant, &participant_tls))
            .map_err(format_slim_error)?;
        let participant_app = participant_service
            .create_app_with_secret(std::sync::Arc::new(participant_name.clone()), TEST_SHARED_SECRET.to_string())
            .map_err(format_slim_error)?;

        participant_app
            .subscribe(std::sync::Arc::new(participant_name), Some(connection_id))
            .map_err(format_slim_error)?;
        thread::sleep(Duration::from_millis(200));
        ready_tx.send(()).map_err(|err| err.to_string())?;

        let session = participant_app
            .listen_for_session(Some(Duration::from_secs(20)))
            .map_err(format_slim_error)?;
        let payload = session
            .get_message(Some(Duration::from_secs(20)))
            .map_err(format_slim_error)?
            .payload;
        session
            .publish_and_wait(b"reply".to_vec(), None, Some(HashMap::new()))
            .map_err(format_slim_error)?;

        let _ = participant_app.delete_session_and_wait(session);
        participant_service
            .disconnect(connection_id)
            .map_err(format_slim_error)?;
        participant_service.shutdown().map_err(format_slim_error)?;
        Ok(payload)
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("participant ready");

    let mut child = Command::new(bridge_bin())
        .args(["--destination", "agntcy/shadi/secops-a"])
        .env("SHADI_TMP_DIR", dir.path())
        .env("SLIM_ENDPOINT", &endpoint)
        .env("SLIM_SHARED_SECRET", TEST_SHARED_SECRET)
        .env("SHADI_AGENT_ID", "avatar")
        .env_remove("SLIM_TLS_CERT")
        .env_remove("SLIM_TLS_KEY")
        .env_remove("SLIM_TLS_CA")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn bridge bin");

    child
        .stdin
        .take()
        .expect("bridge stdin")
        .write_all(b"hello\n")
        .expect("write stdin");

    let output = child.wait_with_output().expect("wait for bridge bin");
    let payload = participant_handle
        .join()
        .expect("participant thread panicked")
        .expect("participant payload");

    node_service
        .stop_server(endpoint.clone())
        .expect("stop node server");
    node_service.shutdown().expect("shutdown node service");

    assert!(output.status.success());
    assert_eq!(payload, b"hello".to_vec());
    assert!(String::from_utf8_lossy(&output.stdout).contains("reply\n"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("connected SLIM stdio bridge as"));
    assert!(stderr.contains("published 1 SLIM messages and received 1 SLIM messages"));
}