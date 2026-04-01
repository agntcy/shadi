// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Cursor, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_transport_slim::{BridgeArgs, NativeSlimBootstrap, start_bridge_with_io};
use slim_bindings::{CaSource, Service, TlsSource};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const TEST_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";

fn env_lock() -> &'static Mutex<()> {
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

struct ScopedEnvVar {
    name: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnvVar {
    fn set(name: &'static str, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }

    fn unset(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::remove_var(name);
        Self { name, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
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
            "shadi-stdio-bridge-flow-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

struct SharedBuffer {
    data: Arc<Mutex<Vec<u8>>>,
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data
            .lock()
            .expect("shared output buffer")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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

fn client_tls_material(base_dir: &Path, agent_id: &str) -> TlsMaterial {
    let cert = base_dir.join(format!("client-{agent_id}.crt"));
    let key = base_dir.join(format!("client-{agent_id}.key"));
    assert!(cert.is_file(), "missing client cert for {agent_id}");
    assert!(key.is_file(), "missing client key for {agent_id}");

    TlsMaterial {
        cert,
        key,
        ca: base_dir.join("ca.crt"),
    }
}

fn server_tls_material(base_dir: &Path) -> TlsMaterial {
    TlsMaterial {
        cert: base_dir.join("server.crt"),
        key: base_dir.join("server.key"),
        ca: base_dir.join("ca.crt"),
    }
}

fn build_client_config(endpoint: &str, tls: &TlsMaterial) -> slim_bindings::ClientConfig {
    let mut config = slim_bindings::ClientConfig::default();
    config.endpoint = format!("https://{endpoint}");
    config.tls = slim_bindings::TlsClientConfig {
        insecure: false,
        insecure_skip_verify: false,
        source: TlsSource::File {
            cert: tls.cert.display().to_string(),
            key: tls.key.display().to_string(),
        },
        ca_source: CaSource::File {
            path: tls.ca.display().to_string(),
        },
        include_system_ca_certs_pool: false,
        tls_version: "tls1.3".to_string(),
    };
    config
}

fn build_server_config(endpoint: &str, tls: &TlsMaterial) -> slim_bindings::ServerConfig {
    let mut config = slim_bindings::ServerConfig::default();
    config.endpoint = endpoint.to_string();
    config.tls = slim_bindings::TlsServerConfig {
        insecure: false,
        source: TlsSource::File {
            cert: tls.cert.display().to_string(),
            key: tls.key.display().to_string(),
        },
        client_ca: CaSource::File {
            path: tls.ca.display().to_string(),
        },
        include_system_ca_certs_pool: Some(false),
        tls_version: Some("tls1.3".to_string()),
        reload_client_ca_file: Some(false),
    };
    config
}

fn reserve_test_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let endpoint = listener.local_addr().expect("local addr").to_string();
    drop(listener);
    endpoint
}

fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

#[test]
fn given_generated_assets_when_bridge_runs_then_it_reports_and_forwards_messages() {
    let _guard = env_lock().lock().expect("env lock");
    let dir = TestDir::new("runtime-flow");
    let tls_dir = generate_test_tls_dir(dir.path());
    let endpoint = reserve_test_endpoint();
    let server_tls = server_tls_material(&tls_dir);
    let participant_tls = client_tls_material(&tls_dir, "secops-a");
    let output = Arc::new(Mutex::new(Vec::new()));

    let node_service = Service::new(format!("stdio-bridge-test-node-{}", std::process::id()));
    node_service
        .run_server(build_server_config(&endpoint, &server_tls))
        .expect("start local SLIM node");
    thread::sleep(Duration::from_millis(250));

    let (ready_tx, ready_rx) = mpsc::channel();
    let endpoint_for_participant = endpoint.clone();
    let participant_handle = thread::spawn(move || -> Result<(u32, Vec<u8>), String> {
        let participant_service =
            Service::new(format!("stdio-bridge-test-participant-{}", std::process::id()));
        let participant_name = slim_bindings::Name::from_string("agntcy/shadi/secops-a".to_string())
            .map_err(format_slim_error)?;
        let connection_id = participant_service
            .connect(build_client_config(&endpoint_for_participant, &participant_tls))
            .map_err(format_slim_error)?;
        let participant_app = participant_service
            .create_app_with_secret(Arc::new(participant_name.clone()), TEST_SHARED_SECRET.to_string())
            .map_err(format_slim_error)?;

        participant_app
            .subscribe(Arc::new(participant_name), Some(connection_id))
            .map_err(format_slim_error)?;
        thread::sleep(Duration::from_millis(200));
        ready_tx.send(()).map_err(|err| err.to_string())?;

        let session = participant_app
            .listen_for_session(Some(Duration::from_secs(20)))
            .map_err(format_slim_error)?;
        let session_id = session.session_id().map_err(format_slim_error)?;
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
        Ok((session_id, payload))
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("participant ready");

    let _tmp_dir = ScopedEnvVar::set("SHADI_TMP_DIR", dir.path().as_os_str());
    let _endpoint = ScopedEnvVar::set("SLIM_ENDPOINT", &endpoint);
    let _secret = ScopedEnvVar::set("SLIM_SHARED_SECRET", TEST_SHARED_SECRET);
    let _agent_id = ScopedEnvVar::set("SHADI_AGENT_ID", "avatar");
    let _local_name = ScopedEnvVar::unset("SHADI_SLIM_LOCAL_NAME");
    let _cert = ScopedEnvVar::unset("SLIM_TLS_CERT");
    let _key = ScopedEnvVar::unset("SLIM_TLS_KEY");
    let _ca = ScopedEnvVar::unset("SLIM_TLS_CA");

    let bridge = start_bridge_with_io(
        BridgeArgs {
            bootstrap: NativeSlimBootstrap::PointToPoint {
                destination: "agntcy/shadi/secops-a".to_string(),
            },
            payload_type: Some("text/plain".to_string()),
            allow_empty: false,
        },
        Cursor::new("hello\n"),
        SharedBuffer {
            data: Arc::clone(&output),
        },
        None,
    )
    .expect("start stdio bridge");
    let session_info = bridge.session_info().clone();

    let report = bridge.wait().expect("wait for bridge");
    let (participant_session_id, participant_payload) = participant_handle
        .join()
        .expect("participant thread panicked")
        .expect("participant result");

    assert_eq!(session_info.mode, "point-to-point");
    assert_eq!(report.mode, "point-to-point");
    assert_eq!(report.local_name, session_info.local_name);
    assert_eq!(report.target, session_info.target);
    assert_eq!(report.session_id, session_info.session_id);
    assert_eq!(report.session_id, participant_session_id);
    assert_eq!(report.published, 1);
    assert_eq!(report.received, 1);
    assert_eq!(participant_payload, b"hello".to_vec());
    assert_eq!(
        output.lock().expect("output bytes").as_slice(),
        b"reply\n"
    );

    node_service
        .stop_server(endpoint.clone())
        .expect("stop node server");
    node_service.shutdown().expect("shutdown node service");
}