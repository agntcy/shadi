// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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