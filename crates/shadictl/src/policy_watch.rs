// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Control channel for runtime policy patches.
//!
//! When `--watch-policy` is passed, `shadictl` creates a local AF_UNIX
//! control socket.  On Unix the path is `$TMPDIR/shadi-ctl-<pid>.sock`;
//! on Windows (10 1803+) it is `%TEMP%\shadi-ctl-<pid>.sock` using the
//! native `AF_UNIX` support via the [`uds_windows`] crate.
//!
//! External callers (including `shadictl policy patch`) connect, send a JSON
//! [`ControlMessage`], and receive a JSON [`ControlResponse`].
//!
//! Only user-space axes (command allow/block lists) can be applied immediately.
//! Filesystem and network changes are staged and reported as
//! [`PatchAxisStatus::PendingRestart`].

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(unix)]
use std::os::unix::net::UnixListener;

#[cfg(windows)]
use uds_windows::UnixListener;

use shadi_sandbox::{
    ControlMessage, ControlResponse, PatchAxisStatus, PolicyPatch, PolicyPatchResponse,
    SandboxPolicy,
};
use tracing::info_span;

/// Mutable policy state shared between the main thread and the control socket
/// listener thread.
pub(crate) struct LivePolicy {
    pub(crate) policy: SandboxPolicy,
    pub(crate) blocked: HashSet<String>,
    pub(crate) allow: HashSet<String>,
    /// Filesystem patches staged for next restart.
    pub(crate) staged_read: Vec<String>,
    pub(crate) staged_write: Vec<String>,
    pub(crate) staged_allow: Vec<String>,
    /// Network destinations staged for next restart.
    pub(crate) staged_net_allow: Vec<String>,
}

/// Handle to a running control listener. Dropping it removes the endpoint file.
pub(crate) struct ControlSocketHandle {
    path: PathBuf,
    _thread: thread::JoinHandle<()>,
}

impl ControlSocketHandle {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ControlSocketHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Resolve the default control socket path for a given PID.
#[cfg(unix)]
pub(crate) fn default_socket_path(pid: u32) -> PathBuf {
    let dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(dir).join(format!("shadi-ctl-{}.sock", pid))
}

/// Resolve the default control socket path for a given PID.
///
/// On Windows this is an `AF_UNIX` socket file (requires Windows 10 1803+).
#[cfg(windows)]
pub(crate) fn default_socket_path(pid: u32) -> PathBuf {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(dir).join(format!("shadi-ctl-{}.sock", pid))
}

// ---------------------------------------------------------------------------
// Listener (AF_UNIX on all platforms)
// ---------------------------------------------------------------------------

pub(crate) fn start_control_socket(
    path: &Path,
    live: Arc<Mutex<LivePolicy>>,
) -> Result<ControlSocketHandle, String> {
    // Remove stale socket if present.
    let _ = std::fs::remove_file(path);

    let listener =
        UnixListener::bind(path).map_err(|e| format!("failed to bind control socket: {}", e))?;

    listener
        .set_nonblocking(true)
        .map_err(|e| format!("failed to set non-blocking: {}", e))?;

    let socket_path = path.to_path_buf();
    let thread_path = socket_path.clone();

    let handle = thread::spawn(move || {
        accept_loop(&listener, &live, &thread_path);
    });

    Ok(ControlSocketHandle {
        path: socket_path,
        _thread: handle,
    })
}

fn accept_loop(listener: &UnixListener, live: &Arc<Mutex<LivePolicy>>, socket_path: &Path) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                handle_stream(stream, live);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if !socket_path.exists() {
                    break;
                }
                continue;
            }
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared: stream handling and patch logic
// ---------------------------------------------------------------------------

fn handle_stream(stream: impl std::io::Read + std::io::Write, live: &Arc<Mutex<LivePolicy>>) {
    let span = info_span!("shadi.policy.control_socket");
    let _guard = span.enter();

    let mut reader = BufReader::new(stream);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }

        if line_buf.trim().is_empty() {
            continue;
        }

        let msg: ControlMessage = match serde_json::from_str(&line_buf) {
            Ok(m) => m,
            Err(e) => {
                let resp = ControlResponse::Error {
                    message: format!("invalid message: {}", e),
                };
                let _ = write_response(reader.get_mut(), &resp);
                continue;
            }
        };

        let resp = match msg {
            ControlMessage::QueryPolicy => handle_query(live),
            ControlMessage::Patch(patch) => handle_patch(live, patch),
        };

        if write_response(reader.get_mut(), &resp).is_err() {
            break;
        }
    }
}

fn write_response(writer: &mut impl Write, resp: &ControlResponse) -> std::io::Result<()> {
    let json = serde_json::to_string(resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn handle_query(live: &Arc<Mutex<LivePolicy>>) -> ControlResponse {
    let guard = match live.lock() {
        Ok(g) => g,
        Err(_) => {
            return ControlResponse::Error {
                message: "internal lock error".to_string(),
            }
        }
    };

    let policy_json = serde_json::json!({
        "allow_read": guard.policy.allow_read().iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "allow_write": guard.policy.allow_write().iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "net_blocked": guard.policy.net_blocked(),
        "allow_command": guard.allow.iter().cloned().collect::<Vec<_>>(),
        "block_command": guard.blocked.iter().cloned().collect::<Vec<_>>(),
        "staged_read": guard.staged_read,
        "staged_write": guard.staged_write,
        "staged_allow": guard.staged_allow,
        "staged_net_allow": guard.staged_net_allow,
    });

    ControlResponse::Policy {
        policy: policy_json,
    }
}

fn handle_patch(live: &Arc<Mutex<LivePolicy>>, patch: PolicyPatch) -> ControlResponse {
    let span = info_span!(
        "shadi.policy.patch",
        patch.add_commands = patch.add_allow_command.len() as i64,
        patch.block_commands = patch.add_block_command.len() as i64,
        patch.fs_paths = (patch.add_read.len() + patch.add_write.len() + patch.add_allow.len()) as i64,
        patch.net_entries = patch.add_net_allow.len() as i64,
    );
    let _guard = span.enter();

    let mut guard = match live.lock() {
        Ok(g) => g,
        Err(_) => {
            return ControlResponse::PatchResult(PolicyPatchResponse {
                accepted: false,
                filesystem: PatchAxisStatus::Rejected,
                commands: PatchAxisStatus::Rejected,
                network: PatchAxisStatus::Rejected,
                message: "internal lock error".to_string(),
                pending_restart: vec![],
            })
        }
    };

    let mut commands_status = PatchAxisStatus::Unchanged;
    let mut fs_status = PatchAxisStatus::Unchanged;
    let mut net_status = PatchAxisStatus::Unchanged;
    let mut pending_restart = Vec::new();

    // --- Command allow/block (user-space, immediate) ---
    let has_cmd_changes = !patch.add_allow_command.is_empty()
        || !patch.remove_allow_command.is_empty()
        || !patch.add_block_command.is_empty()
        || !patch.remove_block_command.is_empty();

    if has_cmd_changes {
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
        commands_status = PatchAxisStatus::Applied;
    }

    // --- Filesystem paths (kernel, staged) ---
    let has_fs_changes =
        !patch.add_read.is_empty() || !patch.add_write.is_empty() || !patch.add_allow.is_empty();

    if has_fs_changes {
        guard.staged_read.extend(patch.add_read);
        guard.staged_write.extend(patch.add_write);
        guard.staged_allow.extend(patch.add_allow);
        fs_status = PatchAxisStatus::PendingRestart;
        pending_restart.push("filesystem".to_string());
    }

    // --- Network allow (kernel, staged) ---
    let has_net_changes = !patch.add_net_allow.is_empty() || !patch.remove_net_allow.is_empty();

    if has_net_changes {
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

    let accepted = commands_status != PatchAxisStatus::Rejected
        && fs_status != PatchAxisStatus::Rejected
        && net_status != PatchAxisStatus::Rejected;

    let message = if pending_restart.is_empty() {
        "patch applied".to_string()
    } else {
        format!(
            "patch accepted; {} require process restart to take effect",
            pending_restart.join(", ")
        )
    };

    ControlResponse::PatchResult(PolicyPatchResponse {
        accepted,
        filesystem: fs_status,
        commands: commands_status,
        network: net_status,
        message,
        pending_restart,
    })
}

// ---------------------------------------------------------------------------
// Client helpers (cross-platform)
// ---------------------------------------------------------------------------

/// Send a patch to a running control endpoint and return the response.
pub(crate) fn send_patch(socket_path: &Path, patch: &PolicyPatch) -> Result<PolicyPatchResponse, String> {
    let msg = ControlMessage::Patch(patch.clone());
    let resp = send_message(socket_path, &msg)?;
    match resp {
        ControlResponse::PatchResult(r) => Ok(r),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected response type".to_string()),
    }
}

/// Query the current effective policy from a running control endpoint.
pub(crate) fn query_policy(socket_path: &Path) -> Result<serde_json::Value, String> {
    let msg = ControlMessage::QueryPolicy;
    let resp = send_message(socket_path, &msg)?;
    match resp {
        ControlResponse::Policy { policy } => Ok(policy),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected response type".to_string()),
    }
}

fn send_message(socket_path: &Path, msg: &ControlMessage) -> Result<ControlResponse, String> {
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    #[cfg(windows)]
    use uds_windows::UnixStream;

    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("failed to connect: {}", e))?;

    let json =
        serde_json::to_string(msg).map_err(|e| format!("failed to serialize message: {}", e))?;
    stream
        .write_all(json.as_bytes())
        .map_err(|e| format!("failed to write: {}", e))?;
    stream
        .write_all(b"\n")
        .map_err(|e| format!("failed to write newline: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {}", e))?;

    // Shutdown write half so the server sees EOF on our request.
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("failed to shutdown write: {}", e))?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed to read response: {}", e))?;

    serde_json::from_str(&line).map_err(|e| format!("invalid response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn wait_for_socket_ready(sock_path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if sock_path.exists() && query_policy(sock_path).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("control socket did not become ready: {}", sock_path.display());
    }

    fn wait_for_socket_removed(sock_path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !sock_path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("control socket was not removed: {}", sock_path.display());
    }

    fn test_live_policy() -> Arc<Mutex<LivePolicy>> {
        Arc::new(Mutex::new(LivePolicy {
            policy: SandboxPolicy::new().block_network(true),
            blocked: ["rm", "sudo"].iter().map(|s| s.to_string()).collect(),
            allow: HashSet::new(),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            staged_net_allow: Vec::new(),
        }))
    }

    #[test]
    fn handle_patch_applies_command_changes() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_allow_command: vec!["npm".to_string()],
            add_block_command: vec!["curl".to_string()],
            ..Default::default()
        };

        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.commands, PatchAxisStatus::Applied);
                assert_eq!(r.filesystem, PatchAxisStatus::Unchanged);
                assert!(r.pending_restart.is_empty());
            }
            _ => panic!("expected PatchResult"),
        }

        let guard = live.lock().unwrap();
        assert!(guard.allow.contains("npm"));
        assert!(guard.blocked.contains("curl"));
    }

    #[test]
    fn handle_patch_stages_filesystem_changes() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_read: vec!["/opt/tools".to_string()],
            add_write: vec!["/tmp/out".to_string()],
            ..Default::default()
        };

        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.filesystem, PatchAxisStatus::PendingRestart);
                assert!(r.pending_restart.contains(&"filesystem".to_string()));
            }
            _ => panic!("expected PatchResult"),
        }

        let guard = live.lock().unwrap();
        assert_eq!(guard.staged_read, vec!["/opt/tools"]);
        assert_eq!(guard.staged_write, vec!["/tmp/out"]);
    }

    #[test]
    fn handle_patch_stages_network_changes() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_net_allow: vec!["api.github.com".to_string()],
            ..Default::default()
        };

        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.network, PatchAxisStatus::PendingRestart);
                assert!(r.pending_restart.contains(&"network".to_string()));
            }
            _ => panic!("expected PatchResult"),
        }

        let guard = live.lock().unwrap();
        assert_eq!(guard.staged_net_allow, vec!["api.github.com"]);
    }

    #[test]
    fn handle_query_returns_current_state() {
        let live = test_live_policy();
        let resp = handle_query(&live);
        match resp {
            ControlResponse::Policy { policy } => {
                assert!(policy["net_blocked"].as_bool().unwrap());
            }
            _ => panic!("expected Policy"),
        }
    }

    #[test]
    fn empty_patch_is_accepted() {
        let live = test_live_policy();
        let patch = PolicyPatch::default();
        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.commands, PatchAxisStatus::Unchanged);
                assert_eq!(r.filesystem, PatchAxisStatus::Unchanged);
                assert_eq!(r.network, PatchAxisStatus::Unchanged);
            }
            _ => panic!("expected PatchResult"),
        }
    }

    #[test]
    fn control_socket_round_trip() {
        let live = test_live_policy();
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("test.sock");

        let handle = start_control_socket(&sock_path, live).expect("start socket");
        assert!(handle.path().exists());
        wait_for_socket_ready(&sock_path);

        // Send a command patch.
        let patch = PolicyPatch {
            add_allow_command: vec!["node".to_string()],
            ..Default::default()
        };
        let result = send_patch(&sock_path, &patch).expect("send patch");
        assert!(result.accepted);
        assert_eq!(result.commands, PatchAxisStatus::Applied);

        // Query current state.
        let policy = query_policy(&sock_path).expect("query");
        let allow_cmds = policy["allow_command"]
            .as_array()
            .expect("allow_command array");
        let has_node = allow_cmds.iter().any(|v| v.as_str() == Some("node"));
        assert!(has_node);

        drop(handle);
        // Endpoint file should be cleaned up.
        wait_for_socket_removed(&sock_path);
    }

    #[test]
    fn default_socket_path_contains_pid() {
        let path = default_socket_path(42);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.contains("42"));
        assert!(name.ends_with(".sock"));
    }

    #[test]
    fn handle_patch_removes_commands() {
        let live = test_live_policy();
        // "rm" and "sudo" are in the initial blocked set.
        let patch = PolicyPatch {
            remove_block_command: vec!["rm".to_string()],
            add_allow_command: vec!["git".to_string()],
            remove_allow_command: vec!["git".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.commands, PatchAxisStatus::Applied);
            }
            _ => panic!("expected PatchResult"),
        }
        let guard = live.lock().unwrap();
        assert!(!guard.blocked.contains("rm"));
        assert!(guard.blocked.contains("sudo"));
        assert!(!guard.allow.contains("git"));
    }

    #[test]
    fn handle_patch_removes_net_allow() {
        let live = test_live_policy();
        // First add a network entry.
        let patch1 = PolicyPatch {
            add_net_allow: vec!["example.com".to_string()],
            ..Default::default()
        };
        handle_patch(&live, patch1);
        // Now remove it.
        let patch2 = PolicyPatch {
            remove_net_allow: vec!["example.com".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch2);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.network, PatchAxisStatus::PendingRestart);
            }
            _ => panic!("expected PatchResult"),
        }
        let guard = live.lock().unwrap();
        assert!(guard.staged_net_allow.is_empty());
    }

    #[test]
    fn handle_patch_deduplicates_net_allow() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_net_allow: vec!["dup.com".to_string(), "dup.com".to_string()],
            ..Default::default()
        };
        handle_patch(&live, patch);
        let guard = live.lock().unwrap();
        assert_eq!(guard.staged_net_allow, vec!["dup.com"]);
    }

    #[test]
    fn handle_patch_stages_allow_paths() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_allow: vec!["/opt/shared".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.filesystem, PatchAxisStatus::PendingRestart);
            }
            _ => panic!("expected PatchResult"),
        }
        let guard = live.lock().unwrap();
        assert_eq!(guard.staged_allow, vec!["/opt/shared"]);
    }

    #[test]
    fn handle_patch_combined_axes() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_allow_command: vec!["npm".to_string()],
            add_read: vec!["/opt/data".to_string()],
            add_net_allow: vec!["cdn.example.com".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.commands, PatchAxisStatus::Applied);
                assert_eq!(r.filesystem, PatchAxisStatus::PendingRestart);
                assert_eq!(r.network, PatchAxisStatus::PendingRestart);
                assert_eq!(r.pending_restart.len(), 2);
                assert!(r.message.contains("require process restart"));
            }
            _ => panic!("expected PatchResult"),
        }
    }

    #[test]
    fn handle_stream_tolerates_invalid_json() {
        use std::io::Cursor;

        let live = test_live_policy();
        let input = b"not valid json\n";
        let mut buf = Vec::new();
        buf.extend_from_slice(input);
        // Provide enough capacity for the response.
        let stream = Cursor::new(buf);
        handle_stream(stream, &live);
        // No panic — the error path was exercised.
    }

    #[test]
    fn handle_stream_skips_blank_lines() {
        use std::io::Cursor;

        let live = test_live_policy();
        let input = b"\n   \n";
        let stream = Cursor::new(input.to_vec());
        handle_stream(stream, &live);
    }

    #[test]
    fn send_message_fails_on_bad_path() {
        let bad_path = Path::new("/tmp/shadi-nonexistent-test.sock");
        let msg = ControlMessage::QueryPolicy;
        let result = send_message(bad_path, &msg);
        assert!(result.is_err());
    }

    #[test]
    fn send_patch_propagates_connect_error() {
        let bad_path = Path::new("/tmp/shadi-nonexistent-test.sock");
        let patch = PolicyPatch::default();
        let result = send_patch(bad_path, &patch);
        assert!(result.is_err());
    }

    #[test]
    fn query_policy_propagates_connect_error() {
        let bad_path = Path::new("/tmp/shadi-nonexistent-test.sock");
        let result = query_policy(bad_path);
        assert!(result.is_err());
    }

    #[test]
    fn handle_query_includes_staged_data() {
        let live = test_live_policy();
        {
            let mut guard = live.lock().unwrap();
            guard.staged_read.push("/staged/read".to_string());
            guard.staged_write.push("/staged/write".to_string());
            guard.staged_allow.push("/staged/allow".to_string());
            guard.staged_net_allow.push("staged.example.com".to_string());
            guard.allow.insert("allowed-cmd".to_string());
        }
        let resp = handle_query(&live);
        match resp {
            ControlResponse::Policy { policy } => {
                assert_eq!(policy["staged_read"][0], "/staged/read");
                assert_eq!(policy["staged_write"][0], "/staged/write");
                assert_eq!(policy["staged_allow"][0], "/staged/allow");
                assert_eq!(policy["staged_net_allow"][0], "staged.example.com");
                let allow_cmds = policy["allow_command"].as_array().unwrap();
                assert!(allow_cmds.iter().any(|v| v == "allowed-cmd"));
            }
            _ => panic!("expected Policy"),
        }
    }
}
