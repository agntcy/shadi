// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Client side of a sandbox's control socket.
//!
//! `shadictl --watch-policy` serves a local `AF_UNIX` control socket; the
//! server half lives with it. This is the caller's half, so everything outside
//! that process — `shadictl policy patch`, the shell's session commands, SHADI
//! Desktop — reaches a running session through one implementation instead of
//! restating the protocol.
//!
//! Sockets are named `shadi-ctl-<pid>.sock` for the PID-based default and
//! `shadi-ctl-<name>.sock` when the session was given a name, both inside
//! [`socket_dir`]. A caller connects, writes one JSON [`ControlMessage`] line,
//! and reads one JSON [`ControlResponse`] line back.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::policy_patch::{
    ControlMessage, ControlResponse, PolicyPatch, PolicyPatchResponse, ProcessResources,
};

/// Directory holding control sockets.
///
/// Discovery and path construction both go through this, so a session can
/// never be created somewhere the listing does not look.
#[cfg(unix)]
pub fn socket_dir() -> PathBuf {
    PathBuf::from(std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string()))
}

/// Directory holding control sockets (Windows).
#[cfg(windows)]
pub fn socket_dir() -> PathBuf {
    PathBuf::from(std::env::var("TEMP").unwrap_or_else(|_| ".".to_string()))
}

/// Resolve the default control socket path for a given PID.
pub fn default_socket_path(pid: u32) -> PathBuf {
    socket_dir().join(format!("shadi-ctl-{}.sock", pid))
}

/// Resolve a named control socket path.
///
/// Named sockets use `shadi-ctl-<name>.sock` instead of the PID-based path,
/// making them stable and human-addressable: any tool can connect by name
/// without needing to discover the PID.
///
/// Only alphanumeric characters, hyphens, and underscores survive in the name;
/// other characters become `-` to keep the filename safe.
pub fn named_socket_path(name: &str) -> PathBuf {
    socket_dir().join(format!("shadi-ctl-{}.sock", sanitize_session_name(name)))
}

/// Resolve the control socket path for a session name or socket path.
///
/// A value that looks like a path is used as-is; anything else is treated as a
/// session name and resolved via [`named_socket_path`].
pub fn resolve_session_socket(name_or_path: &str) -> PathBuf {
    if looks_like_path(name_or_path) {
        PathBuf::from(name_or_path)
    } else {
        named_socket_path(name_or_path)
    }
}

#[cfg(unix)]
fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.ends_with(".sock")
}

#[cfg(windows)]
fn looks_like_path(value: &str) -> bool {
    value.contains('\\') || value.contains('/') || value.ends_with(".sock")
}

/// Extract the human-readable session name from a socket path.
///
/// `shadi-ctl-myagent.sock` → `"myagent"`, and `shadi-ctl-12345.sock` →
/// `"12345"` for the PID-based fallback.
pub fn session_name_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("shadi-ctl-"))
        .unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("session"))
        .to_string()
}

/// Sanitize a session name: keep only alphanumerics, hyphens and underscores,
/// replace everything else with `-`, and truncate to 48 characters.
pub fn sanitize_session_name(name: &str) -> String {
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let slug = slug.trim_matches('-');
    slug.chars().take(48).collect()
}

/// Every control socket endpoint file in `dir`, reachable or not.
///
/// A socket file outliving its process is left on disk, so a path from here is
/// a candidate, not a live session — [`is_reachable`] settles that.
pub fn discover_sockets(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("shadi-ctl-") && name_str.ends_with(".sock") {
                found.push(entry.path());
            }
        }
    }
    found
}

/// Whether a socket answers, i.e. its session is still alive.
pub fn is_reachable(socket_path: &Path) -> bool {
    query_policy(socket_path).is_ok()
}

/// Pair every socket with whether it answers, touching nothing on disk.
///
/// This is what a repeatedly refreshed listing wants: deleting files as a side
/// effect of looking at them is a surprise when the caller is a UI.
pub fn classify_sockets(sockets: Vec<PathBuf>) -> Vec<(PathBuf, bool)> {
    sockets
        .into_iter()
        .map(|sock| {
            let reachable = is_reachable(&sock);
            (sock, reachable)
        })
        .collect()
}

/// Return the sockets that answer, deleting the endpoint files that do not.
///
/// Prefer [`classify_sockets`] unless the caller genuinely wants the cleanup.
pub fn prune_unreachable(sockets: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut live = Vec::new();
    for sock in sockets {
        if is_reachable(&sock) {
            live.push(sock);
        } else {
            let _ = std::fs::remove_file(&sock);
        }
    }
    live
}

/// Send a patch to a running control endpoint and return the response.
pub fn send_patch(
    socket_path: &Path,
    patch: &PolicyPatch,
) -> Result<PolicyPatchResponse, String> {
    match send_message(socket_path, &ControlMessage::Patch(patch.clone()))? {
        ControlResponse::PatchResult(r) => Ok(r),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected response type".to_string()),
    }
}

/// Query the current effective policy from a running control endpoint.
pub fn query_policy(socket_path: &Path) -> Result<serde_json::Value, String> {
    match send_message(socket_path, &ControlMessage::QueryPolicy)? {
        ControlResponse::Policy { policy } => Ok(policy),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected response type".to_string()),
    }
}

/// Ask a session to terminate its sandboxed child.
pub fn send_terminate(socket_path: &Path) -> Result<String, String> {
    match send_message(socket_path, &ControlMessage::Terminate)? {
        ControlResponse::Ack { message } => Ok(message),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected response type".to_string()),
    }
}

/// Query resource usage of the sandboxed child process.
pub fn query_resources(socket_path: &Path) -> Result<ProcessResources, String> {
    match send_message(socket_path, &ControlMessage::QueryResources)? {
        ControlResponse::Resources(r) => Ok(r),
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
    let payload = format!("{}\n", json);
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("failed to write: {}", e))?;
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

    #[test]
    fn default_socket_path_contains_pid() {
        let path = default_socket_path(42);
        let name = path.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "shadi-ctl-42.sock");
        assert_eq!(path.parent().unwrap(), socket_dir());
    }

    #[test]
    fn named_socket_path_slugs_unsafe_characters() {
        let path = named_socket_path("my agent/../v2");
        let name = path.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "shadi-ctl-my-agent----v2.sock");
        assert!(!name.contains('/'));
    }

    #[test]
    fn sanitize_session_name_trims_and_truncates() {
        assert_eq!(sanitize_session_name("--edgy--"), "edgy");
        assert_eq!(sanitize_session_name("a/b c"), "a-b-c");
        assert_eq!(sanitize_session_name(&"x".repeat(60)).len(), 48);
    }

    #[test]
    fn session_name_round_trips_through_the_socket_path() {
        for name in ["myagent", "12345", "with-dash", "with_underscore"] {
            assert_eq!(session_name_from_path(&named_socket_path(name)), name);
        }
    }

    #[test]
    fn session_name_falls_back_for_unrelated_paths() {
        assert_eq!(session_name_from_path(Path::new("/tmp/other.sock")), "other");
        assert_eq!(session_name_from_path(Path::new("/")), "session");
    }

    #[test]
    fn resolve_session_socket_distinguishes_names_from_paths() {
        let by_name = resolve_session_socket("myagent");
        assert_eq!(by_name, named_socket_path("myagent"));

        let explicit = resolve_session_socket("relative.sock");
        assert_eq!(explicit, PathBuf::from("relative.sock"));
    }

    #[test]
    fn discover_sockets_matches_only_control_endpoints() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["shadi-ctl-1.sock", "shadi-ctl-agent.sock"] {
            std::fs::write(dir.path().join(name), b"").expect("write");
        }
        for name in ["shadi-ctl-1.txt", "other.sock", "shadi-1.sock"] {
            std::fs::write(dir.path().join(name), b"").expect("write");
        }

        let mut found: Vec<String> = discover_sockets(dir.path())
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        found.sort();
        assert_eq!(found, vec!["shadi-ctl-1.sock", "shadi-ctl-agent.sock"]);
    }

    #[test]
    fn discover_sockets_on_a_missing_directory_is_empty() {
        assert!(discover_sockets(Path::new("/nonexistent-shadi-control-dir")).is_empty());
    }

    #[test]
    fn unreachable_sockets_are_pruned_but_classification_leaves_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dead = dir.path().join("shadi-ctl-dead.sock");
        std::fs::write(&dead, b"").expect("write");

        // Not a live listener, so it cannot answer.
        let classified = classify_sockets(vec![dead.clone()]);
        assert_eq!(classified, vec![(dead.clone(), false)]);
        assert!(dead.exists(), "classify must not delete anything");

        let live = prune_unreachable(vec![dead.clone()]);
        assert!(live.is_empty());
        assert!(!dead.exists(), "prune must remove the stale endpoint");
    }

    #[test]
    fn client_calls_against_a_dead_socket_error_rather_than_panic() {
        let missing = Path::new("/nonexistent-shadi-control-dir/shadi-ctl-x.sock");
        assert!(query_policy(missing).is_err());
        assert!(query_resources(missing).is_err());
        assert!(send_terminate(missing).is_err());
        assert!(send_patch(missing, &PolicyPatch::default()).is_err());
        assert!(!is_reachable(missing));
    }
}
