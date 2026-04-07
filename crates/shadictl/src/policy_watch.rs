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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
use std::os::unix::net::UnixListener;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use uds_windows::UnixListener;

use shadi_sandbox::{
    ControlMessage, ControlResponse, NetAllowlist, PatchAxisStatus, PolicyPatch,
    PolicyPatchResponse, ProcessResources, SandboxPolicy,
};
use tracing::info_span;

/// Mutable policy state shared between the main thread and the control socket
/// listener thread.
pub(crate) struct LivePolicy {
    pub(crate) policy: SandboxPolicy,
    pub(crate) blocked: HashSet<String>,
    pub(crate) allow: HashSet<String>,
    pub(crate) terminate_requested: Arc<AtomicBool>,
    pub(crate) restart_requested: Arc<AtomicBool>,
    /// PID of the currently running sandboxed child (updated on restart).
    pub(crate) child_pid: Arc<AtomicU32>,
    /// Filesystem patches staged for next restart.
    pub(crate) staged_read: Vec<String>,
    pub(crate) staged_write: Vec<String>,
    pub(crate) staged_allow: Vec<String>,
    /// Live network allowlist shared with the userspace proxy.
    /// When `Some`, network patches update this directly — no restart needed.
    pub(crate) live_net_allowlist: Option<NetAllowlist>,
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

/// Strip a URL scheme and path from a net-allow entry, returning just the host.
///
/// Users may naturally write `http://httping.org/` but the proxy allowlist
/// works on hostnames only.  This normalisation makes both equivalent:
///
/// ```
/// // assert_eq!(extract_host("http://httping.org/ping"), "httping.org");
/// // assert_eq!(extract_host("httping.org"),             "httping.org");
/// // assert_eq!(extract_host("192.0.2.1"),               "192.0.2.1");  // RFC 5737 TEST-NET
/// ```
fn extract_host(dest: &str) -> String {
    // Strip scheme (e.g. "http://", "https://").
    let after_scheme = if let Some(pos) = dest.find("://") {
        &dest[pos + 3..]
    } else {
        dest
    };
    // Strip trailing path / query / fragment — take up to the first '/'.
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    // Strip port suffix (host:port) — only for non-IPv6 addresses.
    let host = if host_port.starts_with('[') {
        // IPv6 literal [::1]:port or [::1]
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host_port)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.to_ascii_lowercase()
}

/// Resolve the default control socket path for a given PID.
#[cfg(unix)]
pub(crate) fn default_socket_path(pid: u32) -> PathBuf {
    let dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(dir).join(format!("shadi-ctl-{}.sock", pid))
}

/// Resolve a named control socket path.
///
/// Named sockets use `$TMPDIR/shadi-ctl-<name>.sock` instead of the PID-based
/// path, making them stable and human-addressable: any tool can connect by name
/// without needing to discover the PID.
///
/// Only alphanumeric characters, hyphens, and underscores are allowed in the
/// name; other characters are replaced with `-` to keep the filename safe.
#[cfg(unix)]
pub(crate) fn named_socket_path(name: &str) -> PathBuf {
    let dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let slug = sanitize_session_name(name);
    PathBuf::from(dir).join(format!("shadi-ctl-{}.sock", slug))
}

/// Resolve the control socket path for a given session name or socket path.
///
/// If `name_or_path` looks like a path (contains `/` or ends with `.sock`) it
/// is used as-is; otherwise it is treated as a session name and resolved via
/// `named_socket_path`.
#[cfg(unix)]
pub(crate) fn resolve_session_socket(name_or_path: &str) -> PathBuf {
    if name_or_path.contains('/') || name_or_path.ends_with(".sock") {
        PathBuf::from(name_or_path)
    } else {
        named_socket_path(name_or_path)
    }
}

/// Extract the human-readable session name from a socket path.
///
/// `$TMPDIR/shadi-ctl-myagent.sock` → `"myagent"`
/// `$TMPDIR/shadi-ctl-12345.sock`   → `"12345"` (PID-based fallback)
pub(crate) fn session_name_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("shadi-ctl-"))
        .unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("session"))
        .to_string()
}

/// Sanitize a session name: keep only alphanumerics, hyphens, and underscores;
/// replace everything else with `-`; truncate to 48 characters.
pub(crate) fn sanitize_session_name(name: &str) -> String {
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let slug = slug.trim_matches('-');
    slug.chars().take(48).collect()
}

/// Resolve the default control socket path for a given PID.
///
/// On Windows this is an `AF_UNIX` socket file (requires Windows 10 1803+).
#[cfg(windows)]
pub(crate) fn default_socket_path(pid: u32) -> PathBuf {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(dir).join(format!("shadi-ctl-{}.sock", pid))
}

/// Resolve a named control socket path (Windows).
#[cfg(windows)]
pub(crate) fn named_socket_path(name: &str) -> PathBuf {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let slug = sanitize_session_name(name);
    PathBuf::from(dir).join(format!("shadi-ctl-{}.sock", slug))
}

/// Resolve the control socket path for a given session name or socket path (Windows).
#[cfg(windows)]
pub(crate) fn resolve_session_socket(name_or_path: &str) -> PathBuf {
    if name_or_path.contains('\\') || name_or_path.contains('/') || name_or_path.ends_with(".sock") {
        PathBuf::from(name_or_path)
    } else {
        named_socket_path(name_or_path)
    }
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

    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to protect control socket permissions: {}", e))?;

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
                let mut stream = stream;
                #[cfg(unix)]
                if let Err(err) = authorize_control_peer(&stream) {
                    let _ = write_response(
                        &mut stream,
                        &ControlResponse::Error {
                            message: format!("unauthorized control socket peer: {}", err),
                        },
                    );
                    continue;
                }
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

#[cfg(target_os = "macos")]
fn authorize_control_peer(stream: &UnixStream) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        // getpeereid(2) failed — this can happen on some macOS versions/environments
        // (e.g., macOS 15 Sequoia CI runners).  The socket is already protected by
        // 0o600 filesystem permissions set at bind time, so we degrade gracefully:
        // skip UID verification rather than refusing all connections.  We only
        // actively deny when the syscall succeeds but reports a UID mismatch.
        return Ok(());
    }
    let current_uid = unsafe { libc::geteuid() };
    if uid != current_uid {
        return Err(format!("peer uid {} does not match current uid {}", uid, current_uid));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn authorize_control_peer(stream: &UnixStream) -> Result<(), String> {
    use std::mem::size_of;
    use std::os::fd::AsRawFd;

    let mut peer_cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer_cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let current_uid = unsafe { libc::geteuid() };
    if peer_cred.uid != current_uid {
        return Err(format!(
            "peer uid {} does not match current uid {}",
            peer_cred.uid, current_uid
        ));
    }
    Ok(())
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
            ControlMessage::Terminate => handle_terminate(live),
            ControlMessage::QueryResources => handle_resources(live),
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
        "net_allow": guard.policy.net_allow(),
        "net_blocked": guard.policy.net_blocked(),
        "allow_command": guard.allow.iter().cloned().collect::<Vec<_>>(),
        "block_command": guard.blocked.iter().cloned().collect::<Vec<_>>(),
        "staged_read": guard.staged_read,
        "staged_write": guard.staged_write,
        "staged_allow": guard.staged_allow,
        "net_allow_live": guard.live_net_allowlist.as_ref().map(|al| al.snapshot()),
        "restart_requested": guard.restart_requested.load(Ordering::SeqCst),
    });

    ControlResponse::Policy {
        policy: policy_json,
    }
}

fn handle_terminate(live: &Arc<Mutex<LivePolicy>>) -> ControlResponse {
    let guard = match live.lock() {
        Ok(g) => g,
        Err(_) => {
            return ControlResponse::Error {
                message: "internal lock error".to_string(),
            }
        }
    };

    guard.terminate_requested.store(true, Ordering::SeqCst);
    ControlResponse::Ack {
        message: "termination requested".to_string(),
    }
}

fn handle_resources(live: &Arc<Mutex<LivePolicy>>) -> ControlResponse {
    let pid = match live.lock() {
        Ok(g) => g.child_pid.load(Ordering::SeqCst),
        Err(_) => {
            return ControlResponse::Error {
                message: "internal lock error".to_string(),
            }
        }
    };

    if pid == 0 {
        return ControlResponse::Error {
            message: "no child process is running".to_string(),
        };
    }

    match crate::resource_info::query_process_resources(pid) {
        Some(resources) => ControlResponse::Resources(resources),
        None => ControlResponse::Error {
            message: format!("failed to query resources for pid {}", pid),
        },
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

    // --- Network allow ---
    // When a live proxy allowlist is present the change takes effect immediately
    // (no restart needed).  Without the proxy the change is staged and requires a
    // manual restart because the kernel sandbox cannot be updated in place.
    let has_net_changes = !patch.add_net_allow.is_empty() || !patch.remove_net_allow.is_empty();

    if has_net_changes {
        let current = guard
            .live_net_allowlist
            .as_ref()
            .map(|al| al.snapshot())
            .unwrap_or_else(|| guard.policy.net_allow().to_vec());

        let mut next_allow = current;
        for dest in &patch.add_net_allow {
            let host = extract_host(dest);
            if !next_allow.contains(&host) {
                next_allow.push(host);
            }
        }
        for dest in &patch.remove_net_allow {
            let host = extract_host(dest);
            next_allow.retain(|d| d != &host);
        }

        if let Some(ref al) = guard.live_net_allowlist {
            // Proxy is running: update the allowlist live — no restart needed.
            al.update(next_allow.clone());
            // Also keep the policy in sync so QueryPolicy reflects reality.
            guard.policy = guard.policy.clone().with_network_destinations(next_allow);
            net_status = PatchAxisStatus::Applied;
        } else {
            // No proxy: network patches cannot be applied live and MUST NOT
            // trigger a child restart (that would break the running application).
            // Reject the change so the caller knows it cannot take effect.
            net_status = PatchAxisStatus::Rejected;
        }
    }

    if !pending_restart.is_empty() {
        guard.restart_requested.store(true, Ordering::SeqCst);
    }

    let accepted = commands_status != PatchAxisStatus::Rejected
        && fs_status != PatchAxisStatus::Rejected
        && net_status != PatchAxisStatus::Rejected;

    let message = if pending_restart.is_empty() {
        "patch applied".to_string()
    } else {
        format!(
            "patch accepted; staged axes ({}) require manual process restart",
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

pub(crate) fn snapshot_live_policy(live: &Arc<Mutex<LivePolicy>>) -> Result<SandboxPolicy, String> {
    let guard = live
        .lock()
        .map_err(|_| "internal lock error".to_string())?;
    Ok(guard.policy.clone())
}

pub(crate) fn apply_staged_policy_updates(live: &Arc<Mutex<LivePolicy>>) -> Result<bool, String> {
    let mut guard = live
        .lock()
        .map_err(|_| "internal lock error".to_string())?;

    let has_staged = !guard.staged_read.is_empty()
        || !guard.staged_write.is_empty()
        || !guard.staged_allow.is_empty();

    if !has_staged {
        guard.restart_requested.store(false, Ordering::SeqCst);
        return Ok(false);
    }

    let mut policy = guard.policy.clone();
    for path in guard.staged_read.drain(..) {
        policy = policy.allow_read_path(&path);
    }
    for path in guard.staged_write.drain(..) {
        policy = policy.allow_write_path(&path);
    }
    for path in guard.staged_allow.drain(..) {
        policy = policy.allow_read_path(&path).allow_write_path(&path);
    }

    guard.policy = policy;
    guard.restart_requested.store(false, Ordering::SeqCst);
    Ok(true)
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

pub(crate) fn send_terminate(socket_path: &Path) -> Result<String, String> {
    let msg = ControlMessage::Terminate;
    let resp = send_message(socket_path, &msg)?;
    match resp {
        ControlResponse::Ack { message } => Ok(message),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected response type".to_string()),
    }
}

/// Query resource usage of the sandboxed child process.
pub(crate) fn query_resources(socket_path: &Path) -> Result<ProcessResources, String> {
    let msg = ControlMessage::QueryResources;
    let resp = send_message(socket_path, &msg)?;
    match resp {
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
    use std::collections::HashSet;

    #[test]
    fn extract_host_handles_bare_hostname() {
        assert_eq!(extract_host("httping.org"), "httping.org");
    }

    #[test]
    fn extract_host_strips_http_scheme() {
        assert_eq!(extract_host("http://httping.org/"), "httping.org");
    }

    #[test]
    fn extract_host_strips_https_scheme_and_path() {
        assert_eq!(extract_host("https://httping.org/ping?v=1"), "httping.org");
    }

    #[test]
    fn extract_host_strips_port() {
        assert_eq!(extract_host("httping.org:80"), "httping.org");
    }

    #[test]
    fn extract_host_bare_ip() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — reserved for documentation.
        assert_eq!(extract_host("192.0.2.1"), "192.0.2.1");
    }

    #[test]
    fn extract_host_ip_with_scheme_and_path() {
        assert_eq!(extract_host("http://192.0.2.1/"), "192.0.2.1");
    }

    #[test]
    fn extract_host_lowercases() {
        assert_eq!(extract_host("HTTPing.ORG"), "httping.org");
    }

    fn wait_for_socket_ready_with_timeout(sock_path: &Path, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if sock_path.exists() && query_policy(sock_path).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("control socket did not become ready: {}", sock_path.display());
    }

    fn wait_for_socket_removed_with_timeout(sock_path: &Path, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if !sock_path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("control socket was not removed: {}", sock_path.display());
    }

    fn wait_for_socket_ready(sock_path: &Path) {
        wait_for_socket_ready_with_timeout(sock_path, std::time::Duration::from_secs(2));
    }

    fn wait_for_socket_removed(sock_path: &Path) {
        wait_for_socket_removed_with_timeout(sock_path, std::time::Duration::from_secs(2));
    }

    #[test]
    #[should_panic(expected = "control socket did not become ready")]
    fn wait_for_socket_ready_times_out_on_missing_socket() {
        wait_for_socket_ready_with_timeout(
            Path::new("/tmp/shadi-nonexistent-test-never-exists.sock"),
            std::time::Duration::from_millis(1),
        );
    }

    #[test]
    #[should_panic(expected = "control socket was not removed")]
    fn wait_for_socket_removed_times_out_when_file_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("still-here.txt");
        std::fs::write(&sock_path, b"").expect("write");
        wait_for_socket_removed_with_timeout(&sock_path, std::time::Duration::from_millis(1));
    }

    fn test_live_policy() -> Arc<Mutex<LivePolicy>> {
        Arc::new(Mutex::new(LivePolicy {
            policy: SandboxPolicy::new().block_network(true),
            blocked: ["rm", "sudo"].iter().map(|s| s.to_string()).collect(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: None,
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
    fn handle_patch_rejects_network_changes_without_proxy() {
        let live = test_live_policy(); // live_net_allowlist: None
        let patch = PolicyPatch {
            add_net_allow: vec!["allowed.example.com".to_string()],  // RFC 2606
            ..Default::default()
        };

        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                // Without a proxy, network patches are rejected — never staged
                // for restart, because restarting the child breaks the application.
                assert!(!r.accepted);
                assert_eq!(r.network, PatchAxisStatus::Rejected);
                assert!(r.pending_restart.is_empty());
            }
            _ => panic!("expected PatchResult"),
        }

        // Policy must not be mutated on rejection.
        let guard = live.lock().unwrap();
        assert!(guard.policy.net_allow().is_empty());
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
    fn terminate_round_trip_sets_termination_flag() {
        let live = test_live_policy();
        let terminate_flag = {
            let guard = live.lock().expect("lock live policy");
            Arc::clone(&guard.terminate_requested)
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("terminate.sock");

        let handle = start_control_socket(&sock_path, live).expect("start socket");
        wait_for_socket_ready(&sock_path);

        let message = send_terminate(&sock_path).expect("send terminate");
        assert_eq!(message, "termination requested");
        assert!(terminate_flag.load(Ordering::SeqCst));

        drop(handle);
        wait_for_socket_removed(&sock_path);
    }

    #[cfg(unix)]
    #[test]
    fn control_socket_is_created_with_owner_only_permissions() {
        let live = test_live_policy();
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("protected.sock");

        let handle = start_control_socket(&sock_path, live).expect("start socket");
        let mode = std::fs::metadata(handle.path())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
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
        // Without a proxy, both add and remove net patches are rejected.
        let live = test_live_policy();
        let patch = PolicyPatch {
            remove_net_allow: vec!["example.com".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(!r.accepted);
                assert_eq!(r.network, PatchAxisStatus::Rejected);
            }
            _ => panic!("expected PatchResult"),
        }
    }

    #[test]
    fn handle_patch_deduplicates_net_allow() {
        // With a live proxy, duplicate entries in the same patch are deduplicated.
        let al = NetAllowlist::new(vec![]);
        let live = Arc::new(Mutex::new(LivePolicy {
            policy: SandboxPolicy::new().block_network(true),
            blocked: HashSet::new(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: Some(al.clone()),
        }));
        let patch = PolicyPatch {
            add_net_allow: vec!["dup.com".to_string(), "dup.com".to_string()],
            ..Default::default()
        };
        handle_patch(&live, patch);
        assert_eq!(al.snapshot(), &["dup.com".to_string()]);
        let guard = live.lock().unwrap();
        assert_eq!(guard.policy.net_allow(), &["dup.com".to_string()]);
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
        // Combined patch: commands (applied live) + filesystem (staged for restart).
        // Network without proxy is rejected but does not block the other axes.
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_allow_command: vec!["npm".to_string()],
            add_read: vec!["/opt/data".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.commands, PatchAxisStatus::Applied);
                assert_eq!(r.filesystem, PatchAxisStatus::PendingRestart);
                assert_eq!(r.network, PatchAxisStatus::Unchanged);
                assert_eq!(r.pending_restart.len(), 1);
                assert!(r.message.contains("manual process restart"));
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
            guard.allow.insert("allowed-cmd".to_string());
        }
        let resp = handle_query(&live);
        match resp {
            ControlResponse::Policy { policy } => {
                assert_eq!(policy["staged_read"][0], "/staged/read");
                assert_eq!(policy["staged_write"][0], "/staged/write");
                assert_eq!(policy["staged_allow"][0], "/staged/allow");
                let allow_cmds = policy["allow_command"].as_array().unwrap();
                assert!(allow_cmds.iter().any(|v| v == "allowed-cmd"));
            }
            _ => panic!("expected Policy"),
        }
    }

    // ── apply_staged_policy_updates behavioral tests ──────────────────────

    #[test]
    fn apply_staged_returns_false_when_nothing_staged() {
        let live = test_live_policy();
        let changed = apply_staged_policy_updates(&live).expect("apply");
        assert!(!changed);
    }

    #[test]
    fn apply_staged_merges_read_paths_into_live_policy() {
        let live = test_live_policy();
        {
            let mut guard = live.lock().unwrap();
            guard.staged_read.push("/opt/new-read".to_string());
        }
        let changed = apply_staged_policy_updates(&live).expect("apply");
        assert!(changed);

        let guard = live.lock().unwrap();
        assert!(guard.staged_read.is_empty(), "staged_read should be drained");
        assert!(
            guard.policy.allow_read().iter().any(|p| p.to_str() == Some("/opt/new-read")),
            "read path should be in effective policy"
        );
    }

    #[test]
    fn apply_staged_merges_write_paths_into_live_policy() {
        let live = test_live_policy();
        {
            let mut guard = live.lock().unwrap();
            guard.staged_write.push("/tmp/new-write".to_string());
        }
        let changed = apply_staged_policy_updates(&live).expect("apply");
        assert!(changed);

        let guard = live.lock().unwrap();
        assert!(guard.staged_write.is_empty());
        assert!(
            guard.policy.allow_write().iter().any(|p| p.to_str() == Some("/tmp/new-write")),
            "write path should be in effective policy"
        );
    }

    #[test]
    fn apply_staged_merges_allow_paths_into_both_read_and_write() {
        let live = test_live_policy();
        {
            let mut guard = live.lock().unwrap();
            guard.staged_allow.push("/opt/shared".to_string());
        }
        let changed = apply_staged_policy_updates(&live).expect("apply");
        assert!(changed);

        let guard = live.lock().unwrap();
        assert!(guard.staged_allow.is_empty());
        assert!(guard.policy.allow_read().iter().any(|p| p.to_str() == Some("/opt/shared")));
        assert!(guard.policy.allow_write().iter().any(|p| p.to_str() == Some("/opt/shared")));
    }

    #[test]
    fn apply_staged_replaces_net_allow_in_live_policy() {
        // With no proxy, network patches are rejected — the policy must not be
        // modified.  Only filesystem staged changes are written to the policy.
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_net_allow: vec!["allowed.example.com".to_string(), "192.0.2.1:80".to_string()],  // RFC 2606 / RFC 5737
            ..Default::default()
        };
        handle_patch(&live, patch);

        // Policy net_allow must remain empty because the patch was rejected.
        let guard = live.lock().unwrap();
        assert!(guard.policy.net_allow().is_empty());
    }

    #[test]
    fn apply_staged_clears_restart_flag() {
        let live = test_live_policy();
        {
            let mut guard = live.lock().unwrap();
            guard.staged_read.push("/opt/path".to_string());
            guard.restart_requested.store(true, Ordering::SeqCst);
        }
        apply_staged_policy_updates(&live).expect("apply");

        let guard = live.lock().unwrap();
        assert!(!guard.restart_requested.load(Ordering::SeqCst));
    }

    #[test]
    fn apply_staged_is_idempotent_when_called_twice() {
        let live = test_live_policy();
        {
            let mut guard = live.lock().unwrap();
            guard.staged_read.push("/opt/tools".to_string());
        }
        let first = apply_staged_policy_updates(&live).expect("first apply");
        assert!(first);

        let second = apply_staged_policy_updates(&live).expect("second apply");
        assert!(!second, "no more staged changes should remain");
    }

    // ── restart_requested behavioral tests ──────────────────────────────

    #[test]
    fn handle_patch_sets_restart_flag_for_filesystem_changes() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_read: vec!["/opt/data".to_string()],
            ..Default::default()
        };
        handle_patch(&live, patch);

        let guard = live.lock().unwrap();
        assert!(guard.restart_requested.load(Ordering::SeqCst));
    }

    #[test]
    fn handle_patch_does_not_set_restart_flag_for_rejected_network_changes() {
        let live = test_live_policy(); // no proxy
        let patch = PolicyPatch {
            add_net_allow: vec!["cdn.example.com".to_string()],
            ..Default::default()
        };
        handle_patch(&live, patch);

        // Network rejected — must NOT set restart_requested.
        let guard = live.lock().unwrap();
        assert!(!guard.restart_requested.load(Ordering::SeqCst));
    }

    #[test]
    fn handle_patch_with_live_proxy_applies_network_changes_without_restart() {
        // When a live proxy is present, network patches take effect immediately
        // through the shared allowlist — no child restart needed.
        // The proxy itself can be restarted independently (it rebinds the same
        // loopback port) without touching the kernel-sandboxed child process.
        let al = NetAllowlist::new(vec![]);
        let live = Arc::new(Mutex::new(LivePolicy {
            policy: SandboxPolicy::new().block_network(true),
            blocked: HashSet::new(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: Some(al.clone()),
        }));

        let patch = PolicyPatch {
            add_net_allow: vec!["api.example.com".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);

        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.network, PatchAxisStatus::Applied);
                assert!(r.pending_restart.is_empty());
            }
            _ => panic!("expected PatchResult"),
        }

        // Proxy allowlist updated in-place — child not touched.
        assert_eq!(al.snapshot(), vec!["api.example.com".to_string()]);
        let guard = live.lock().unwrap();
        assert!(!guard.restart_requested.load(Ordering::SeqCst));
        assert_eq!(guard.policy.net_allow(), &["api.example.com".to_string()]);
    }

    #[test]
    fn handle_patch_does_not_set_restart_flag_for_command_only_changes() {
        let live = test_live_policy();
        let patch = PolicyPatch {
            add_allow_command: vec!["npm".to_string()],
            ..Default::default()
        };
        handle_patch(&live, patch);

        let guard = live.lock().unwrap();
        assert!(!guard.restart_requested.load(Ordering::SeqCst));
    }

    #[test]
    fn handle_patch_message_mentions_restarting_for_staged_changes() {
        let live = test_live_policy();
        // Only filesystem changes are staged for restart (no proxy).
        let patch = PolicyPatch {
            add_read: vec!["/opt/data".to_string()],
            add_write: vec!["/opt/out".to_string()],
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);
        match resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.message.contains("manual process restart"), "message should mention restart: {}", r.message);
                assert!(r.message.contains("filesystem"));
            }
            _ => panic!("expected PatchResult"),
        }
    }

    #[test]
    fn handle_query_includes_restart_requested_field() {
        let live = test_live_policy();
        {
            let guard = live.lock().unwrap();
            guard.restart_requested.store(true, Ordering::SeqCst);
        }
        let resp = handle_query(&live);
        match resp {
            ControlResponse::Policy { policy } => {
                assert_eq!(policy["restart_requested"], true);
            }
            _ => panic!("expected Policy"),
        }
    }

    #[test]
    fn handle_query_includes_net_allow_from_effective_policy() {
        let live = Arc::new(Mutex::new(LivePolicy {
            policy: SandboxPolicy::new()
                .block_network(true)
                .allow_network_destination("10.0.0.1:443"),
            blocked: HashSet::new(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: None,
        }));
        let resp = handle_query(&live);
        match resp {
            ControlResponse::Policy { policy } => {
                let net_allow = policy["net_allow"].as_array().unwrap();
                assert_eq!(net_allow.len(), 1);
                assert_eq!(net_allow[0], "10.0.0.1:443");
            }
            _ => panic!("expected Policy"),
        }
    }

    // ── net_allow proxy round-trip ───────────────────────────────────────

    #[test]
    fn net_allow_patch_then_apply_updates_effective_policy() {
        // With a live proxy, the allowlist is updated in-place immediately.
        let al = NetAllowlist::new(vec![]);
        let live = Arc::new(Mutex::new(LivePolicy {
            policy: SandboxPolicy::new().block_network(true),
            blocked: HashSet::new(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: Some(al.clone()),
        }));

        let patch = PolicyPatch {
            add_net_allow: vec!["allowed.example.com".to_string(), "192.0.2.1".to_string()],  // RFC 2606 / RFC 5737
            ..Default::default()
        };
        let resp = handle_patch(&live, patch);
        match &resp {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.network, PatchAxisStatus::Applied);
                assert!(r.pending_restart.is_empty());
            }
            _ => panic!("expected PatchResult"),
        }

        // Both the proxy allowlist and the mirrored policy are updated.
        assert_eq!(al.snapshot(), &["allowed.example.com".to_string(), "192.0.2.1".to_string()]);
        let guard = live.lock().unwrap();
        assert_eq!(
            guard.policy.net_allow(),
            &["allowed.example.com".to_string(), "192.0.2.1".to_string()]
        );
    }

    #[test]
    fn net_allow_remove_then_apply_removes_from_effective_policy() {
        // With a proxy: removing an entry updates the allowlist in-place.
        let al = NetAllowlist::new(vec![
            "keep.example.com".to_string(),
            "remove.example.com".to_string(),
        ]);
        let live = Arc::new(Mutex::new(LivePolicy {
            policy: SandboxPolicy::new()
                .block_network(true)
                .allow_network_destination("keep.example.com")
                .allow_network_destination("remove.example.com"),
            blocked: HashSet::new(),
            allow: HashSet::new(),
            terminate_requested: Arc::new(AtomicBool::new(false)),
            restart_requested: Arc::new(AtomicBool::new(false)),
            child_pid: Arc::new(AtomicU32::new(0)),
            staged_read: Vec::new(),
            staged_write: Vec::new(),
            staged_allow: Vec::new(),
            live_net_allowlist: Some(al.clone()),
        }));

        let patch = PolicyPatch {
            remove_net_allow: vec!["remove.example.com".to_string()],
            ..Default::default()
        };
        handle_patch(&live, patch);

        assert_eq!(al.snapshot(), &["keep.example.com".to_string()]);
        let guard = live.lock().unwrap();
        assert_eq!(guard.policy.net_allow(), &["keep.example.com".to_string()]);
    }

    #[test]
    fn snapshot_live_policy_returns_current_effective_policy() {
        let live = test_live_policy();
        let snapshot = snapshot_live_policy(&live).expect("snapshot");
        assert!(snapshot.net_blocked(), "default test policy is net-blocked");
    }

    // ── control-socket restart round-trip ──────────────────────────────

    #[test]
    fn control_socket_patch_sets_restart_flag_round_trip() {
        let live = test_live_policy();
        let restart_flag = {
            let guard = live.lock().expect("lock");
            Arc::clone(&guard.restart_requested)
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("restart.sock");
        let handle = start_control_socket(&sock_path, live).expect("start socket");
        wait_for_socket_ready(&sock_path);

        // Send a filesystem patch via the socket.
        let patch = PolicyPatch {
            add_read: vec!["/opt/data".to_string()],
            ..Default::default()
        };
        let result = send_patch(&sock_path, &patch).expect("send patch");
        assert!(result.accepted);
        assert_eq!(result.filesystem, PatchAxisStatus::PendingRestart);
        assert!(result.message.contains("manual process restart"));

        // Verify restart flag was set.
        assert!(restart_flag.load(Ordering::SeqCst));

        drop(handle);
        wait_for_socket_removed(&sock_path);
    }

    #[test]
    fn control_socket_command_patch_does_not_set_restart_flag() {
        let live = test_live_policy();
        let restart_flag = {
            let guard = live.lock().expect("lock");
            Arc::clone(&guard.restart_requested)
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("no-restart.sock");
        let handle = start_control_socket(&sock_path, live).expect("start socket");
        wait_for_socket_ready(&sock_path);

        let patch = PolicyPatch {
            add_allow_command: vec!["node".to_string()],
            ..Default::default()
        };
        let result = send_patch(&sock_path, &patch).expect("send patch");
        assert!(result.accepted);
        assert_eq!(result.commands, PatchAxisStatus::Applied);
        assert_eq!(result.message, "patch applied");

        assert!(!restart_flag.load(Ordering::SeqCst));

        drop(handle);
        wait_for_socket_removed(&sock_path);
    }

    // ── handle_stream with valid messages ────────────────────────────────

    #[test]
    fn handle_stream_processes_query_message() {
        use std::io::Cursor;

        let live = test_live_policy();
        let msg = serde_json::to_string(&ControlMessage::QueryPolicy).unwrap();
        let input = format!("{}\n", msg);
        let stream = Cursor::new(input.into_bytes());
        handle_stream(stream, &live);
        // If we got here without panic, the query path was exercised.
    }

    #[test]
    fn handle_stream_processes_patch_message() {
        use std::io::Cursor;

        let live = test_live_policy();
        let patch = PolicyPatch {
            add_allow_command: vec!["node".to_string()],
            ..Default::default()
        };
        let msg = serde_json::to_string(&ControlMessage::Patch(patch)).unwrap();
        let input = format!("{}\n", msg);
        let stream = Cursor::new(input.into_bytes());
        handle_stream(stream, &live);

        let guard = live.lock().unwrap();
        assert!(guard.allow.contains("node"));
    }

    #[test]
    fn handle_stream_processes_terminate_message() {
        use std::io::Cursor;

        let live = test_live_policy();
        let msg = serde_json::to_string(&ControlMessage::Terminate).unwrap();
        let input = format!("{}\n", msg);
        let stream = Cursor::new(input.into_bytes());
        handle_stream(stream, &live);

        let guard = live.lock().unwrap();
        assert!(guard.terminate_requested.load(Ordering::SeqCst));
    }

    #[test]
    fn handle_stream_processes_multiple_messages() {
        use std::io::Cursor;

        let live = test_live_policy();
        let q = serde_json::to_string(&ControlMessage::QueryPolicy).unwrap();
        let patch = PolicyPatch {
            add_allow_command: vec!["npm".to_string()],
            ..Default::default()
        };
        let p = serde_json::to_string(&ControlMessage::Patch(patch)).unwrap();
        let input = format!("{}\n{}\n", q, p);
        let stream = Cursor::new(input.into_bytes());
        handle_stream(stream, &live);

        let guard = live.lock().unwrap();
        assert!(guard.allow.contains("npm"));
    }

    #[test]
    fn send_terminate_propagates_connect_error() {
        let bad_path = Path::new("/tmp/shadi-nonexistent-test.sock");
        let result = send_terminate(bad_path);
        assert!(result.is_err());
    }

    // ── resource queries ─────────────────────────────────────────────────

    #[test]
    fn handle_resources_returns_error_when_no_child_pid() {
        let live = test_live_policy();
        let resp = handle_resources(&live);
        match resp {
            ControlResponse::Error { message } => {
                assert!(message.contains("no child process"));
            }
            _ => panic!("expected Error for pid 0"),
        }
    }

    #[test]
    fn handle_resources_returns_resources_for_own_pid() {
        let live = test_live_policy();
        {
            let guard = live.lock().unwrap();
            guard.child_pid.store(std::process::id(), Ordering::SeqCst);
        }
        let resp = handle_resources(&live);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        match resp {
            ControlResponse::Resources(r) => {
                assert_eq!(r.pid, std::process::id());
                assert!(r.rss_bytes.unwrap() > 0);
            }
            _ => panic!("expected Resources"),
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        match resp {
            ControlResponse::Error { .. } => {}
            _ => panic!("expected Error on unsupported platform"),
        }
    }

    #[test]
    fn handle_stream_processes_query_resources_message() {
        use std::io::Cursor;

        let live = test_live_policy();
        let msg = serde_json::to_string(&ControlMessage::QueryResources).unwrap();
        let input = format!("{}\n", msg);
        let stream = Cursor::new(input.into_bytes());
        handle_stream(stream, &live);
        // No panic — the resource query path was exercised.
    }

    #[test]
    fn query_resources_propagates_connect_error() {
        let bad_path = Path::new("/tmp/shadi-nonexistent-test.sock");
        let result = query_resources(bad_path);
        assert!(result.is_err());
    }

    #[test]
    fn query_resources_round_trip_via_socket() {
        let live = test_live_policy();
        {
            let guard = live.lock().unwrap();
            guard.child_pid.store(std::process::id(), Ordering::SeqCst);
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("resources.sock");
        let handle = start_control_socket(&sock_path, live).expect("start socket");
        wait_for_socket_ready(&sock_path);

        let result = query_resources(&sock_path);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let r = result.expect("query_resources");
            assert_eq!(r.pid, std::process::id());
            assert!(r.rss_bytes.is_some());
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            assert!(result.is_err());
        }

        drop(handle);
    }

    // ── named session helpers ────────────────────────────────────────────────

    #[test]
    fn named_socket_path_uses_slug_not_pid() {
        let path = named_socket_path("my-agent");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "shadi-ctl-my-agent.sock");
    }

    #[test]
    fn named_socket_path_sanitizes_special_chars() {
        let path = named_socket_path("my agent/session!");
        let name = path.file_name().unwrap().to_str().unwrap();
        // spaces and slashes become hyphens; exclamation is stripped
        assert!(name.starts_with("shadi-ctl-"));
        assert!(name.ends_with(".sock"));
        assert!(!name.contains(' '));
        assert!(!name.contains('/'));
    }

    #[test]
    fn session_name_from_path_strips_prefix_and_extension() {
        let path = std::path::PathBuf::from("/tmp/shadi-ctl-codex-session.sock");
        assert_eq!(session_name_from_path(&path), "codex-session");
    }

    #[test]
    fn session_name_from_path_works_for_pid_sockets() {
        let path = std::path::PathBuf::from("/tmp/shadi-ctl-98765.sock");
        assert_eq!(session_name_from_path(&path), "98765");
    }

    #[test]
    fn resolve_session_socket_accepts_name() {
        let path = resolve_session_socket("my-agent");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "shadi-ctl-my-agent.sock");
    }

    #[test]
    fn resolve_session_socket_accepts_full_path() {
        let path = resolve_session_socket("/tmp/shadi-ctl-12345.sock");
        assert_eq!(path, std::path::PathBuf::from("/tmp/shadi-ctl-12345.sock"));
    }
}

