// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

pub mod control;
pub mod net_proxy;
pub mod policy;
pub mod policy_patch;
pub mod resolve;
mod platform;

pub use control::{read_control_line, ControlLine, CONTROL_LINE_MAX_BYTES};
pub use net_proxy::{
    normalize_net_allow, parse_http_proxy_request, parse_socks5_connect, parse_socks5_greeting,
    parse_socks5_request, HttpParseError, HttpProxyRequest, NetAllowlist, NetProxy, Socks5Connect,
    Socks5ParseError,
};

/// Render the Seatbelt profile text for `policy` without calling `sandbox_init`.
/// Used by the `seatbelt-profile` fuzz target.
#[cfg(target_os = "macos")]
pub fn seatbelt_profile_text(policy: &SandboxPolicy) -> Result<String, SandboxError> {
    platform::macos::build_profile(policy)
}
pub use policy::{PlatformSandboxProfile, ProfileDefaults, SandboxPolicy, SandboxProfile};
pub use resolve::{
    canonicalize_path, default_blocked_commands, describe_policy, is_command_blocked,
    resolve_policy, PolicyDescription, PolicyFileValues, PolicyOverrides, ResolvedPolicy,
};
pub use policy_patch::{
    apply_policy_patch, ControlMessage, ControlResponse, PatchAxisStatus,
    PatchState, PolicyPatch, PolicyPatchResponse, ProcessResources,
};
use std::process::{Command, ExitStatus};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;
use tracing::{field, info_span};

/// Set on a sandboxed child's environment by [`spawn_sandboxed`], `"1"` iff
/// the process is running under a SHADI sandbox at all.
///
/// Env vars are inherited by descendants automatically, so a grandchild
/// spawned by the sandboxed process (e.g. a coding-tool subprocess launched
/// by an agentbridge adapter) can observe this too — but it does not, on its
/// own, mean anything is actually restricted. Use [`sandbox_enforced`]
/// to check for a *meaningfully* restrictive policy, not just an active one.
pub const SANDBOX_ACTIVE_ENV: &str = "SHADI_SANDBOX_ACTIVE";

/// Set on a sandboxed child's environment by [`spawn_sandboxed`], `"1"` iff
/// the enclosing policy blocks network by default ([`SandboxPolicy::net_blocked`]).
pub const SANDBOX_NET_BLOCKED_ENV: &str = "SHADI_SANDBOX_NET_BLOCKED";

/// Whether the current process is running under a SHADI sandbox that blocks
/// network by default (exceptions carved out via `net_allow` are fine — the
/// point is default-deny, not zero connectivity).
///
/// Seatbelt (macOS), Landlock (Linux), and AppContainer + Job Objects
/// (Windows) sandboxes are all kernel-enforced and inherited by descendant
/// processes, so any subprocess spawned by a sandboxed process — including a
/// coding-tool subprocess an agentbridge adapter launches — is bound by the
/// same policy automatically. A remote-reachable listener (or any other
/// operation that executes attacker-influenceable input) should call this
/// before starting and refuse to run if it returns `false`, rather than
/// re-implementing policy enforcement itself.
///
/// The environment flags say SHADI launched this process; the kernel probe
/// ([`network_blocked_by_kernel`]) proves the network really is confined, so
/// exporting the flags by hand is not enough.
pub fn sandbox_enforced() -> bool {
    std::env::var(SANDBOX_ACTIVE_ENV).as_deref() == Ok("1")
        && std::env::var(SANDBOX_NET_BLOCKED_ENV).as_deref() == Ok("1")
        && network_blocked_by_kernel()
}

#[deprecated(note = "use `sandbox_enforced`, which also checks the kernel")]
pub fn sandbox_enforced_from_env() -> bool {
    sandbox_enforced()
}

/// TEST-NET-1 (RFC 5737) on the discard port: never a real peer, and never on
/// an allow-list.
const CONFINEMENT_PROBE: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9));

/// Whether the kernel refuses a connection to an address no policy allows.
///
/// A sandbox that blocks network by default fails `connect` with a permission
/// error (`EPERM` under Seatbelt, `EACCES` under Landlock, `WSAEACCES` in an
/// AppContainer). A timeout, an unreachable route or a connection all mean the
/// network is open.
pub fn network_blocked_by_kernel() -> bool {
    confinement_denied(&TcpStream::connect_timeout(
        &CONFINEMENT_PROBE,
        Duration::from_millis(300),
    ))
}

fn confinement_denied<T>(result: &std::io::Result<T>) -> bool {
    matches!(result, Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied)
}

pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    let program = command.get_program().to_string_lossy().to_string();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let cwd = command
        .get_current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let allowed_paths = policy.allow_read().len() + policy.allow_write().len();
    let network_mode = if policy.net_blocked() { "blocked" } else { "allowed" };

    let span = info_span!(
        "shadi.sandbox.spawn",
        command = %program,
        args = %args,
        cwd = %cwd,
        policy.allowed_paths = allowed_paths as i64,
        network.mode = %network_mode,
    );
    let _guard = span.enter();

    command.env(SANDBOX_ACTIVE_ENV, "1");
    command.env(
        SANDBOX_NET_BLOCKED_ENV,
        if policy.net_blocked() { "1" } else { "0" },
    );

    platform::spawn_sandboxed(command, policy)
}

pub struct SandboxedChild {
    inner: SandboxedChildInner,
}

enum SandboxedChildInner {
    Std(std::process::Child),
    #[cfg(target_os = "windows")]
    Windows(WindowsChild),
}

impl SandboxedChild {
    pub fn from_std(child: std::process::Child) -> Self {
        Self {
            inner: SandboxedChildInner::Std(child),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn from_windows(child: WindowsChild) -> Self {
        Self {
            inner: SandboxedChildInner::Windows(child),
        }
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let span = info_span!("shadi.sandbox.wait", pid = self.id(), exit.code = field::Empty);
        let _guard = span.enter();

        let status = match &mut self.inner {
            SandboxedChildInner::Std(child) => child.wait(),
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(child) => child.wait(),
        };

        if let Ok(ref status) = status {
            span.record("exit.code", status.code().unwrap_or(-1));
        }

        status
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match &mut self.inner {
            SandboxedChildInner::Std(child) => child.try_wait(),
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(child) => child.try_wait(),
        }
    }

    pub fn kill(&mut self) -> io::Result<()> {
        let span = info_span!("shadi.sandbox.kill", pid = self.id());
        let _guard = span.enter();

        match &mut self.inner {
            SandboxedChildInner::Std(child) => {
                // On macOS/Linux the sandboxed child runs in its own
                // process group (via setsid in pre_exec). Kill the entire
                // group so that grandchild processes are cleaned up too,
                // mirroring the Windows Job-object behaviour.
                #[cfg(unix)]
                {
                    let pid = child.id() as i32;
                    // killpg sends the signal to every process in the group.
                    // SAFETY: killpg with SIGKILL is always safe.
                    let rc = unsafe { libc::killpg(pid, libc::SIGKILL) };
                    if rc == 0 {
                        return Ok(());
                    }
                    // Fall back to single-process kill if killpg fails
                    // (e.g. the child didn't get a new process group in
                    // test/coverage mode).
                    child.kill()
                }
                #[cfg(not(unix))]
                child.kill()
            }
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(child) => child.kill(),
        }
    }

    pub fn id(&self) -> u32 {
        match &self.inner {
            SandboxedChildInner::Std(child) => child.id(),
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(child) => child.id(),
        }
    }

    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        match &mut self.inner {
            SandboxedChildInner::Std(child) => child.stdin.take(),
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(_) => None,
        }
    }

    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        match &mut self.inner {
            SandboxedChildInner::Std(child) => child.stdout.take(),
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(_) => None,
        }
    }

    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        match &mut self.inner {
            SandboxedChildInner::Std(child) => child.stderr.take(),
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(_) => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox not supported on this platform")]
    NotSupported,
    #[error("invalid sandbox configuration")]
    InvalidConfig,
    #[error("sandbox apply failed: {0}")]
    ApplyFailed(String),
    #[error("spawn failed: {0}")]
    SpawnFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    use std::os::windows::ffi::OsStrExt;

    #[cfg(unix)]
    #[test]
    fn kill_uses_killpg_when_child_is_process_group_leader() {
        use std::os::unix::process::CommandExt;
        // Spawn a child that calls setsid() in pre_exec so it becomes the
        // leader of its own process group. killpg(pid, SIGKILL) should then
        // succeed (rc == 0) and return Ok(()) without falling back to
        // child.kill(), exercising the `return Ok(())` branch.
        let child = unsafe {
            Command::new("sleep")
                .arg("30")
                .pre_exec(|| {
                    libc::setsid();
                    Ok(())
                })
                .spawn()
                .expect("spawn sleep in own session")
        };
        let mut wrapped = SandboxedChild::from_std(child);
        wrapped.kill().expect("killpg kill");
        let status = wrapped.wait().expect("wait");
        assert!(!status.success(), "killed process must not succeed");
    }

    #[test]
    fn sandbox_error_display_message() {
        let err = SandboxError::InvalidConfig;
        assert!(format!("{}", err).contains("invalid sandbox configuration"));
    }

    #[test]
    fn sandbox_error_apply_failed_message() {
        let err = SandboxError::ApplyFailed("boom".to_string());
        assert!(format!("{}", err).contains("sandbox apply failed"));
    }

    #[test]
    fn sandbox_error_not_supported_message() {
        let err = SandboxError::NotSupported;
        assert!(format!("{}", err).contains("sandbox not supported"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn spawn_sandboxed_runs_command() {
        let mut command = Command::new("/usr/bin/true");
        let policy = SandboxPolicy::new().allow_read_path("/usr/bin");
        let mut child = spawn_sandboxed(&mut command, &policy).expect("spawn");
        let _ = child.wait().expect("wait");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn spawn_sandboxed_propagates_sandbox_env_vars_to_child() {
        use std::process::Stdio;

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!("echo ${SANDBOX_ACTIVE_ENV} ${SANDBOX_NET_BLOCKED_ENV}"))
            .stdout(Stdio::piped());
        let policy = SandboxPolicy::new()
            .allow_read_path("/bin")
            .allow_read_path("/usr/bin")
            .block_network(true);
        let mut child = spawn_sandboxed(&mut command, &policy).expect("spawn");
        let stdout = child.take_stdout().expect("stdout piped");
        let output = std::io::read_to_string(stdout).expect("read child stdout");
        child.wait().expect("wait");
        assert_eq!(output.trim(), "1 1");
    }

    #[test]
    fn sandbox_enforced_needs_both_flags() {
        // These env vars are touched by no other test in this crate, so a single
        // sequential test needs no cross-test lock. Every case lacks a flag, so
        // the kernel probe is never reached and in-process sandboxing by other
        // tests cannot change the answer.
        std::env::remove_var(SANDBOX_ACTIVE_ENV);
        std::env::remove_var(SANDBOX_NET_BLOCKED_ENV);
        assert!(!sandbox_enforced(), "no sandbox env vars set");

        std::env::set_var(SANDBOX_ACTIVE_ENV, "1");
        assert!(
            !sandbox_enforced(),
            "active but permissive (network not blocked) must not count as enforced"
        );

        std::env::set_var(SANDBOX_NET_BLOCKED_ENV, "0");
        assert!(!sandbox_enforced());

        std::env::remove_var(SANDBOX_ACTIVE_ENV);
        std::env::set_var(SANDBOX_NET_BLOCKED_ENV, "1");
        assert!(
            !sandbox_enforced(),
            "net-blocked flag alone without the active flag must not count as enforced"
        );

        std::env::remove_var(SANDBOX_NET_BLOCKED_ENV);
    }

    #[test]
    fn only_a_permission_error_counts_as_confinement() {
        use std::io::{Error, ErrorKind};

        assert!(confinement_denied::<()>(&Err(Error::from(
            ErrorKind::PermissionDenied
        ))));
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionRefused,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::Other,
        ] {
            assert!(
                !confinement_denied::<()>(&Err(Error::from(kind))),
                "{kind:?}"
            );
        }
        assert!(
            !confinement_denied(&Ok(())),
            "a connection means the network is open"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandboxed_child_wraps_std_process() {
        let child = Command::new("/usr/bin/true").spawn().expect("spawn");
        let mut wrapped = SandboxedChild::from_std(child);
        assert!(wrapped.id() > 0);
        let status = wrapped.wait().expect("wait");
        assert!(status.success());
    }

    #[cfg(unix)]
    #[test]
    fn sandboxed_child_kill_stops_process() {
        let child = Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn");
        let mut wrapped = SandboxedChild::from_std(child);
        wrapped.kill().expect("kill");
        let _ = wrapped.wait().expect("wait");
    }

    #[cfg(unix)]
    #[test]
    fn sandboxed_child_try_wait_reports_running_then_exit() {
        let child = Command::new("/bin/sleep")
            .arg("1")
            .spawn()
            .expect("spawn");
        let mut wrapped = SandboxedChild::from_std(child);
        assert!(wrapped.try_wait().expect("try_wait").is_none());
        let _ = wrapped.wait().expect("wait");
    }

    #[cfg(unix)]
    #[test]
    fn sandboxed_child_exposes_piped_stdio_handles() {
        let child = Command::new("/bin/cat")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut wrapped = SandboxedChild::from_std(child);

        assert!(wrapped.take_stdin().is_some());
        assert!(wrapped.take_stdout().is_some());
        assert!(wrapped.take_stderr().is_some());

        wrapped.kill().expect("kill");
        let _ = wrapped.wait().expect("wait");
    }

    #[cfg(target_os = "windows")]
    fn to_wide(value: &std::path::Path) -> Vec<u16> {
        value.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    #[cfg(target_os = "windows")]
    fn open_process_handle(pid: u32, access: u32) -> windows_sys::Win32::Foundation::HANDLE {
        use windows_sys::Win32::System::Threading::OpenProcess;

        let handle = unsafe { OpenProcess(access, 0, pid) };
        assert!(!handle.is_null(), "OpenProcess should succeed");
        handle
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sandboxed_child_wraps_std_process_on_windows() {
        let child = Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .expect("spawn");
        let pid = child.id();

        let mut wrapped = SandboxedChild::from_std(child);
        assert_eq!(wrapped.id(), pid);

        let status = wrapped.wait().expect("wait");
        assert!(status.success());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sandboxed_child_kill_stops_std_process_on_windows() {
        let child = Command::new("cmd")
            .args(["/C", "ping", "-n", "6", "127.0.0.1", ">", "NUL"])
            .spawn()
            .expect("spawn");

        let mut wrapped = SandboxedChild::from_std(child);
        wrapped.kill().expect("kill");
        let _ = wrapped.wait().expect("wait");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sandboxed_child_wraps_windows_process_on_windows() {
        const PROCESS_QUERY_LIMITED_INFORMATION_ACCESS: u32 = 0x1000;
        const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

        let mut std_child = Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .expect("spawn");
        let process = open_process_handle(
            std_child.id(),
            PROCESS_QUERY_LIMITED_INFORMATION_ACCESS | SYNCHRONIZE_ACCESS,
        );

        let windows_child = WindowsChild::new(process, std::ptr::null_mut(), std_child.id(), Vec::new());
        let mut wrapped = SandboxedChild::from_windows(windows_child);

        assert_eq!(wrapped.id(), std_child.id());
        let status = wrapped.wait().expect("wait");
        assert!(status.success());

        let _ = std_child.wait().expect("wait std child");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sandboxed_windows_child_kill_stops_process_on_windows() {
        const PROCESS_QUERY_LIMITED_INFORMATION_ACCESS: u32 = 0x1000;
        const PROCESS_TERMINATE_ACCESS: u32 = 0x0001;
        const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

        let mut std_child = Command::new("cmd")
            .args(["/C", "ping", "-n", "6", "127.0.0.1", ">", "NUL"])
            .spawn()
            .expect("spawn");
        let process = open_process_handle(
            std_child.id(),
            PROCESS_QUERY_LIMITED_INFORMATION_ACCESS | PROCESS_TERMINATE_ACCESS | SYNCHRONIZE_ACCESS,
        );

        let windows_child = WindowsChild::new(process, std::ptr::null_mut(), std_child.id(), Vec::new());
        let mut wrapped = SandboxedChild::from_windows(windows_child);

        wrapped.kill().expect("kill");
        let status = std_child.wait().expect("wait std child");
        assert!(!status.success());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn restore_windows_acl_rollbacks_drains_entries() {
        let path = std::env::temp_dir().join("shadi-coverage-rollback");
        std::fs::write(&path, b"rollback").expect("write temp file");

        let mut rollbacks = vec![WindowsAclRollback {
            path: to_wide(&path),
            path_string: path.display().to_string(),
            sid: "S-1-15-2-1".to_string(),
            profile: "shadi_sandbox_test".to_string(),
            journal_path: None,
        }];

        restore_windows_acl_rollbacks(&mut rollbacks);
        assert!(rollbacks.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_acl_journal_entry_round_trips() {
        let entry = WindowsAclRollbackJournalEntry {
            path: r"C:\temp\foo".to_string(),
            sid: "S-1-15-2-1-2-3".to_string(),
            profile: "shadi_sandbox_1_0_00000000".to_string(),
            owner_pid: 42,
            hmac: "deadbeef".to_string(),
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: WindowsAclRollbackJournalEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.path, entry.path);
        assert_eq!(restored.sid, entry.sid);
        assert_eq!(restored.profile, entry.profile);
        assert_eq!(restored.owner_pid, entry.owner_pid);
        assert_eq!(restored.hmac, entry.hmac);
    }

    /// Recovery tells the two formats apart by which one parses, so neither
    /// may parse as the other.
    #[cfg(target_os = "windows")]
    #[test]
    fn the_two_journal_formats_never_parse_as_each_other() {
        let grant =
            r#"{"path":"C:\\a","sid":"S-1-15-2-1","profile":"p","owner_pid":1,"hmac":"00"}"#;
        let legacy = r#"{"path":"C:\\a","dacl_sddl":"D:(A;;FA;;;SY)","hmac":"00"}"#;
        assert!(serde_json::from_str::<WindowsAclRollbackJournalEntry>(grant).is_ok());
        assert!(serde_json::from_str::<LegacyAclJournalEntry>(grant).is_err());
        assert!(serde_json::from_str::<LegacyAclJournalEntry>(legacy).is_ok());
        assert!(serde_json::from_str::<WindowsAclRollbackJournalEntry>(legacy).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn a_grant_entry_is_trusted_only_when_signed_and_naming_an_appcontainer() {
        let key = b"test-key-32-bytes-long-enough!!!";
        let signed =
            |path: &str, sid: &str, profile: &str, pid: u32| WindowsAclRollbackJournalEntry {
                path: path.to_string(),
                sid: sid.to_string(),
                profile: profile.to_string(),
                owner_pid: pid,
                hmac: grant_journal_hmac(key, path, sid, profile, pid),
            };
        let good = signed(r"C:\temp\foo", "S-1-15-2-11-22", "shadi_sandbox_1_0_0a", 7);
        assert!(journal_entry_is_trusted(key, &good).is_ok());

        // Signed, but revoking a real account's SID could strip its access.
        for sid in ["S-1-5-32-544", "S-1-15-2-", "S-1-15-2-1-x", "S-1-15-2-1--2"] {
            let err =
                journal_entry_is_trusted(key, &signed(r"C:\temp\foo", sid, "p", 7)).expect_err(sid);
            assert!(err.contains("not an AppContainer SID"), "{sid}: {err}");
        }

        // Each field is under the tag.
        let mut rewritten = Vec::new();
        for (field, value) in [
            ("path", "C:\\other"),
            ("sid", "S-1-15-2-99"),
            ("profile", "q"),
        ] {
            let mut entry = signed(r"C:\temp\foo", "S-1-15-2-11-22", "shadi_sandbox_1_0_0a", 7);
            match field {
                "path" => entry.path = value.to_string(),
                "sid" => entry.sid = value.to_string(),
                _ => entry.profile = value.to_string(),
            }
            rewritten.push(entry);
        }
        let mut other_owner = signed(r"C:\temp\foo", "S-1-15-2-11-22", "shadi_sandbox_1_0_0a", 7);
        other_owner.owner_pid = 8;
        rewritten.push(other_owner);
        for entry in rewritten {
            assert!(journal_entry_is_trusted(key, &entry).is_err(), "{entry:?}");
        }

        let mut forged = good;
        forged.hmac = grant_journal_hmac(
            b"a-different-key-of-the-same-size",
            &forged.path,
            &forged.sid,
            &forged.profile,
            forged.owner_pid,
        );
        assert!(journal_entry_is_trusted(key, &forged).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_acl_journal_dir_uses_temp_dir() {
        let dir = windows_acl_journal_dir();
        assert!(dir.ends_with(WINDOWS_ACL_ROLLBACK_DIR_NAME));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_acl_journal_hmac_detects_tamper() {
        let key = b"test-key-32-bytes-long-enough!!!";
        let tag = compute_journal_hmac(key, r"C:\temp\foo", "D:(A;;FA;;;SY)");
        assert!(!tag.is_empty());

        // Same inputs produce same tag.
        let tag2 = compute_journal_hmac(key, r"C:\temp\foo", "D:(A;;FA;;;SY)");
        assert_eq!(tag, tag2);

        // Different path produces different tag.
        let tag3 = compute_journal_hmac(key, r"C:\temp\bar", "D:(A;;FA;;;SY)");
        assert_ne!(tag, tag3);

        // Different SDDL produces different tag.
        let tag4 = compute_journal_hmac(key, r"C:\temp\foo", "D:(A;;FA;;;BA)");
        assert_ne!(tag, tag4);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn validate_sddl_accepts_valid_strings() {
        assert!(validate_sddl("D:(A;;FA;;;SY)").is_ok());
        assert!(validate_sddl("D:P(A;;FA;;;BA)(A;;FA;;;SY)").is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn validate_sddl_rejects_invalid_strings() {
        assert!(validate_sddl("").is_err());
        assert!(validate_sddl("S:(ML;;;;;LW)").is_err());
        assert!(validate_sddl("D:(A;;FA;;;SY)\x00evil").is_err());
    }

    /// Deterministic xorshift, so a failure names an input the next run
    /// reproduces exactly.
    #[cfg(target_os = "windows")]
    struct Rng(u64);

    #[cfg(target_os = "windows")]
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn string(&mut self, max_len: usize) -> String {
            const ALPHABET: &[char] = &[
                'D', 'S', ':', 'P', '(', ')', ';', 'A', 'F', 'Y', 'B', '\\', '\x00', '\n', '\t',
                'é', ' ', '0',
            ];
            let len = self.below(max_len + 1);
            (0..len)
                .map(|_| ALPHABET[self.below(ALPHABET.len())])
                .collect()
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn validate_sddl_accepts_only_control_free_dacl_strings() {
        let mut rng = Rng(0x5eed_1234_abcd_ef01);
        for i in 0..20_000 {
            // Half the inputs already carry the DACL prefix; an unbiased
            // alphabet almost never clears that check, which would leave the
            // accepting branch untested.
            let candidate = if i % 2 == 0 {
                format!("D:{}", rng.string(22))
            } else {
                rng.string(24)
            };
            if validate_sddl(&candidate).is_ok() {
                assert!(
                    candidate.starts_with("D:"),
                    "validate_sddl accepted {candidate:?}, which is not a DACL string"
                );
                assert!(
                    !candidate.chars().any(char::is_control),
                    "validate_sddl accepted {candidate:?}, which carries a control character"
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn journal_hmac_separates_the_path_from_the_sddl() {
        let key = b"test-key-32-bytes-long-enough!!!";
        assert_ne!(
            compute_journal_hmac(key, "a\x00b", "c"),
            compute_journal_hmac(key, "a", "b\x00c"),
            "a path that embeds the separator must not forge another entry's tag"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn a_legacy_entry_is_trusted_only_when_signed_and_well_formed() {
        let key = b"test-key-32-bytes-long-enough!!!";
        let signed = |path: &str, sddl: &str| LegacyAclJournalEntry {
            path: path.to_string(),
            dacl_sddl: sddl.to_string(),
            hmac: compute_journal_hmac(key, path, sddl),
        };

        assert!(legacy_entry_is_trusted(key, &signed(r"C:\temp\foo", "D:(A;;FA;;;SY)")).is_ok());

        // Signed with this key, but the SDDL would still be handed to
        // ConvertStringSecurityDescriptorToSecurityDescriptorW.
        let err = legacy_entry_is_trusted(key, &signed(r"C:\temp\foo", "S:(ML;;;;;LW)"))
            .expect_err("a signed entry with a non-DACL string must be refused");
        assert!(err.contains("D:"), "{err}");

        // Signed with a key the recovering process does not hold.
        let mut forged = signed(r"C:\temp\foo", "D:(A;;FA;;;SY)");
        forged.hmac = compute_journal_hmac(
            b"a-different-key-of-the-same-size",
            &forged.path,
            &forged.dacl_sddl,
        );
        assert!(legacy_entry_is_trusted(key, &forged).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rewriting_any_legacy_journal_field_breaks_trust() {
        let key = b"test-key-32-bytes-long-enough!!!";
        let mut rng = Rng(0x1234_5eed_fee1_dead);

        for _ in 0..2_000 {
            let path = format!(r"C:\temp\{}", rng.string(8));
            let sddl = format!("D:{}", rng.string(12));
            let entry = LegacyAclJournalEntry {
                path: path.clone(),
                dacl_sddl: sddl.clone(),
                hmac: compute_journal_hmac(key, &path, &sddl),
            };

            // A round trip through the journal file format preserves trust.
            let json = serde_json::to_string(&entry).expect("serialize");
            let reloaded: LegacyAclJournalEntry = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                legacy_entry_is_trusted(key, &reloaded).is_ok(),
                legacy_entry_is_trusted(key, &entry).is_ok(),
                "the journal format changed the verdict for {entry:?}"
            );

            // Rewriting the path or the SDDL without the key must not verify.
            let repathed = LegacyAclJournalEntry {
                path: format!("{path}x"),
                dacl_sddl: sddl.clone(),
                hmac: entry.hmac.clone(),
            };
            assert!(
                legacy_entry_is_trusted(key, &repathed).is_err(),
                "a rewritten path kept its tag: {repathed:?}"
            );

            let resddled = LegacyAclJournalEntry {
                path: path.clone(),
                dacl_sddl: format!("{sddl}(A;;FA;;;WD)"),
                hmac: entry.hmac.clone(),
            };
            assert!(
                legacy_entry_is_trusted(key, &resddled).is_err(),
                "a rewritten SDDL kept its tag: {resddled:?}"
            );
        }
    }
}

/// A grant to undo: revoke `sid`'s ACEs on `path`. Every other ACE is left as
/// it is at that moment, so sandboxes sharing a path can exit in any order
/// (#335).
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct WindowsAclRollback {
    path: Vec<u16>,
    path_string: String,
    /// The sandbox's own AppContainer SID, in string form.
    sid: String,
    /// The sandbox's AppContainer profile, deleted with it.
    profile: String,
    journal_path: Option<std::path::PathBuf>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsAclRollbackJournalEntry {
    path: String,
    sid: String,
    profile: String,
    /// Recovery leaves the entry alone while this process runs.
    owner_pid: u32,
    hmac: String,
}

/// A journal entry from before #335: a snapshot of the DACL to put back.
/// Recovery still restores these, as the version that wrote them would have.
#[cfg(target_os = "windows")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAclJournalEntry {
    path: String,
    dacl_sddl: String,
    hmac: String,
}

#[cfg(target_os = "windows")]
const WINDOWS_ACL_ROLLBACK_DIR_NAME: &str = "shadi-acl-rollbacks";

#[cfg(target_os = "windows")]
const WINDOWS_ACL_HMAC_KEY_FILE: &str = "hmac-key";

#[cfg(target_os = "windows")]
pub struct WindowsChild {
    process: windows_sys::Win32::Foundation::HANDLE,
    thread: windows_sys::Win32::Foundation::HANDLE,
    pid: u32,
    rollbacks: Vec<WindowsAclRollback>,
    /// The sandbox's own AppContainer profile, deleted at cleanup.
    profile: Option<String>,
    cleaned: bool,
}

#[cfg(target_os = "windows")]
impl WindowsChild {
    pub fn new(
        process: windows_sys::Win32::Foundation::HANDLE,
        thread: windows_sys::Win32::Foundation::HANDLE,
        pid: u32,
        rollbacks: Vec<WindowsAclRollback>,
    ) -> Self {
        Self {
            process,
            thread,
            pid,
            rollbacks,
            profile: None,
            cleaned: false,
        }
    }

    pub(crate) fn with_profile(mut self, profile: String) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
        use std::os::windows::process::ExitStatusExt;

        unsafe {
            let wait = WaitForSingleObject(self.process, INFINITE);
            if wait == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            let mut code: u32 = 1;
            if GetExitCodeProcess(self.process, &mut code) == 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = self.cleanup();
            Ok(ExitStatus::from_raw(code))
        }
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        use std::os::windows::process::ExitStatusExt;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, WaitForSingleObject,
        };
        const WAIT_OBJECT_0: u32 = 0;

        unsafe {
            let wait = WaitForSingleObject(self.process, 0);
            if wait == WAIT_OBJECT_0 {
                let mut code: u32 = 1;
                if GetExitCodeProcess(self.process, &mut code) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let _ = self.cleanup();
                return Ok(Some(ExitStatus::from_raw(code)));
            }
            if wait == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            Ok(None)
        }
    }

    pub fn kill(&mut self) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::TerminateProcess;
        unsafe {
            if TerminateProcess(self.process, 1) == 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = self.cleanup();
            Ok(())
        }
    }

    pub fn id(&self) -> u32 {
        self.pid
    }

    fn cleanup(&mut self) -> io::Result<()> {
        use windows_sys::Win32::Foundation::CloseHandle;

        if self.cleaned {
            return Ok(());
        }

        self.cleaned = true;
        restore_windows_acl_rollbacks(&mut self.rollbacks);
        if let Some(profile) = self.profile.take() {
            crate::platform::windows::delete_appcontainer_profile(&profile);
        }

        unsafe {
            if !self.thread.is_null() {
                CloseHandle(self.thread);
                self.thread = std::ptr::null_mut();
            }
            if !self.process.is_null() {
                CloseHandle(self.process);
                self.process = std::ptr::null_mut();
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsChild {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(target_os = "windows")]
fn windows_acl_journal_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(WINDOWS_ACL_ROLLBACK_DIR_NAME)
}

#[cfg(target_os = "windows")]
fn windows_acl_journal_path() -> std::path::PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    windows_acl_journal_dir().join(format!("rollback-{}-{}.json", std::process::id(), now))
}

/// Create the journal directory with a restrictive DACL (owner + SYSTEM only).
#[cfg(target_os = "windows")]
fn ensure_journal_dir_restricted() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let dir = windows_acl_journal_dir();
    std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;

    // SDDL: owner full access + SYSTEM full access, deny everyone else.
    // D:P(A;;FA;;;CO)(A;;FA;;;SY) means Protected DACL, Creator-Owner FA, SYSTEM FA.
    // We use BA (Built-in Administrators) as a safer alternative to CO.
    let sddl = "D:P(A;;FA;;;BA)(A;;FA;;;SY)";
    let sddl_w: Vec<u16> = std::ffi::OsStr::new(sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let result = (|| {
        let mut dacl_present = 0;
        let mut dacl = std::ptr::null_mut();
        let mut defaulted = 0;
        let ok = unsafe {
            GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut defaulted)
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }

        let dir_w: Vec<u16> = std::ffi::OsStr::new(dir.as_os_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let rc = unsafe {
            SetNamedSecurityInfoW(
                dir_w.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(format!("SetNamedSecurityInfoW on journal dir failed (win32={})", rc));
        }
        Ok(())
    })();

    unsafe {
        if !sd.is_null() {
            LocalFree(sd);
        }
    }

    result
}

/// Load or create the per-session HMAC key for journal integrity.
#[cfg(target_os = "windows")]
fn load_or_create_hmac_key() -> Result<Vec<u8>, String> {
    let key_path = windows_acl_journal_dir().join(WINDOWS_ACL_HMAC_KEY_FILE);
    if key_path.exists() {
        let hex_str = std::fs::read_to_string(&key_path).map_err(|e| e.to_string())?;
        hex::decode(hex_str.trim()).map_err(|e| format!("corrupt HMAC key file: {}", e))
    } else {
        use rand::Rng;
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        let hex_str = hex::encode(&key);
        std::fs::write(&key_path, hex_str.as_bytes()).map_err(|e| e.to_string())?;
        Ok(key)
    }
}

/// HMAC-SHA256 over `fields`.
///
/// Each field is length-prefixed rather than separated by a byte: a plain
/// separator leaves the tag covering one concatenated string, so the boundary
/// between fields is not part of what is signed.
#[cfg(target_os = "windows")]
fn journal_mac(key: &[u8], fields: &[&str]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC key length is always valid");
    for field in fields {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

/// The tag a legacy entry carries, binding `path` to `dacl_sddl`.
#[cfg(target_os = "windows")]
fn compute_journal_hmac(key: &[u8], path: &str, dacl_sddl: &str) -> String {
    journal_mac(key, &[path, dacl_sddl])
}

#[cfg(target_os = "windows")]
fn grant_journal_hmac(key: &[u8], path: &str, sid: &str, profile: &str, owner_pid: u32) -> String {
    journal_mac(key, &[path, sid, profile, &owner_pid.to_string()])
}

/// Decide whether a journal entry read off disk may be applied.
///
/// The journal directory is locked down to owner and SYSTEM, but recovery
/// runs against whatever is on disk after a crash, so the HMAC is what
/// actually stands between a rewritten entry and `SetNamedSecurityInfoW`.
#[cfg(target_os = "windows")]
fn journal_entry_is_trusted(
    key: &[u8],
    entry: &WindowsAclRollbackJournalEntry,
) -> Result<(), String> {
    let expected = grant_journal_hmac(
        key,
        &entry.path,
        &entry.sid,
        &entry.profile,
        entry.owner_pid,
    );
    if entry.hmac != expected {
        return Err("HMAC mismatch".to_string());
    }
    // AppContainer SIDs are S-1-15-2-…; revoking anything else could strip a
    // real account's access.
    let well_formed = entry.sid.starts_with("S-1-15-2-")
        && entry.sid["S-1-15-2-".len()..]
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if !well_formed {
        return Err(format!("{:?} is not an AppContainer SID", entry.sid));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn legacy_entry_is_trusted(key: &[u8], entry: &LegacyAclJournalEntry) -> Result<(), String> {
    let expected = compute_journal_hmac(key, &entry.path, &entry.dacl_sddl);
    if entry.hmac != expected {
        return Err("HMAC mismatch".to_string());
    }
    validate_sddl(&entry.dacl_sddl)
}

/// Validate that an SDDL string has a plausible format before trusting it.
#[cfg(target_os = "windows")]
fn validate_sddl(sddl: &str) -> Result<(), String> {
    if sddl.is_empty() {
        return Err("SDDL string is empty".to_string());
    }
    if !sddl.starts_with("D:") {
        return Err(format!("SDDL does not start with 'D:': {}", sddl));
    }
    // Reject control characters and non-ASCII that shouldn't appear in valid SDDL
    if sddl.chars().any(|c| c.is_control()) {
        return Err("SDDL contains control characters".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn persist_windows_acl_rollback(rollback: &mut WindowsAclRollback) -> Result<(), String> {
    if rollback.journal_path.is_some() {
        return Ok(());
    }

    ensure_journal_dir_restricted()?;
    let key = load_or_create_hmac_key()?;

    let journal_path = windows_acl_journal_path();
    let owner_pid = std::process::id();
    let entry = WindowsAclRollbackJournalEntry {
        path: rollback.path_string.clone(),
        sid: rollback.sid.clone(),
        profile: rollback.profile.clone(),
        owner_pid,
        hmac: grant_journal_hmac(
            &key,
            &rollback.path_string,
            &rollback.sid,
            &rollback.profile,
            owner_pid,
        ),
    };
    let json = serde_json::to_vec_pretty(&entry).map_err(|err| err.to_string())?;
    std::fs::write(&journal_path, json).map_err(|err| err.to_string())?;
    rollback.journal_path = Some(journal_path);
    Ok(())
}

#[cfg(target_os = "windows")]
fn restore_legacy_journal_entry(entry: &LegacyAclJournalEntry) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
    };

    let sddl: Vec<u16> = std::ffi::OsStr::new(&entry.dacl_sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut security_descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1, // SECURITY_DESCRIPTOR_REVISION
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let result = (|| {
        let mut dacl_present = 0;
        let mut dacl = std::ptr::null_mut();
        let mut defaulted = 0;
        let ok = unsafe {
            GetSecurityDescriptorDacl(
                security_descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut defaulted,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }

        let path_w: Vec<u16> = std::ffi::OsStr::new(&entry.path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let rc = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(format!("SetNamedSecurityInfoW failed (win32={})", rc));
        }

        Ok(())
    })();

    unsafe {
        if !security_descriptor.is_null() {
            LocalFree(security_descriptor);
        }
    }

    result
}

#[cfg(target_os = "windows")]
pub(crate) fn recover_windows_acl_rollbacks() -> Result<usize, String> {
    use std::os::windows::ffi::OsStrExt;
    use tracing::{info, warn};

    let dir = windows_acl_journal_dir();
    if !dir.exists() {
        return Ok(0);
    }

    let key = load_or_create_hmac_key()?;

    let mut restored = 0;
    for entry in std::fs::read_dir(&dir).map_err(|err| err.to_string())? {
        let entry = entry.map_err(|err| err.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let data = std::fs::read_to_string(&path).map_err(|err| err.to_string())?;
        let (target, outcome) = match serde_json::from_str::<WindowsAclRollbackJournalEntry>(&data)
        {
            Ok(journal) => {
                // A sandbox that is still running owns this grant.
                if crate::platform::windows::owner_is_alive(journal.owner_pid) {
                    continue;
                }
                let outcome = journal_entry_is_trusted(&key, &journal).and_then(|()| {
                    let path_w: Vec<u16> = std::ffi::OsStr::new(&journal.path)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();
                    crate::platform::windows::revoke_sid_access(&path_w, &journal.sid)?;
                    crate::platform::windows::delete_appcontainer_profile(&journal.profile);
                    Ok(())
                });
                (journal.path, outcome)
            }
            Err(_) => match serde_json::from_str::<LegacyAclJournalEntry>(&data) {
                Ok(journal) => {
                    let outcome = legacy_entry_is_trusted(&key, &journal)
                        .and_then(|()| restore_legacy_journal_entry(&journal));
                    (journal.path, outcome)
                }
                Err(err) => (String::new(), Err(format!("unreadable journal: {err}"))),
            },
        };

        match outcome {
            Ok(()) => {
                let _ = std::fs::remove_file(&path);
                restored += 1;
                info!(target: "shadi.sandbox.windows", journal = %path.display(), target_path = %target, "restored stale ACL rollback journal");
            }
            Err(err) => {
                warn!(target: "shadi.sandbox.windows", journal = %path.display(), error = %err, "skipping ACL rollback journal");
            }
        }
    }

    Ok(restored)
}

#[cfg(target_os = "windows")]
pub(crate) fn restore_windows_acl_rollbacks(rollbacks: &mut Vec<WindowsAclRollback>) {
    use tracing::warn;

    for mut rollback in rollbacks.drain(..) {
        match crate::platform::windows::revoke_sid_access(&rollback.path, &rollback.sid) {
            Ok(()) => {
                if let Some(journal_path) = rollback.journal_path.take() {
                    let _ = std::fs::remove_file(journal_path);
                }
            }
            Err(err) => {
                warn!(target: "shadi.sandbox.windows", path = %rollback.path_string, error = %err, "failed to revoke a sandbox ACL grant; leaving journal for later recovery");
            }
        }
    }
}
