// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

pub mod policy;
pub mod policy_patch;
mod platform;

pub use policy::{PlatformSandboxProfile, SandboxPolicy};
pub use policy_patch::{
    ControlMessage, ControlResponse, PatchAxisStatus, PolicyPatch, PolicyPatchResponse,
};
use std::process::{Command, ExitStatus};
use std::io;
use tracing::{field, info_span};

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
        .unwrap_or_else(|| "".to_string());
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
            span.record("exit.code", &status.code().unwrap_or(-1));
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
            dacl: std::ptr::null_mut(),
            security_descriptor: std::ptr::null_mut(),
            dacl_sddl: String::new(),
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
            dacl_sddl: "D:(A;;FA;;;SY)".to_string(),
            hmac: "deadbeef".to_string(),
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: WindowsAclRollbackJournalEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.path, entry.path);
        assert_eq!(restored.dacl_sddl, entry.dacl_sddl);
        assert_eq!(restored.hmac, entry.hmac);
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
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct WindowsAclRollback {
    path: Vec<u16>,
    path_string: String,
    dacl: *mut core::ffi::c_void,
    security_descriptor: *mut core::ffi::c_void,
    dacl_sddl: String,
    journal_path: Option<std::path::PathBuf>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct WindowsAclRollbackJournalEntry {
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
            cleaned: false,
        }
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
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let hex_str = hex::encode(&key);
        std::fs::write(&key_path, hex_str.as_bytes()).map_err(|e| e.to_string())?;
        Ok(key)
    }
}

/// Compute HMAC-SHA256 over `path || dacl_sddl`.
#[cfg(target_os = "windows")]
fn compute_journal_hmac(key: &[u8], path: &str, dacl_sddl: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC key length is always valid");
    mac.update(path.as_bytes());
    mac.update(b"\x00");
    mac.update(dacl_sddl.as_bytes());
    hex::encode(mac.finalize().into_bytes())
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
    let hmac_tag = compute_journal_hmac(&key, &rollback.path_string, &rollback.dacl_sddl);
    let entry = WindowsAclRollbackJournalEntry {
        path: rollback.path_string.clone(),
        dacl_sddl: rollback.dacl_sddl.clone(),
        hmac: hmac_tag,
    };
    let json = serde_json::to_vec_pretty(&entry).map_err(|err| err.to_string())?;
    std::fs::write(&journal_path, json).map_err(|err| err.to_string())?;
    rollback.journal_path = Some(journal_path);
    Ok(())
}

#[cfg(target_os = "windows")]
fn restore_windows_acl_journal_entry(entry: &WindowsAclRollbackJournalEntry) -> Result<(), String> {
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
        let journal: WindowsAclRollbackJournalEntry =
            serde_json::from_str(&data).map_err(|err| err.to_string())?;

        // Verify HMAC before trusting journal content.
        let expected_hmac = compute_journal_hmac(&key, &journal.path, &journal.dacl_sddl);
        if journal.hmac != expected_hmac {
            warn!(
                target: "shadi.sandbox.windows",
                journal = %path.display(),
                "rejecting tampered ACL rollback journal (HMAC mismatch)"
            );
            continue;
        }

        // Validate SDDL syntax before applying.
        if let Err(err) = validate_sddl(&journal.dacl_sddl) {
            warn!(
                target: "shadi.sandbox.windows",
                journal = %path.display(),
                error = %err,
                "rejecting ACL rollback journal with invalid SDDL"
            );
            continue;
        }

        match restore_windows_acl_journal_entry(&journal) {
            Ok(()) => {
                let _ = std::fs::remove_file(&path);
                restored += 1;
                info!(target: "shadi.sandbox.windows", journal = %path.display(), target_path = %journal.path, "restored stale ACL rollback journal");
            }
            Err(err) => {
                warn!(target: "shadi.sandbox.windows", journal = %path.display(), error = %err, "failed to restore stale ACL rollback journal");
            }
        }
    }

    Ok(restored)
}

#[cfg(target_os = "windows")]
pub(crate) fn restore_windows_acl_rollbacks(rollbacks: &mut Vec<WindowsAclRollback>) {
    use tracing::warn;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Foundation::LocalFree;

    for mut rollback in rollbacks.drain(..) {
        let restored;
        unsafe {
            let rc = SetNamedSecurityInfoW(
                rollback.path.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                rollback.dacl as *mut _,
                std::ptr::null_mut(),
            );
            restored = rc == 0;

            if !rollback.security_descriptor.is_null() {
                LocalFree(rollback.security_descriptor);
            }
        }

        if restored {
            if let Some(journal_path) = rollback.journal_path.take() {
                let _ = std::fs::remove_file(journal_path);
            }
        } else {
            warn!(target: "shadi.sandbox.windows", path = %rollback.path_string, "failed to restore ACL rollback in-memory; leaving journal for later recovery");
        }
    }
}
