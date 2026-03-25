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
            dacl: std::ptr::null_mut(),
            security_descriptor: std::ptr::null_mut(),
        }];

        restore_windows_acl_rollbacks(&mut rollbacks);
        assert!(rollbacks.is_empty());

        let _ = std::fs::remove_file(path);
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct WindowsAclRollback {
    path: Vec<u16>,
    dacl: *mut core::ffi::c_void,
    security_descriptor: *mut core::ffi::c_void,
}

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
pub(crate) fn restore_windows_acl_rollbacks(rollbacks: &mut Vec<WindowsAclRollback>) {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Foundation::LocalFree;

    for rollback in rollbacks.drain(..) {
        unsafe {
            let _ = SetNamedSecurityInfoW(
                rollback.path.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                rollback.dacl as *mut _,
                std::ptr::null_mut(),
            );

            if !rollback.security_descriptor.is_null() {
                LocalFree(rollback.security_descriptor);
            }
        }
    }
}
