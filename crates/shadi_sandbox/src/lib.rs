// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

pub mod policy;
mod platform;

pub use policy::SandboxPolicy;
use std::process::{Command, ExitStatus};
use std::io;

pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
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
        match &mut self.inner {
            SandboxedChildInner::Std(child) => child.wait(),
            #[cfg(target_os = "windows")]
            SandboxedChildInner::Windows(child) => child.wait(),
        }
    }

    pub fn kill(&mut self) -> io::Result<()> {
        match &mut self.inner {
            SandboxedChildInner::Std(child) => child.kill(),
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
}

#[cfg(target_os = "windows")]
pub(crate) struct WindowsAclRollback {
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
        use windows_sys::Win32::Foundation::CloseHandle;
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
        if self.cleaned {
            return Ok(());
        }

        self.cleaned = true;
        restore_acl_rollbacks(&mut self.rollbacks);

        unsafe {
            if self.thread != 0 {
                CloseHandle(self.thread);
                self.thread = 0;
            }
            if self.process != 0 {
                CloseHandle(self.process);
                self.process = 0;
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
fn restore_acl_rollbacks(rollbacks: &mut Vec<WindowsAclRollback>) {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::System::Memory::LocalFree;

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
                LocalFree(rollback.security_descriptor as isize);
            }
        }
    }
}
