// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

use crate::{SandboxError, SandboxPolicy, SandboxedChild, WindowsAclRollback, WindowsChild};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::Security::{
    DeriveCapabilitySidsFromName, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, NO_INHERITANCE,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, TRUSTEE_IS_SID,
    TRUSTEE_W, GRANT_ACCESS, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    DeleteProcThreadAttributeList, PROCESS_INFORMATION, STARTUPINFOEXW,
    EXTENDED_STARTUPINFO_PRESENT, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
};
use windows_sys::Win32::Foundation::LocalFree;

pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    let program = command.get_program().to_string_lossy().to_string();
    let args = command.get_args().map(|arg| arg.to_string_lossy().to_string()).collect::<Vec<_>>();

    let appcontainer = AppContainer::new("shadi_sandbox", policy.net_blocked())
        .map_err(SandboxError::ApplyFailed)?;

    let mut rollbacks = apply_policy_acl_grants(appcontainer.sid(), policy)
        .map_err(SandboxError::ApplyFailed)?;

    let process_info = match spawn_appcontainer_process(&program, &args, &appcontainer) {
        Ok(info) => info,
        Err(err) => {
            rollback_acl_changes(&mut rollbacks);
            return Err(SandboxError::SpawnFailed(err));
        }
    };

    let child = WindowsChild::new(
        process_info.hProcess,
        process_info.hThread,
        process_info.dwProcessId,
        rollbacks,
    );

    apply_job_object(child.process).map_err(SandboxError::ApplyFailed)?;

    Ok(SandboxedChild::from_windows(child))
}

fn apply_policy_acl_grants(
    sid: *mut core::ffi::c_void,
    policy: &SandboxPolicy,
) -> Result<Vec<WindowsAclRollback>, String> {
    let mut rollbacks = Vec::new();
    for path in policy.allow_read() {
        match grant_path_access(sid, path, true, false) {
            Ok(rollback) => rollbacks.push(rollback),
            Err(err) => {
                rollback_acl_changes(&mut rollbacks);
                return Err(err);
            }
        }
    }

    for path in policy.allow_write() {
        match grant_path_access(sid, path, true, true) {
            Ok(rollback) => rollbacks.push(rollback),
            Err(err) => {
                rollback_acl_changes(&mut rollbacks);
                return Err(err);
            }
        }
    }

    Ok(rollbacks)
}

fn rollback_acl_changes(rollbacks: &mut Vec<WindowsAclRollback>) {
    crate::restore_windows_acl_rollbacks(rollbacks);
}

fn last_win32_error_message(operation: &'static str) -> String {
    let code = unsafe { GetLastError() };
    format!("{} failed (win32={})", operation, code)
}

fn win32_error_message(operation: &'static str, code: u32) -> String {
    format!("{} failed (win32={})", operation, code)
}

fn hresult_error_message(operation: &'static str, code: i32) -> String {
    format!("{} failed (hresult=0x{:08x})", operation, code as u32)
}

struct AppContainer {
    sid: *mut core::ffi::c_void,
    caps: *mut SID_AND_ATTRIBUTES,
    group_caps: *mut SID_AND_ATTRIBUTES,
    cap_count: u32,
}

impl AppContainer {
    fn new(name: &str, net_blocked: bool) -> Result<Self, String> {
        let sid = create_or_derive_appcontainer_sid(name)?;
        let (caps, group_caps, cap_count) = if net_blocked {
            (std::ptr::null_mut(), std::ptr::null_mut(), 0)
        } else {
            derive_internet_client_capabilities()?
        };

        Ok(Self {
            sid,
            caps,
            group_caps,
            cap_count,
        })
    }

    fn sid(&self) -> *mut core::ffi::c_void {
        self.sid
    }
}

fn create_or_derive_appcontainer_sid(name: &str) -> Result<*mut core::ffi::c_void, String> {
        let name_w = to_wide(name);
        let display_w = to_wide("SHADI Sandbox");
        let description_w = to_wide("SHADI AppContainer");

    let mut sid: *mut core::ffi::c_void = std::ptr::null_mut();
    let rc = unsafe {
        CreateAppContainerProfile(
            name_w.as_ptr(),
            display_w.as_ptr(),
            description_w.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut sid,
        )
    };

    if rc != 0 {
        if rc as u32 == ERROR_ALREADY_EXISTS {
            let derive_rc = unsafe { DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut sid) };
            if derive_rc != 0 {
                return Err(hresult_error_message(
                    "DeriveAppContainerSidFromAppContainerName",
                    derive_rc,
                ));
            }
        } else {
            return Err(hresult_error_message("CreateAppContainerProfile", rc));
        }
    }

    Ok(sid)
}

fn derive_internet_client_capabilities() -> Result<(*mut SID_AND_ATTRIBUTES, *mut SID_AND_ATTRIBUTES, u32), String> {
    let cap_name = to_wide("internetClient");
    let mut caps_raw: *mut *mut core::ffi::c_void = std::ptr::null_mut();
    let mut group_caps_raw: *mut *mut core::ffi::c_void = std::ptr::null_mut();
    let mut cap_count: u32 = 0;
    let mut group_cap_count: u32 = 0;

    let ok = unsafe {
        DeriveCapabilitySidsFromName(
            cap_name.as_ptr(),
            &mut group_caps_raw,
            &mut group_cap_count,
            &mut caps_raw,
            &mut cap_count,
        )
    };

    let caps = caps_raw as *mut SID_AND_ATTRIBUTES;
    let group_caps = group_caps_raw as *mut SID_AND_ATTRIBUTES;
    if ok == 0 || caps.is_null() || cap_count == 0 {
        return Err(last_win32_error_message("DeriveCapabilitySidsFromName"));
    }

    Ok((caps, group_caps, cap_count))
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        unsafe {
            if !self.sid.is_null() {
                LocalFree(self.sid);
            }
            if !self.caps.is_null() {
                LocalFree(self.caps as *mut _);
            }
            if !self.group_caps.is_null() {
                LocalFree(self.group_caps as *mut _);
            }
        }
    }
}

fn spawn_appcontainer_process(
    program: &str,
    args: &[String],
    appcontainer: &AppContainer,
) -> Result<PROCESS_INFORMATION, String> {
    let cmdline = build_command_line(program, args);
    let mut cmdline_w = to_wide(&cmdline);

    let mut security_caps = SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer.sid(),
        Capabilities: appcontainer.caps,
        CapabilityCount: appcontainer.cap_count,
        Reserved: 0,
    };

    let attribute_list = ProcThreadAttributeList::new(1)?;
    attribute_list.set_security_capabilities(&mut security_caps)?;
    create_process_with_attributes(&mut cmdline_w, attribute_list.list)
}

struct ProcThreadAttributeList {
    _buffer: Vec<u8>,
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl ProcThreadAttributeList {
    fn new(count: u32) -> Result<Self, String> {
        let mut size: usize = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size);
        }
        if size == 0 {
            return Err(last_win32_error_message("InitializeProcThreadAttributeList"));
        }

        let mut buffer = vec![0u8; size];
        let list = buffer.as_mut_ptr()
            as windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;
        let ok = unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) };
        if ok == 0 {
            return Err(last_win32_error_message("InitializeProcThreadAttributeList"));
        }

        Ok(Self {
            _buffer: buffer,
            list,
        })
    }

    fn set_security_capabilities(&self, caps: &mut SECURITY_CAPABILITIES) -> Result<(), String> {
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                caps as *mut _ as *mut _,
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_win32_error_message("UpdateProcThreadAttribute"));
        }
        Ok(())
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

fn create_process_with_attributes(
    cmdline_w: &mut [u16],
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
) -> Result<PROCESS_INFORMATION, String> {
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = list;

    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null_mut(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut info,
        )
    };

    if ok == 0 {
        return Err(last_win32_error_message("CreateProcessW"));
    }

    Ok(info)
}

fn build_command_line(program: &str, args: &[String]) -> String {
    let mut out = String::new();
    out.push_str(&quote_arg(program));
    for arg in args {
        out.push(' ');
        out.push_str(&quote_arg(arg));
    }
    out
}

fn quote_arg(arg: &str) -> String {
    if arg.contains(' ') || arg.contains('"') {
        let escaped = arg.replace('"', "\\\"");
        format!("\"{}\"", escaped)
    } else {
        arg.to_string()
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn grant_path_access(
    sid: *mut core::ffi::c_void,
    path: &Path,
    read: bool,
    write: bool,
) -> Result<WindowsAclRollback, String> {
    let mut access_mask: u32 = 0;
    if read {
        access_mask |= windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
        access_mask |= windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
    }
    if write {
        access_mask |= windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
    }

    if access_mask == 0 {
        return Err("no access requested".to_string());
    }

    let rollback = capture_dacl(path)?;

    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: 0,
        ptstrName: sid as *mut u16,
    };

    let mut entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: trustee,
    };

    let mut acl: *mut ACL = std::ptr::null_mut();
    let result = unsafe { SetEntriesInAclW(1, &mut entry, rollback.dacl as *mut ACL, &mut acl) };
    if result != 0 {
        return Err(win32_error_message("SetEntriesInAclW", result));
    }

    let path_w = to_wide(path.to_string_lossy().as_ref());
    let result = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        if !acl.is_null() {
            LocalFree(acl as *mut _);
        }
    }
    if result != 0 {
        return Err(win32_error_message("SetNamedSecurityInfoW", result));
    }

    Ok(rollback)
}

fn capture_dacl(path: &Path) -> Result<WindowsAclRollback, String> {
    let mut dacl: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut security_descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
    let path_w = to_wide(path.to_string_lossy().as_ref());
    let result = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl as *mut _ as *mut _,
            std::ptr::null_mut(),
            &mut security_descriptor as *mut _ as *mut _,
        )
    };
    if result != 0 {
        return Err(win32_error_message("GetNamedSecurityInfoW", result));
    }

    Ok(WindowsAclRollback {
        path: path_w,
        dacl,
        security_descriptor,
    })
}

fn apply_job_object(process: HANDLE) -> Result<(), String> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(last_win32_error_message("CreateJobObjectW"));
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 {
            CloseHandle(job);
            return Err(last_win32_error_message("SetInformationJobObject"));
        }

        let ok = AssignProcessToJobObject(job, process);
        if ok == 0 {
            CloseHandle(job);
            return Err(last_win32_error_message("AssignProcessToJobObject"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn windows_spawn_returns_clear_error_when_attribute_init_fails() {
        let err = win32_error_message("InitializeProcThreadAttributeList", 87);
        assert!(err.contains("InitializeProcThreadAttributeList"));
        assert!(err.contains("87"));
    }

    #[test]
    fn windows_spawn_returns_clear_error_when_create_process_fails() {
        let err = win32_error_message("CreateProcessW", 2);
        assert!(err.contains("CreateProcessW"));
        assert!(err.contains("2"));
    }

    #[test]
    fn windows_rollback_is_safe_when_called_multiple_times() {
        let mut rollbacks = Vec::new();
        rollback_acl_changes(&mut rollbacks);
        rollback_acl_changes(&mut rollbacks);
        assert!(rollbacks.is_empty());
    }

    #[test]
    fn quote_arg_leaves_simple_values_unchanged() {
        assert_eq!(quote_arg("cmd"), "cmd");
        assert_eq!(quote_arg("--flag"), "--flag");
    }

    #[test]
    fn quote_arg_wraps_and_escapes_when_needed() {
        assert_eq!(quote_arg("hello world"), "\"hello world\"");
        assert_eq!(quote_arg("has\"quote"), "\"has\\\"quote\"");
    }

    #[test]
    fn build_command_line_quotes_program_and_args() {
        let cmdline = build_command_line(
            "C:\\Program Files\\app.exe",
            &[
                "arg1".to_string(),
                "arg two".to_string(),
                "quoted\"value".to_string(),
            ],
        );

        assert_eq!(
            cmdline,
            "\"C:\\Program Files\\app.exe\" arg1 \"arg two\" \"quoted\\\"value\""
        );
    }

    #[test]
    fn to_wide_appends_null_terminator() {
        let wide = to_wide("shadi");
        assert_eq!(wide.last().copied(), Some(0));
        assert!(wide.len() >= 2);
    }

    #[test]
    fn hresult_error_messages_are_stable() {
        let err = hresult_error_message("CreateAppContainerProfile", -2147467259);
        assert!(err.contains("CreateAppContainerProfile"));
        assert!(err.contains("hresult=0x"));
    }

    #[test]
    fn grant_path_access_rejects_empty_access_request() {
        let path = PathBuf::from("C:\\temp");
        let err = grant_path_access(std::ptr::null_mut(), &path, false, false)
            .expect_err("empty access mask should fail");
        assert_eq!(err, "no access requested");
    }
}
