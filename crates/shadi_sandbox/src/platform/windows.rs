// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

use crate::{SandboxError, SandboxPolicy, SandboxedChild, WindowsAclRollback, WindowsChild};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, ERROR_ALREADY_EXISTS};
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

    let mut rollbacks = Vec::new();
    for path in policy.allow_read() {
        let rollback = grant_path_access(appcontainer.sid(), path, true, false)
            .map_err(SandboxError::ApplyFailed)?;
        rollbacks.push(rollback);
    }

    for path in policy.allow_write() {
        let rollback = grant_path_access(appcontainer.sid(), path, true, true)
            .map_err(SandboxError::ApplyFailed)?;
        rollbacks.push(rollback);
    }

    let child = match spawn_appcontainer_process(&program, &args, &appcontainer, rollbacks) {
        Ok(child) => child,
        Err(err) => {
            return Err(SandboxError::SpawnFailed(err));
        }
    };

    apply_job_object(child.process).map_err(SandboxError::ApplyFailed)?;

    Ok(SandboxedChild::from_windows(child))
}

struct AppContainer {
    sid: *mut core::ffi::c_void,
    caps: *mut SID_AND_ATTRIBUTES,
    group_caps: *mut SID_AND_ATTRIBUTES,
    cap_count: u32,
}

impl AppContainer {
    fn new(name: &str, net_blocked: bool) -> Result<Self, String> {
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
                let ok = unsafe { DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut sid) };
                if ok != 0 {
                    return Err("DeriveAppContainerSidFromAppContainerName failed".to_string());
                }
            } else {
                return Err("CreateAppContainerProfile failed".to_string());
            }
        }

        let mut caps: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
        let mut group_caps: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
        let mut cap_count: u32 = 0;
        let mut group_cap_count: u32 = 0;
        if !net_blocked {
            let cap_name = to_wide("internetClient");
            let mut caps_raw: *mut *mut core::ffi::c_void = std::ptr::null_mut();
            let mut group_caps_raw: *mut *mut core::ffi::c_void = std::ptr::null_mut();
            let ok = unsafe {
                DeriveCapabilitySidsFromName(
                    cap_name.as_ptr(),
                    &mut group_caps_raw,
                    &mut group_cap_count,
                    &mut caps_raw,
                    &mut cap_count,
                )
            };
            caps = caps_raw as *mut SID_AND_ATTRIBUTES;
            group_caps = group_caps_raw as *mut SID_AND_ATTRIBUTES;
            if ok == 0 || caps.is_null() || cap_count == 0 {
                return Err("DeriveCapabilitySidsFromName failed".to_string());
            }
        }

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
    rollbacks: Vec<WindowsAclRollback>,
) -> Result<WindowsChild, String> {
    let cmdline = build_command_line(program, args);
    let mut cmdline_w = to_wide(&cmdline);

    let mut caps = SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer.sid(),
        Capabilities: appcontainer.caps,
        CapabilityCount: appcontainer.cap_count,
        Reserved: 0,
    };

    let mut size: usize = 0;
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
    }
    let mut buffer = vec![0u8; size];
    let list = buffer.as_mut_ptr() as windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;
    let ok = unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) };
    if ok == 0 {
        return Err("InitializeProcThreadAttributeList failed".to_string());
    }

    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &mut caps as *mut _ as *mut _,
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe { DeleteProcThreadAttributeList(list) };
        return Err("UpdateProcThreadAttribute failed".to_string());
    }

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

    unsafe { DeleteProcThreadAttributeList(list) };

    if ok == 0 {
        return Err("CreateProcessW failed".to_string());
    }

    Ok(WindowsChild::new(info.hProcess, info.hThread, info.dwProcessId, rollbacks))
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
    let result = unsafe { SetEntriesInAclW(1, &mut entry, std::ptr::null_mut(), &mut acl) };
    if result != 0 {
        return Err("SetEntriesInAclW failed".to_string());
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
        return Err("SetNamedSecurityInfoW failed".to_string());
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
        return Err("GetNamedSecurityInfoW failed".to_string());
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
            return Err("CreateJobObjectW failed".to_string());
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
            return Err("SetInformationJobObject failed".to_string());
        }

        let ok = AssignProcessToJobObject(job, process);
        if ok == 0 {
            CloseHandle(job);
            return Err("AssignProcessToJobObject failed".to_string());
        }

        Ok(())
    }
}
