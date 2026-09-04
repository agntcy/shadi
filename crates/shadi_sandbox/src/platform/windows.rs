// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::Command;

use crate::{
    persist_windows_acl_rollback, recover_windows_acl_rollbacks, SandboxError, SandboxPolicy,
    SandboxedChild, WindowsAclRollback, WindowsChild,
};
use tracing::{info, warn};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, ERROR_ALREADY_EXISTS, HANDLE_FLAG_INHERIT,
    SetHandleInformation,
};
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
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    let program = command.get_program().to_string_lossy().to_string();
    let args = command.get_args().map(|arg| arg.to_string_lossy().to_string()).collect::<Vec<_>>();
    let environment = build_environment_block(command);
    let current_dir = command.get_current_dir().map(path_to_wide);
    let inherited_handles = extract_inherited_handles(command).map_err(SandboxError::ApplyFailed)?;
    let profile_name = sandbox_profile_name();

    // On Windows, kernel-level TCP channel enforcement (equivalent to Linux
    // Landlock ConnectTcp or macOS Seatbelt `remote tcp`) is not available
    // without elevated privileges (Windows Filtering Platform / WFP requires
    // admin).  When a net proxy port is configured, the proxy env vars
    // (http_proxy, https_proxy, …) are the only enforcement mechanism — a
    // process that calls connect() directly can bypass them.
    if policy.net_proxy_port().is_some() {
        warn!(
            target: "shadi.sandbox.windows",
            "net proxy mode: kernel-level TCP channel enforcement is not available \
             on Windows without elevated privileges; proxy env vars are set but a \
             process can bypass them with direct connect() calls"
        );
    }

    match recover_windows_acl_rollbacks() {
        Ok(restored) if restored > 0 => {
            info!(
                target: "shadi.sandbox.windows",
                restored = restored,
                "recovered stale Windows ACL rollback journals before sandbox startup"
            );
        }
        Ok(_) => {}
        Err(err) => {
            warn!(
                target: "shadi.sandbox.windows",
                error = %err,
                "failed to recover stale Windows ACL rollback journals before sandbox startup"
            );
        }
    }

    info!(
        target: "shadi.sandbox.windows",
        command = %program,
        arg_count = args.len(),
        read_paths = policy.allow_read().len(),
        write_paths = policy.allow_write().len(),
        net_blocked = policy.net_blocked(),
        "starting Windows AppContainer sandbox"
    );

    let appcontainer = AppContainer::new(&profile_name, policy.net_blocked())
        .map_err(SandboxError::ApplyFailed)?;

    let mut rollbacks = apply_policy_acl_grants(appcontainer.sid(), policy)
        .map_err(SandboxError::ApplyFailed)?;

    let process_info = match spawn_appcontainer_process(
        &program,
        &args,
        &appcontainer,
        environment.as_deref(),
        current_dir.as_deref(),
        &inherited_handles,
    ) {
        Ok(info) => info,
        Err(err) => {
            warn!(
                target: "shadi.sandbox.windows",
                error = %err,
                "AppContainer process spawn failed; rolling back ACL changes"
            );
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

fn sandbox_profile_name() -> String {
    std::env::var("SHADI_APPCONTAINER_NAME").unwrap_or_else(|_| "shadi_sandbox".to_string())
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
    if !rollbacks.is_empty() {
        warn!(
            target: "shadi.sandbox.windows",
            rollback_count = rollbacks.len(),
            "restoring ACL rollback entries"
        );
    }
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

fn is_already_exists_hresult(code: i32) -> bool {
    code as u32 == ERROR_ALREADY_EXISTS || code as u32 == (0x8007_0000 | ERROR_ALREADY_EXISTS)
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
        if is_already_exists_hresult(rc) {
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
    environment: Option<&[u16]>,
    current_dir: Option<&[u16]>,
    inherited_handles: &[HANDLE],
) -> Result<PROCESS_INFORMATION, String> {
    let cmdline = build_command_line(program, args);
    let mut cmdline_w = to_wide(&cmdline);
    let application_name = resolve_application_name(program);

    let mut security_caps = SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer.sid(),
        Capabilities: appcontainer.caps,
        CapabilityCount: appcontainer.cap_count,
        Reserved: 0,
    };

    let attribute_count = if inherited_handles.is_empty() { 1 } else { 2 };
    let attribute_list = ProcThreadAttributeList::new(attribute_count)?;
    attribute_list.set_security_capabilities(&mut security_caps)?;
    if !inherited_handles.is_empty() {
        attribute_list.set_handle_list(inherited_handles)?;
    }
    create_process_with_attributes(
        application_name.as_deref(),
        &mut cmdline_w,
        attribute_list.list,
        environment,
        current_dir,
        !inherited_handles.is_empty(),
    )
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

    fn set_handle_list(&self, handles: &[HANDLE]) -> Result<(), String> {
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *mut _,
                std::mem::size_of_val(handles),
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
    application_name_w: Option<&[u16]>,
    cmdline_w: &mut [u16],
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
    environment: Option<&[u16]>,
    current_dir: Option<&[u16]>,
    inherit_handles: bool,
) -> Result<PROCESS_INFORMATION, String> {
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = list;

    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            application_name_w
                .map(|value| value.as_ptr())
                .unwrap_or(std::ptr::null()),
            cmdline_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            inherit_handles as i32,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment
                .map(|value| value.as_ptr() as *mut _)
                .unwrap_or(std::ptr::null_mut()),
            current_dir
                .map(|value| value.as_ptr())
                .unwrap_or(std::ptr::null()),
            &startup.StartupInfo,
            &mut info,
        )
    };

    if ok == 0 {
        return Err(last_win32_error_message("CreateProcessW"));
    }

    Ok(info)
}

fn resolve_application_name(program: &str) -> Option<Vec<u16>> {
    let path = Path::new(program);
    if path.is_absolute() || program.contains('\\') || program.contains('/') {
        return Some(to_wide(program));
    }

    if program.eq_ignore_ascii_case("cmd") || program.eq_ignore_ascii_case("cmd.exe") {
        if let Some(comspec) = std::env::var_os("ComSpec") {
            let comspec = comspec.to_string_lossy().to_string();
            if !comspec.is_empty() {
                return Some(to_wide(&comspec));
            }
        }

        if let Some(system_root) = std::env::var_os("SystemRoot") {
            let fallback = Path::new(&system_root).join("System32").join("cmd.exe");
            return Some(to_wide(&fallback.to_string_lossy()));
        }
    }

    None
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

/// Strip the `\\?\` extended-path prefix that `Path::canonicalize` produces on
/// Windows. Security APIs (`SetNamedSecurityInfoW`, `GetNamedSecurityInfoW`)
/// do not accept the extended-length prefix and return `ERROR_ACCESS_DENIED`.
fn strip_extended_path_prefix(path: &Path) -> std::borrow::Cow<'_, str> {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix("\\\\?\\") {
        std::borrow::Cow::Owned(stripped.to_string())
    } else {
        s
    }
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn build_environment_block(command: &Command) -> Option<Vec<u16>> {
    let mut env_map = std::env::vars_os()
        .map(|(key, value)| (normalize_env_key(&key), (key, value)))
        .collect::<std::collections::BTreeMap<_, _>>();

    for (key, value) in command.get_envs() {
        if normalize_env_key(key) == "SHADI_INTERNAL_TRUSTED_SECRET_HANDLES" {
            continue;
        }

        let normalized = normalize_env_key(key);
        match value {
            Some(value) => {
                env_map.insert(normalized, (key.to_os_string(), value.to_os_string()));
            }
            None => {
                env_map.remove(&normalized);
            }
        }
    }

    if env_map.is_empty() {
        return None;
    }

    let mut block = Vec::new();
    for (_, (key, value)) in env_map {
        append_env_entry(&mut block, &key, &value);
    }
    block.push(0);
    Some(block)
}

fn append_env_entry(target: &mut Vec<u16>, key: &OsStr, value: &OsStr) {
    target.extend(key.encode_wide());
    target.push('=' as u16);
    target.extend(value.encode_wide());
    target.push(0);
}

fn normalize_env_key(key: &OsStr) -> String {
    key.to_string_lossy().to_ascii_uppercase()
}

fn extract_inherited_handles(command: &Command) -> Result<Vec<HANDLE>, String> {
    let mut handles = Vec::new();
    for (key, value) in command.get_envs() {
        if normalize_env_key(key) != "SHADI_INTERNAL_TRUSTED_SECRET_HANDLES" {
            continue;
        }

        let Some(value) = value else {
            continue;
        };

        for raw in value.to_string_lossy().split(',').filter(|part| !part.is_empty()) {
            let handle_value = raw
                .parse::<usize>()
                .map_err(|_| format!("invalid inherited handle value '{}'", raw))?;
            let handle = handle_value as HANDLE;
            let ok = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
            if ok == 0 {
                return Err(last_win32_error_message("SetHandleInformation"));
            }
            handles.push(handle);
        }
    }

    Ok(handles)
}

fn grant_path_access(
    sid: *mut core::ffi::c_void,
    path: &Path,
    read: bool,
    write: bool,
) -> Result<WindowsAclRollback, String> {
    reject_reparse_points(path)?;

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

    let mut rollback = capture_dacl(path)?;
    persist_windows_acl_rollback(&mut rollback)?;

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
    let result = unsafe { SetEntriesInAclW(1, &entry, rollback.dacl as *mut ACL, &mut acl) };
    if result != 0 {
        return Err(win32_error_message("SetEntriesInAclW", result));
    }

    let path_w = to_wide(&strip_extended_path_prefix(path));
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

fn is_reparse_point_attributes(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn reject_reparse_points(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor)
            .map_err(|e| format!("failed to inspect path {}: {}", ancestor.display(), e))?;
        #[allow(clippy::unnecessary_cast)]
        let attrs = std::os::windows::fs::MetadataExt::file_attributes(&meta) as u32;
        if is_reparse_point_attributes(attrs) {
            return Err(format!(
                "refusing ACL grant for path {} because ancestor {} is a reparse point",
                path.display(),
                ancestor.display()
            ));
        }
    }
    Ok(())
}

fn capture_dacl(path: &Path) -> Result<WindowsAclRollback, String> {
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let mut dacl: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut security_descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
    let path_w = to_wide(&strip_extended_path_prefix(path));
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

    let mut sddl_ptr: *mut u16 = std::ptr::null_mut();
    let mut sddl_len: u32 = 0;
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor,
            1, // SECURITY_DESCRIPTOR_REVISION
            DACL_SECURITY_INFORMATION,
            &mut sddl_ptr,
            &mut sddl_len,
        )
    };
    if ok == 0 {
        unsafe {
            if !security_descriptor.is_null() {
                LocalFree(security_descriptor);
            }
        }
        return Err(last_win32_error_message(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        ));
    }

    let dacl_sddl = unsafe {
        let value = std::ffi::OsString::from_wide(
            std::slice::from_raw_parts(sddl_ptr, sddl_len as usize),
        );
        LocalFree(sddl_ptr as *mut _);
        value.to_string_lossy().to_string()
    };

    Ok(WindowsAclRollback {
        path: path_w,
        path_string: strip_extended_path_prefix(path).to_string(),
        dacl,
        security_descriptor,
        dacl_sddl,
        journal_path: None,
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
    fn already_exists_hresult_matches_raw_and_wrapped_forms() {
        assert!(is_already_exists_hresult(ERROR_ALREADY_EXISTS as i32));
        assert!(is_already_exists_hresult(0x8007_0000u32.wrapping_add(ERROR_ALREADY_EXISTS) as i32));
        assert!(!is_already_exists_hresult(5));
    }

    #[test]
    fn grant_path_access_rejects_empty_access_request() {
        let path = PathBuf::from("C:\\temp");
        let err = grant_path_access(std::ptr::null_mut(), &path, false, false)
            .expect_err("empty access mask should fail");
        assert_eq!(err, "no access requested");
    }

    #[test]
    fn reparse_point_attribute_detection_works() {
        assert!(is_reparse_point_attributes(FILE_ATTRIBUTE_REPARSE_POINT));
        assert!(is_reparse_point_attributes(FILE_ATTRIBUTE_REPARSE_POINT | 0x20));
        assert!(!is_reparse_point_attributes(0));
    }
}
