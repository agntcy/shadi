// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
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
    DeriveCapabilitySidsFromName, EqualSid, GetAce, GetFileSecurityW,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, InitializeSecurityDescriptor, SetFileSecurityW, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACE_HEADER, CONTAINER_INHERIT_ACE,
    NO_INHERITANCE, OBJECT_INHERIT_ACE, SECURITY_CAPABILITIES, SECURITY_DESCRIPTOR,
    SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, REVOKE_ACCESS,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
    SE_GROUP_ENABLED,
};
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

    // Proxy mode routes the child's TCP through a loopback proxy. An
    // AppContainer cannot reach 127.0.0.1 at all without a loopback exemption
    // for its container SID (CheckNetIsolation LoopbackExempt, admin only,
    // and every sandbox here gets a fresh SID). The capability that would let
    // the child out, internetClient, lets it skip the proxy entirely, so
    // there is no setting that confines it to the proxy. Refuse rather than
    // run with the proxy env vars set and nothing enforcing them (#530).
    if policy.net_proxy_port().is_some() {
        return Err(SandboxError::ApplyFailed(
            "network policy cannot be enforced on Windows: an AppContainer cannot reach \
             the loopback proxy without a loopback exemption for its container SID"
                .to_string(),
        ));
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

    let appcontainer = AppContainer::new(&profile_name, !policy.net_blocked()).map_err(|err| {
        delete_appcontainer_profile(&profile_name);
        SandboxError::ApplyFailed(err)
    })?;

    let working_dir = effective_working_dir(command);
    let mut rollbacks =
        apply_policy_acl_grants(&appcontainer, &profile_name, policy, working_dir.as_deref())
            .map_err(|err| {
                delete_appcontainer_profile(&profile_name);
                SandboxError::ApplyFailed(err)
            })?;

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
            delete_appcontainer_profile(&profile_name);
            return Err(SandboxError::SpawnFailed(err));
        }
    };

    let child = WindowsChild::new(
        process_info.hProcess,
        process_info.hThread,
        process_info.dwProcessId,
        rollbacks,
    )
    .with_profile(profile_name);

    apply_job_object(child.process).map_err(SandboxError::ApplyFailed)?;

    Ok(SandboxedChild::from_windows(child))
}

/// A profile of its own for every sandbox, so each has its own SID: a grant to
/// one sandbox is not a grant to another, and revoking it leaves the others
/// alone (#335). `SHADI_APPCONTAINER_NAME` sets the prefix.
fn sandbox_profile_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    // AppContainer names are at most 64 characters.
    const MAX_NAME: usize = 64;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    let base =
        std::env::var("SHADI_APPCONTAINER_NAME").unwrap_or_else(|_| "shadi_sandbox".to_string());
    let nonce: u32 = rand::random();
    let suffix = format!(
        "_{}_{}_{nonce:08x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let base: String = base
        .chars()
        .take(MAX_NAME.saturating_sub(suffix.len()))
        .collect();
    format!("{base}{suffix}")
}

/// Delete a sandbox's profile once nothing uses it. Best effort: a leftover
/// profile grants nothing, since its ACEs are revoked first.
pub(crate) fn delete_appcontainer_profile(name: &str) {
    let name_w = to_wide(name);
    let rc = unsafe { DeleteAppContainerProfile(name_w.as_ptr()) };
    if rc != 0 {
        warn!(
            target: "shadi.sandbox.windows",
            profile = name,
            error = %hresult_error_message("DeleteAppContainerProfile", rc),
            "failed to delete AppContainer profile"
        );
    }
}

/// Whether the process that wrote a journal entry still runs, in which case
/// its sandbox is live and recovery must leave the entry alone.
pub(crate) fn owner_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == std::process::id() {
        return true;
    }
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            // It exists but isn't ours to open.
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        let mut code: u32 = 0;
        let alive = GetExitCodeProcess(process, &mut code) != 0 && code == STILL_ACTIVE as u32;
        CloseHandle(process);
        alive
    }
}

/// The directory the child starts in: the command's, or this process's.
fn effective_working_dir(command: &Command) -> Option<PathBuf> {
    let own = std::env::current_dir().ok();
    match command.get_current_dir() {
        Some(dir) if dir.is_absolute() => Some(dir.to_path_buf()),
        Some(dir) => own.map(|base| base.join(dir)),
        None => own,
    }
}

/// Whether the policy already grants `dir`, itself or as part of a granted
/// directory, whose ACE it inherits.
fn working_dir_is_granted(policy: &SandboxPolicy, dir: &Path) -> bool {
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = canonical(dir);
    policy
        .allow_read()
        .iter()
        .chain(policy.allow_write())
        .filter(|path| !policy.path_is_denied(path))
        .any(|path| {
            let granted = canonical(path);
            dir == granted || (granted.is_dir() && dir.starts_with(&granted))
        })
}

fn apply_policy_acl_grants(
    appcontainer: &AppContainer,
    profile: &str,
    policy: &SandboxPolicy,
    working_dir: Option<&Path>,
) -> Result<Vec<WindowsAclRollback>, String> {
    let sid = appcontainer.sid();
    let sid_string = appcontainer.sid_string()?;
    let mut rollbacks = Vec::new();
    // A denied path is dropped from the grant set, the way Landlock does it.
    // Carving a denial out of an allowed parent needs a deny ACE ordered ahead
    // of the allow ACEs, which is a separate step (agntcy/shadi#541).
    for path in policy.allow_read() {
        if policy.path_is_denied(path) {
            continue;
        }
        match grant_path_access(sid, &sid_string, profile, path, true, false) {
            Ok(rollback) => rollbacks.push(rollback),
            Err(err) => {
                rollback_acl_changes(&mut rollbacks);
                return Err(err);
            }
        }
    }

    for path in policy.allow_write() {
        if policy.path_is_denied(path) {
            continue;
        }
        match grant_path_access(sid, &sid_string, profile, path, true, true) {
            Ok(rollback) => rollbacks.push(rollback),
            Err(err) => {
                rollback_acl_changes(&mut rollbacks);
                return Err(err);
            }
        }
    }

    // A process the child starts opens the working directory again under the
    // AppContainer token, and fails without an ACE there (agntcy/shadi#538).
    // CreateProcessW reads its attributes and opens it for traverse; neither
    // lists or reads anything in it. Without it the child still runs, so a
    // directory whose DACL can't be changed only warns.
    if let Some(dir) = working_dir {
        if !policy.path_is_denied(dir) && !working_dir_is_granted(policy, dir) {
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
            };
            let access = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            match grant_access(sid, &sid_string, profile, dir, access, NO_INHERITANCE) {
                Ok(rollback) => rollbacks.push(rollback),
                Err(err) => warn!(
                    target: "shadi.sandbox.windows",
                    working_dir = %dir.display(),
                    error = %err,
                    "the sandbox cannot open its working directory, so it cannot start other programs"
                ),
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
    caps: Vec<SID_AND_ATTRIBUTES>,
    /// The SIDs `caps` points at; freed with the container.
    capability_sids: Vec<*mut core::ffi::c_void>,
}

impl AppContainer {
    fn new(name: &str, grant_internet: bool) -> Result<Self, String> {
        let sid = create_or_derive_appcontainer_sid(name)?;
        let (caps, capability_sids) = if grant_internet {
            derive_internet_client_capabilities()?
        } else {
            (Vec::new(), Vec::new())
        };

        Ok(Self {
            sid,
            caps,
            capability_sids,
        })
    }

    fn sid(&self) -> *mut core::ffi::c_void {
        self.sid
    }

    fn sid_string(&self) -> Result<String, String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(self.sid, &mut text) } == 0 {
            return Err(last_win32_error_message("ConvertSidToStringSidW"));
        }
        let value = unsafe {
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let value = std::ffi::OsString::from_wide(std::slice::from_raw_parts(text, len));
            LocalFree(text as *mut _);
            value
        };
        Ok(value.to_string_lossy().into_owned())
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

fn derive_internet_client_capabilities(
) -> Result<(Vec<SID_AND_ATTRIBUTES>, Vec<*mut core::ffi::c_void>), String> {
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

    if ok == 0 || caps_raw.is_null() || cap_count == 0 {
        return Err(last_win32_error_message("DeriveCapabilitySidsFromName"));
    }

    // Group capability SIDs have no place in SECURITY_CAPABILITIES.
    unsafe { free_sid_array(group_caps_raw, group_cap_count) };

    // The call returns arrays of PSID, but SECURITY_CAPABILITIES.Capabilities
    // is an array of SID_AND_ATTRIBUTES. Reinterpreting one as the other left
    // Attributes holding whatever followed the SID pointer, and CreateProcessW
    // rejected the attribute list with ERROR_INVALID_PARAMETER (agntcy/shadi#531).
    let sids = unsafe { std::slice::from_raw_parts(caps_raw, cap_count as usize).to_vec() };
    unsafe { LocalFree(caps_raw as *mut _) };

    let caps = sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: *sid,
            Attributes: SE_GROUP_ENABLED as u32,
        })
        .collect();

    Ok((caps, sids))
}

/// Free each SID in an array handed back by `DeriveCapabilitySidsFromName`,
/// then the array itself.
unsafe fn free_sid_array(array: *mut *mut core::ffi::c_void, count: u32) {
    if array.is_null() {
        return;
    }
    for index in 0..count as usize {
        let sid = *array.add(index);
        if !sid.is_null() {
            LocalFree(sid);
        }
    }
    LocalFree(array as *mut _);
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        unsafe {
            if !self.sid.is_null() {
                LocalFree(self.sid);
            }
            for sid in &self.capability_sids {
                if !sid.is_null() {
                    LocalFree(*sid);
                }
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
        Capabilities: if appcontainer.caps.is_empty() {
            std::ptr::null_mut()
        } else {
            appcontainer.caps.as_ptr() as *mut SID_AND_ATTRIBUTES
        },
        CapabilityCount: appcontainer.caps.len() as u32,
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
    sid_string: &str,
    profile: &str,
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

    // An ACE on a directory covers the directory object alone unless it is
    // marked inheritable, which left granted files unreadable (agntcy/shadi#532).
    let inheritance = if path.is_dir() {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    grant_access(sid, sid_string, profile, path, access_mask, inheritance)
}

fn grant_access(
    sid: *mut core::ffi::c_void,
    sid_string: &str,
    profile: &str,
    path: &Path,
    access_mask: u32,
    inheritance: u32,
) -> Result<WindowsAclRollback, String> {
    reject_reparse_points(path)?;

    let path_w = to_wide(&strip_extended_path_prefix(path));
    let mut rollback = WindowsAclRollback {
        path: path_w.clone(),
        path_string: strip_extended_path_prefix(path).to_string(),
        sid: sid_string.to_string(),
        profile: profile.to_string(),
        journal_path: None,
    };
    // Journaled before the change, so a crash in between leaves something to
    // revoke rather than a grant nobody knows about.
    persist_windows_acl_rollback(&mut rollback)?;
    edit_dacl(&path_w, sid, GRANT_ACCESS, access_mask, inheritance)?;
    Ok(rollback)
}

/// Remove every ACE for `sid` from `path`, leaving all other ACEs as they are
/// now, whoever added them.
pub(crate) fn revoke_sid_access(path_w: &[u16], sid: &str) -> Result<(), String> {
    let sid_w = to_wide(sid);
    let mut sid_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid_ptr) } == 0 {
        return Err(last_win32_error_message("ConvertStringSidToSidW"));
    }
    let result = edit_dacl(path_w, sid_ptr, REVOKE_ACCESS, 0, NO_INHERITANCE);
    unsafe { LocalFree(sid_ptr) };
    result
}

/// Read `path`'s DACL as it is now, apply one entry for `sid`, and write it
/// back. Serialized, so two sandboxes in this process can't interleave a
/// read and a write and lose one another's change.
fn edit_dacl(
    path_w: &[u16],
    sid: *mut core::ffi::c_void,
    mode: ACCESS_MODE,
    access_mask: u32,
    inheritance: u32,
) -> Result<(), String> {
    static ACL_EDIT: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = ACL_EDIT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if result != 0 {
        return Err(win32_error_message("GetNamedSecurityInfoW", result));
    }

    // An inheritable ACE reaches existing children only through
    // SetNamedSecurityInfoW, which walks the whole tree and re-marks ACEs
    // copied from the parent as inherited (agntcy/shadi#545). Any other edit
    // is made to this object alone.
    let propagate = if mode == REVOKE_ACCESS {
        holds_inheritable_ace(dacl, sid)
    } else {
        inheritance != NO_INHERITANCE
    };
    if !propagate {
        unsafe { LocalFree(security_descriptor) };
        return edit_object_dacl(path_w, sid, mode, access_mask, inheritance);
    }

    let entry = explicit_access(sid, mode, access_mask, inheritance);
    let mut updated: *mut ACL = std::ptr::null_mut();
    let result = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut updated) };
    let result = if result != 0 {
        Err(win32_error_message("SetEntriesInAclW", result))
    } else {
        let rc = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                updated,
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            Err(win32_error_message("SetNamedSecurityInfoW", rc))
        } else {
            Ok(())
        }
    };
    unsafe {
        if !updated.is_null() {
            LocalFree(updated as *mut _);
        }
        if !security_descriptor.is_null() {
            LocalFree(security_descriptor);
        }
    }
    result
}

fn explicit_access(
    sid: *mut core::ffi::c_void,
    mode: ACCESS_MODE,
    access_mask: u32,
    inheritance: u32,
) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask,
        grfAccessMode: mode,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: 0,
            ptstrName: sid as *mut u16,
        },
    }
}

/// [`edit_dacl`] on `path_w` alone. The DACL is read as stored, with
/// GetFileSecurityW: GetNamedSecurityInfoW reports ACEs copied from the
/// parent as inherited, and writing that back would mark them so.
fn edit_object_dacl(
    path_w: &[u16],
    sid: *mut core::ffi::c_void,
    mode: ACCESS_MODE,
    access_mask: u32,
    inheritance: u32,
) -> Result<(), String> {
    let information = windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    let path = path_w.as_ptr();
    let mut needed: u32 = 0;
    unsafe { GetFileSecurityW(path, information, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(last_win32_error_message("GetFileSecurityW"));
    }
    // u64s, so the descriptor is aligned.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    let descriptor = buffer.as_mut_ptr() as *mut core::ffi::c_void;
    let length = (buffer.len() * 8) as u32;
    let fetched = unsafe { GetFileSecurityW(path, information, descriptor, length, &mut needed) };
    if fetched == 0 {
        return Err(last_win32_error_message("GetFileSecurityW"));
    }

    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    let read = unsafe {
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) != 0
            && GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
    };
    if !read {
        return Err(last_win32_error_message("GetSecurityDescriptorDacl"));
    }
    if present == 0 {
        dacl = std::ptr::null_mut();
    }

    let entry = explicit_access(sid, mode, access_mask, inheritance);
    let mut updated: *mut ACL = std::ptr::null_mut();
    let result = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut updated) };
    if result != 0 {
        return Err(win32_error_message("SetEntriesInAclW", result));
    }
    let result = set_object_dacl(path_w, updated, control);
    unsafe { LocalFree(updated as *mut _) };
    result
}

/// Whether `dacl` has an ACE for `sid` that children inherit. An ACE that
/// can't be read counts as one, so a revoke still reaches the children.
fn holds_inheritable_ace(dacl: *const ACL, sid: *mut core::ffi::c_void) -> bool {
    if dacl.is_null() {
        return false;
    }
    let count = u32::from(unsafe { (*dacl).AceCount });
    (0..count).any(|index| {
        let mut out = std::mem::MaybeUninit::<*mut core::ffi::c_void>::uninit();
        if unsafe { GetAce(dacl, index, out.as_mut_ptr()) } == 0 {
            return true;
        }
        let Some(ace) = std::ptr::NonNull::new(unsafe { out.assume_init() }) else {
            return true;
        };
        let ace = ace.as_ptr();
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        let simple = matches!(
            u32::from(header.AceType),
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        );
        let inheritable =
            u32::from(header.AceFlags) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) != 0;
        simple && inheritable && {
            let ace_sid =
                unsafe { std::ptr::addr_of!((*(ace as *const ACCESS_ALLOWED_ACE)).SidStart) };
            let equal = unsafe { EqualSid(ace_sid as *mut core::ffi::c_void, sid) };
            equal != 0
        }
    })
}

/// Write `dacl` to `path_w` alone, keeping the protection and
/// auto-inheritance bits `control` had.
fn set_object_dacl(path_w: &[u16], dacl: *const ACL, control: u16) -> Result<(), String> {
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let descriptor_ptr = &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void;
    let bits = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED;
    let written = unsafe {
        InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) != 0
            && SetSecurityDescriptorDacl(descriptor_ptr, 1, dacl, 0) != 0
            && SetSecurityDescriptorControl(descriptor_ptr, bits, control & bits) != 0
            && SetFileSecurityW(
                path_w.as_ptr(),
                windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
                descriptor_ptr,
            ) != 0
    };
    if written {
        Ok(())
    } else {
        Err(last_win32_error_message("SetFileSecurityW"))
    }
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
        let err = grant_path_access(std::ptr::null_mut(), "S-1-15-2-1", "p", &path, false, false)
            .expect_err("empty access mask should fail");
        assert_eq!(err, "no access requested");
    }

    #[test]
    fn every_sandbox_gets_its_own_profile_name() {
        let first = sandbox_profile_name();
        let second = sandbox_profile_name();
        assert_ne!(first, second);
        for name in [&first, &second] {
            assert!(name.len() <= 64, "{name}");
            assert!(name.starts_with("shadi_sandbox_"), "{name}");
        }
    }

    #[test]
    fn this_process_counts_as_a_live_owner() {
        assert!(owner_is_alive(std::process::id()));
    }

    #[test]
    fn reparse_point_attribute_detection_works() {
        assert!(is_reparse_point_attributes(FILE_ATTRIBUTE_REPARSE_POINT));
        assert!(is_reparse_point_attributes(FILE_ATTRIBUTE_REPARSE_POINT | 0x20));
        assert!(!is_reparse_point_attributes(0));
    }

    #[test]
    fn a_working_dir_in_a_granted_directory_needs_no_grant_of_its_own() {
        let root = tempfile::tempdir().expect("tempdir");
        let inside = root.path().join("sub");
        std::fs::create_dir(&inside).expect("create sub");
        let other = tempfile::tempdir().expect("tempdir");
        let policy = SandboxPolicy::new().allow_read_path(root.path());

        assert!(working_dir_is_granted(&policy, root.path()));
        assert!(working_dir_is_granted(&policy, &inside));
        assert!(!working_dir_is_granted(&policy, other.path()));
        assert!(!working_dir_is_granted(
            &policy.deny_path(root.path()),
            &inside
        ));
    }

    #[test]
    fn a_relative_working_dir_is_relative_to_this_process() {
        let own = std::env::current_dir().ok();
        let mut command = Command::new("cmd");
        assert_eq!(effective_working_dir(&command), own);
        command.current_dir("sub");
        assert_eq!(
            effective_working_dir(&command),
            own.map(|dir| dir.join("sub"))
        );
    }
}
