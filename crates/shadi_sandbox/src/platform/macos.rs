// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, CString};
#[cfg(not(any(test, feature = "coverage")))]
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::{PlatformSandboxProfile, SandboxError, SandboxPolicy, SandboxedChild};

const DEFAULT_READ_PATHS: &[&str] = &[
    "/System",
    "/usr/lib",
    "/usr/share",
    "/usr/libexec",
    "/Library",
    "/etc",
    "/opt/homebrew",
];

#[cfg(not(any(test, feature = "coverage")))]
pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    let profile = build_profile(policy)?;
    let profile_cstr = CString::new(profile).map_err(|_| SandboxError::InvalidConfig)?;

    unsafe {
        command.pre_exec(move || {
            apply_profile(&profile_cstr)
                .map_err(std::io::Error::other)
        });
    }

    let child = command.spawn().map_err(|err| SandboxError::SpawnFailed(err.to_string()))?;
    Ok(SandboxedChild::from_std(child))
}

#[cfg(any(test, feature = "coverage"))]
pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    let profile = build_profile(policy)?;
    let profile_cstr = CString::new(profile).map_err(|_| SandboxError::InvalidConfig)?;
    apply_profile(profile_cstr.as_c_str())?;
    let child = command.spawn().map_err(|err| SandboxError::SpawnFailed(err.to_string()))?;
    Ok(SandboxedChild::from_std(child))
}

fn build_profile(policy: &SandboxPolicy) -> Result<String, SandboxError> {
    let mut rules = Vec::new();
    let compatibility_profile = policy.platform_profile() == PlatformSandboxProfile::Compatibility;

    rules.push("(version 1)".to_string());
    rules.push("(deny default)".to_string());
    rules.push("(allow process*)".to_string());
    rules.push("(allow process-exec)".to_string());
    rules.push("(allow sysctl-read)".to_string());
    rules.push("(allow mach-lookup)".to_string());
    rules.push("(allow file-read-data file-read-metadata (literal \"/\"))".to_string());

    for path in DEFAULT_READ_PATHS {
        rules.push(format!(
            "(allow file-read* file-map-executable (subpath \"{}\"))",
            path
        ));
    }

    if compatibility_profile {
        rules.push("(allow file-read* file-write* (subpath \"/private/var\"))".to_string());

        rules.push("(allow file-read* file-write* (subpath \"/Library/Keychains\"))".to_string());
        rules.push("(allow file-read* file-write* (subpath \"/private/var/db/Keychains\"))".to_string());
        rules.push("(allow file-read* file-write* (subpath \"/private/var/db/SystemKey\"))".to_string());
        if let Ok(home) = std::env::var("HOME") {
            let home = escape_profile_string(&home)?;
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{}/Library/Keychains\"))",
                home
            ));
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{}/Library\"))",
                home
            ));
            // Allow the 1Password CLI config dir (socket, config, lock files).
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{}/.config\"))",
                home
            ));
            // Allow the slim_bindings local storage directory (~/.slim).
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{}/.slim\"))",
                home
            ));
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{}/.local\"))",
                home
            ));
            // Allow gh CLI cache directory (~/.cache) used by gh and git credential helpers.
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{}/.cache\"))",
                home
            ));
        }
        // Allow /var/folders (op daemon temp dir). /var → /private/var but Seatbelt
        // matches on the literal path seen by the caller, so cover both spellings.
        rules.push("(allow file-read* file-write* (subpath \"/var/folders\"))".to_string());
        rules.push("(allow file-read* file-write* (subpath \"/private/tmp\"))".to_string());
        // Allow /dev/null and other character devices needed by subprocesses (e.g. git, gh).
        rules.push("(allow file-read* file-write* (subpath \"/dev\"))".to_string());
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let canonical = escape_profile_string(tmpdir.trim_end_matches('/'))?;
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{canonical}\"))"
            ));
        }
        // Allow Mach IPC and POSIX IPC for child processes (op daemon, system services).
        rules.push("(allow ipc-posix-shm)".to_string());
    }

    if compatibility_profile || policy.local_unix_sockets_allowed() {
        // Allow Unix-domain socket connections for tightly scoped brokered secret delivery
        // and compatibility-mode daemon IPC.
        rules.push("(allow network-outbound (local unix-socket))".to_string());
        rules.push("(allow network-inbound (local unix-socket))".to_string());
    }

    for path in policy.allow_read() {
        let abs = resolve_path(path);
        let Some(s) = abs.to_str() else {
            return Err(SandboxError::InvalidConfig);
        };
        let s = escape_profile_string(s)?;
        rules.push(format!(
            "(allow file-read* file-map-executable (subpath \"{}\"))",
            s
        ));
    }

    for path in policy.allow_write() {
        let abs = resolve_path(path);
        let Some(s) = abs.to_str() else {
            return Err(SandboxError::InvalidConfig);
        };
        let s = escape_profile_string(s)?;
        rules.push(format!(
            "(allow file-write* file-map-executable (subpath \"{}\"))",
            s
        ));
    }

    if !policy.net_blocked() {
        rules.push("(allow network*)".to_string());
    }

    Ok(rules.join("\n"))
}

fn escape_profile_string(value: &str) -> Result<String, SandboxError> {
    if value.contains('\0') {
        return Err(SandboxError::InvalidConfig);
    }

    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Resolve a path to absolute.  Seatbelt requires absolute paths for
/// `subpath` matchers; relative ones are silently ignored.
/// The result is also lexically normalized (`.` and `..` components removed)
/// because macOS Seatbelt does NOT normalize `subpath` arguments, so a
/// trailing `/./` or similar makes the rule silently ineffective.
fn resolve_path(path: &std::path::Path) -> std::path::PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    normalize_path(abs)
}

/// Lexically normalize a path by resolving `.` and `..` components without
/// hitting the filesystem (so it works for paths that don't exist yet).
fn normalize_path(path: std::path::PathBuf) -> std::path::PathBuf {
    use std::path::{Component, PathBuf};
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(not(any(test, feature = "coverage")))]
fn apply_profile(profile: &CStr) -> Result<(), SandboxError> {
    let mut error_ptr: *mut libc::c_char = std::ptr::null_mut();
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error_ptr) };

    if rc != 0 {
        let message = unsafe {
            if error_ptr.is_null() {
                "sandbox_init failed".to_string()
            } else {
                let err = CStr::from_ptr(error_ptr).to_string_lossy().into_owned();
                sandbox_free_error(error_ptr);
                err
            }
        };
        return Err(SandboxError::ApplyFailed(message));
    }

    Ok(())
}

#[cfg(any(test, feature = "coverage"))]
fn apply_profile(_profile: &CStr) -> Result<(), SandboxError> {
    Ok(())
}

#[cfg(not(any(test, feature = "coverage")))]
#[link(name = "sandbox")]
extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, errorbuf: *mut *mut libc::c_char) -> libc::c_int;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPolicy;
    use std::path::PathBuf;
    use std::sync::Mutex;

    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn tmp_root() -> String {
        std::env::var("SHADI_TMP_DIR").unwrap_or_else(|_| "./.tmp".to_string())
    }

    #[test]
    fn build_profile_includes_paths_and_network_rule() {
        let tmp_dir = tmp_root();
        let policy = SandboxPolicy::new()
            .allow_read_path(&tmp_dir)
            .allow_write_path(&tmp_dir)
            .block_network(false);

        let profile = build_profile(&policy).unwrap();
        let abs_tmp = resolve_path(std::path::Path::new(&tmp_dir));
        let abs_str = abs_tmp.to_str().unwrap();
        assert!(profile.contains(&format!(
            "(allow file-read* file-map-executable (subpath \"{}\"))",
            abs_str
        )));
        assert!(profile.contains(&format!(
            "(allow file-write* file-map-executable (subpath \"{}\"))",
            abs_str
        )));
        assert!(profile.contains("(allow network*)"));
    }

    #[test]
    fn build_profile_blocks_network_when_enabled() {
        let policy = SandboxPolicy::new().block_network(true);
        let profile = build_profile(&policy).unwrap();
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn build_profile_includes_default_read_paths() {
        let policy = SandboxPolicy::new();
        let profile = build_profile(&policy).unwrap();
        assert!(profile.contains("/System"));
        assert!(profile.contains("/usr/lib"));
    }

    #[test]
    fn build_profile_includes_home_keychain_paths() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let original = std::env::var("HOME").ok();
        let tmp_dir = tmp_root();
        std::env::set_var("HOME", &tmp_dir);
        let policy = SandboxPolicy::new();
        let profile = build_profile(&policy).unwrap();
        assert!(profile.contains(&format!("{}/Library/Keychains", tmp_dir)));
        assert!(profile.contains(&format!("{}/Library", tmp_dir)));

        if let Some(value) = original {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn build_profile_skips_home_paths_when_unset() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let original = std::env::var("HOME").ok();
        let tmp_dir = tmp_root();
        let home_dir = format!("{}/shadi-home", tmp_dir);
        std::env::set_var("HOME", &home_dir);
        let policy = SandboxPolicy::new();
        let with_home = build_profile(&policy).unwrap();
        assert!(with_home.contains(&format!("{}/Library/Keychains", home_dir)));

        std::env::remove_var("HOME");
        let without_home = build_profile(&policy).unwrap();
        assert!(!without_home.contains(&format!("{}/Library/Keychains", home_dir)));

        if let Some(value) = original {
            std::env::set_var("HOME", value);
        }
    }

    #[test]
    fn build_profile_includes_keychain_system_paths() {
        let policy = SandboxPolicy::new();
        let profile = build_profile(&policy).unwrap();
        assert!(profile.contains("/Library/Keychains"));
        assert!(profile.contains("/private/var/db/Keychains"));
    }

    #[test]
    fn minimal_profile_skips_compatibility_allowances() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let original = std::env::var("HOME").ok();
        let tmp_dir = tmp_root();
        let home_dir = format!("{}/shadi-minimal-home", tmp_dir);
        std::env::set_var("HOME", &home_dir);

        let policy = SandboxPolicy::new().use_minimal_platform_profile();
        let profile = build_profile(&policy).unwrap();

        assert!(!profile.contains(&format!("{}/Library", home_dir)));
        assert!(!profile.contains(&format!("{}/.config", home_dir)));
        assert!(!profile.contains(&format!("{}/.cache", home_dir)));
        assert!(!profile.contains("/private/var/db/Keychains"));
        assert!(!profile.contains("(allow network-outbound (local unix-socket))"));

        if let Some(value) = original {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn minimal_profile_can_opt_into_local_unix_sockets() {
        let policy = SandboxPolicy::new()
            .use_minimal_platform_profile()
            .allow_local_unix_sockets();
        let profile = build_profile(&policy).unwrap();
        assert!(profile.contains("(allow network-outbound (local unix-socket))"));
        assert!(profile.contains("(allow network-inbound (local unix-socket))"));
    }

    #[test]
    fn build_profile_rejects_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut bytes = Vec::new();
        bytes.push(0xff);
        bytes.push(0xfe);
        let bad = OsString::from_vec(bytes);
        let path = PathBuf::from(bad);

        let policy = SandboxPolicy::new().allow_read_path(path);
        let err = build_profile(&policy).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig));
    }

    #[test]
    fn build_profile_rejects_non_utf8_write_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut bytes = Vec::new();
        bytes.push(0xff);
        bytes.push(0xfe);
        let bad = OsString::from_vec(bytes);
        let path = PathBuf::from(bad);

        let policy = SandboxPolicy::new().allow_write_path(path);
        let err = build_profile(&policy).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig));
    }

    #[test]
    fn apply_profile_noop_in_tests() {
        let profile = CStr::from_bytes_with_nul(b"(version 1)\0").expect("cstr");
        apply_profile(profile).expect("apply");
    }

    #[test]
    fn build_profile_escapes_tmpdir_literals() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let original = std::env::var("TMPDIR").ok();
        std::env::set_var("TMPDIR", "/tmp/shadi-\"quoted\"");

        let profile = build_profile(&SandboxPolicy::new()).unwrap();
        assert!(profile.contains("/tmp/shadi-\\\"quoted\\\""));

        if let Some(value) = original {
            std::env::set_var("TMPDIR", value);
        } else {
            std::env::remove_var("TMPDIR");
        }
    }
}
