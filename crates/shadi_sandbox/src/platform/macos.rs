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

/// Essential Mach services needed by any sandboxed process on macOS.
/// Used in Minimal profile to replace the blanket `(allow mach-lookup)`.
const ESSENTIAL_MACH_SERVICES: &[&str] = &[
    // launchd / bootstrap (required for any child process)
    "com.apple.system.launchctl.system",
    // DNS resolution
    "com.apple.dnssd.service",
    "com.apple.mDNSResponder",
    // Security framework (code signing, keychain reads)
    "com.apple.SecurityServer",
    "com.apple.security.agent",
    "com.apple.security.authhost",
    "com.apple.trustd",
    "com.apple.trustd.agent",
    // System logging
    "com.apple.system.logger",
    "com.apple.diagnosticd",
    // Core services / dyld
    "com.apple.CoreServices.coreservicesd",
    "com.apple.coreservices.launchservicesd",
    // CF preferences (many binaries read defaults)
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
];

#[cfg(not(any(test, feature = "coverage")))]
pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    let profile = build_profile(policy)?;
    let profile_cstr = CString::new(profile).map_err(|_| SandboxError::InvalidConfig)?;

    unsafe {
        command.pre_exec(move || {
            // Create a new process group so the parent can kill the entire
            // tree with killpg(), mirroring the Windows Job-object pattern.
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
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

    // Mach IPC gating: Minimal profile restricts mach-lookup to an
    // essential-services allowlist; Compatibility mode allows all lookups.
    if compatibility_profile {
        rules.push("(allow mach-lookup)".to_string());
    } else {
        // Essential system services needed for basic process execution,
        // DNS resolution, security framework, and logging.
        for svc in ESSENTIAL_MACH_SERVICES {
            rules.push(format!(
                "(allow mach-lookup (global-name \"{}\"))",
                svc
            ));
        }
    }

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
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let canonical = escape_profile_string(tmpdir.trim_end_matches('/'))?;
            rules.push(format!(
                "(allow file-read* file-write* (subpath \"{canonical}\"))"
            ));
        }
        // Allow Mach IPC and POSIX IPC for child processes (op daemon, system services).
        rules.push("(allow ipc-posix-shm)".to_string());
    }

    // Allow /dev unconditionally (mirrors Linux behaviour). /dev/null, /dev/tty,
    // /dev/urandom, /dev/fd/* etc. are fundamental Unix primitives that any
    // process may need — shell redirects (2>/dev/null), curl output (-o /dev/null),
    // random number generation, and terminal I/O all depend on this.
    rules.push("(allow file-read* file-write* (subpath \"/dev\"))".to_string());

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

    if let Some(proxy_port) = policy.net_proxy_port() {
        // Proxy mode: restrict ALL outbound TCP to the loopback proxy port.
        // macOS Seatbelt `remote tcp` only accepts `localhost` or `*` as the
        // host component — IP literals are rejected at sandbox init time.
        rules.push(format!(
            "(allow network-outbound (remote tcp \"localhost:{proxy_port}\"))"
        ));
    } else if !policy.net_allow().is_empty() {
        // net_allow without proxy: enable full outbound (macOS seatbelt cannot
        // filter by arbitrary hostname/IP at spawn time; the allow list is
        // authoritative for audit and is enforced at kernel level on Linux via
        // Landlock ConnectTcp rules).
        rules.push("(allow network-outbound)".to_string());
    } else if !policy.net_blocked() {
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
    fn build_profile_enables_outbound_when_net_allow_destinations_present() {
        let policy = SandboxPolicy::new()
            .block_network(true)
            .allow_network_destination("1.1.1.1:80")
            .allow_network_destination("127.0.0.1");

        let profile = build_profile(&policy).unwrap();

        // Seatbelt cannot filter by destination IP; we just enable outbound.
        assert!(profile.contains("(allow network-outbound)"));
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn build_profile_net_allow_overrides_blanket_block() {
        let policy = SandboxPolicy::new()
            .block_network(true)
            .allow_network_destination("1.1.1.1");

        let profile = build_profile(&policy).unwrap();
        assert!(profile.contains("(allow network-outbound)"));
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn build_profile_prefers_net_allow_over_blanket_network_access() {
        let policy = SandboxPolicy::new()
            .block_network(false)
            .allow_network_destination("1.1.1.1:80");

        let profile = build_profile(&policy).unwrap();

        assert!(profile.contains("(allow network-outbound)"));
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

    // ── mach-lookup gating tests ───────────────────────────────────────────

    #[test]
    fn compatibility_profile_allows_blanket_mach_lookup() {
        let policy = SandboxPolicy::new(); // default is Compatibility
        let profile = build_profile(&policy).unwrap();
        // Compatibility mode should have the blanket allow.
        assert!(
            profile.contains("(allow mach-lookup)"),
            "compatibility profile should allow all mach-lookup"
        );
    }

    #[test]
    fn minimal_profile_restricts_mach_lookup_to_allowlist() {
        let policy = SandboxPolicy::new().use_minimal_platform_profile();
        let profile = build_profile(&policy).unwrap();

        // Should NOT have the blanket allow.
        //
        // We need to check for the exact bare form. The profile may contain
        // mach-lookup with (global-name ...) qualifiers, which is fine.
        let has_blanket = profile
            .lines()
            .any(|line| line.trim() == "(allow mach-lookup)");
        assert!(
            !has_blanket,
            "minimal profile should not have blanket mach-lookup"
        );

        // Should contain targeted allows for essential services.
        assert!(
            profile.contains("com.apple.dnssd.service"),
            "minimal profile should allow DNS service"
        );
        assert!(
            profile.contains("com.apple.SecurityServer"),
            "minimal profile should allow SecurityServer"
        );
        assert!(
            profile.contains("com.apple.trustd"),
            "minimal profile should allow trustd"
        );
        assert!(
            profile.contains("com.apple.cfprefsd.daemon"),
            "minimal profile should allow cfprefsd"
        );
    }

    #[test]
    fn essential_mach_services_is_non_empty() {
        assert!(
            !ESSENTIAL_MACH_SERVICES.is_empty(),
            "ESSENTIAL_MACH_SERVICES should have entries"
        );
    }

    #[test]
    fn minimal_profile_mach_rules_use_global_name_syntax() {
        let policy = SandboxPolicy::new().use_minimal_platform_profile();
        let profile = build_profile(&policy).unwrap();
        // Each service should be wrapped in (allow mach-lookup (global-name "..."))
        for svc in ESSENTIAL_MACH_SERVICES {
            let expected = format!("(allow mach-lookup (global-name \"{}\"))", svc);
            assert!(
                profile.contains(&expected),
                "missing mach-lookup rule for {}",
                svc
            );
        }
    }

    // ── process group cleanup tests ────────────────────────────────────────

    #[test]
    fn kill_uses_killpg_for_process_group() {
        // Verify that kill() works on a spawned child that may be in its
        // own process group. In test mode setsid isn't called, so killpg
        // may fail and fall back to single-process kill — either way the
        // child must be stopped.
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let mut wrapped = crate::SandboxedChild::from_std(child);
        wrapped.kill().expect("kill");
        let status = wrapped.wait().expect("wait");
        assert!(!status.success(), "killed process should not exit 0");
    }
}
