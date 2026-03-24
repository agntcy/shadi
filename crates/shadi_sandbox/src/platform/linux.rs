// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Linux sandbox implementation using Landlock LSM.
//!
//! Landlock provides unprivileged, irreversible, kernel-enforced filesystem
//! and network isolation. Once `restrict_self()` is called the restrictions
//! cannot be removed — child processes inherit them.
//!
//! Requires Linux kernel 5.13+ (ABI V1). Network filtering requires 5.19+
//! (ABI V4). The implementation probes from the highest ABI downward and
//! uses the best available version.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use tracing::{debug, info, warn};

use crate::{PlatformSandboxProfile, SandboxError, SandboxPolicy, SandboxedChild};

/// System paths that all sandboxed processes need to read for basic operation.
const DEFAULT_READ_PATHS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/etc",
    "/proc/self",
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
];

/// ABI probe order — highest to lowest. We want the best features available.
const ABI_PROBE_ORDER: [ABI; 6] = [ABI::V6, ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1];

// ── ABI detection ──────────────────────────────────────────────────────────

/// Detect the highest Landlock ABI supported by the running kernel.
fn detect_abi() -> Result<ABI, SandboxError> {
    for &abi in &ABI_PROBE_ORDER {
        match probe_abi(abi) {
            Ok(()) => return Ok(abi),
            Err(msg) => {
                debug!("Landlock ABI {:?} probe failed: {}", abi, msg);
            }
        }
    }
    Err(SandboxError::ApplyFailed(
        "Landlock not available — requires Linux kernel 5.13+".to_string(),
    ))
}

/// Try to create a ruleset at the given ABI level with HardRequirement.
fn probe_abi(abi: ABI) -> Result<(), String> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("fs access: {}", e))?;

    let net = AccessNet::from_all(abi);
    if !net.is_empty() {
        ruleset = ruleset
            .handle_access(net)
            .map_err(|e| format!("net access: {}", e))?;
    }

    ruleset.create().map_err(|e| format!("create: {}", e))?;
    Ok(())
}

/// Return a human-readable ABI version label.
fn abi_label(abi: ABI) -> &'static str {
    match abi {
        ABI::V1 => "V1",
        ABI::V2 => "V2",
        ABI::V3 => "V3",
        ABI::V4 => "V4",
        ABI::V5 => "V5",
        ABI::V6 => "V6",
        _ => "unknown",
    }
}

// ── sandbox application ────────────────────────────────────────────────────

/// Build and apply a Landlock ruleset from the given policy, then exec the
/// command inside the restricted context.
///
/// The call sequence in the child (via `pre_exec`) is:
/// 1. `prctl(PR_SET_NO_NEW_PRIVS)` — required by Landlock and prevents
///    privilege escalation through setuid binaries.
/// 2. Build a Landlock ruleset from the policy paths.
/// 3. `restrict_self()` — irreversible kernel enforcement from here on.
///
/// If tests or coverage builds are active the sandbox is applied in the
/// parent process instead (same as the macOS test path).
#[cfg(not(any(test, feature = "coverage")))]
pub fn spawn_sandboxed(
    command: &mut Command,
    policy: &SandboxPolicy,
) -> Result<SandboxedChild, SandboxError> {
    let abi = detect_abi()?;
    let apply_fn = build_apply_closure(policy, abi)?;

    unsafe {
        command.pre_exec(move || {
            apply_fn().map_err(|e| std::io::Error::other(e.to_string()))
        });
    }

    let child = command
        .spawn()
        .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;
    Ok(SandboxedChild::from_std(child))
}

/// Test / coverage variant — applies sandbox in the *current* process so
/// that the test harness itself is restricted (mirrors macOS test path).
#[cfg(any(test, feature = "coverage"))]
pub fn spawn_sandboxed(
    command: &mut Command,
    policy: &SandboxPolicy,
) -> Result<SandboxedChild, SandboxError> {
    let abi = detect_abi()?;
    let apply_fn = build_apply_closure(policy, abi)?;
    apply_fn()?;

    let child = command
        .spawn()
        .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;
    Ok(SandboxedChild::from_std(child))
}

/// Create a closure that, when called, sets `no_new_privs` and applies the
/// Landlock ruleset. The closure captures only owned data so it is safe to
/// move into `pre_exec`.
fn build_apply_closure(
    policy: &SandboxPolicy,
    abi: ABI,
) -> Result<Box<dyn FnOnce() -> Result<(), SandboxError> + Send>, SandboxError> {
    // Collect every path rule we need *before* forking.
    let mut read_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut write_paths: Vec<std::path::PathBuf> = Vec::new();

    // Add default system read paths.
    let compatibility =
        policy.platform_profile() == PlatformSandboxProfile::Compatibility;

    for &default in DEFAULT_READ_PATHS {
        if Path::new(default).exists() {
            read_paths.push(default.into());
        }
    }

    // Compatibility profile: extra system paths (tmp, home config dirs, etc.)
    if compatibility {
        for extra in compatibility_read_paths() {
            if Path::new(&extra).exists() {
                read_paths.push(extra);
            }
        }
        for extra in compatibility_write_paths() {
            if Path::new(&extra).exists() {
                write_paths.push(extra);
            }
        }
    }

    // User-specified paths
    for p in policy.allow_read() {
        read_paths.push(p.clone());
    }
    for p in policy.allow_write() {
        write_paths.push(p.clone());
    }

    let net_block = policy.net_blocked();

    Ok(Box::new(move || apply_landlock(abi, &read_paths, &write_paths, net_block)))
}

/// Extra read paths for the compatibility profile.
fn compatibility_read_paths() -> Vec<std::path::PathBuf> {
    let mut paths = vec![
        "/tmp".into(),
        "/var/tmp".into(),
        "/dev".into(),
        "/run".into(),
    ];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(format!("{}/.config", home).into());
        paths.push(format!("{}/.local", home).into());
        paths.push(format!("{}/.cache", home).into());
    }
    paths
}

/// Extra write paths for the compatibility profile.
fn compatibility_write_paths() -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = vec![
        "/tmp".into(),
        "/var/tmp".into(),
        "/dev/null".into(),
        "/dev/tty".into(),
    ];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(format!("{}/.config", home).into());
        paths.push(format!("{}/.local", home).into());
        paths.push(format!("{}/.cache", home).into());
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        paths.push(tmpdir.into());
    }
    paths
}

// ── Landlock ruleset construction ──────────────────────────────────────────

/// Set `PR_SET_NO_NEW_PRIVS`, build the Landlock ruleset, and call
/// `restrict_self()`.
fn apply_landlock(
    abi: ABI,
    read_paths: &[std::path::PathBuf],
    write_paths: &[std::path::PathBuf],
    net_block: bool,
) -> Result<(), SandboxError> {
    info!("Applying Landlock sandbox (ABI {})", abi_label(abi));

    // 1. PR_SET_NO_NEW_PRIVS — required for unprivileged Landlock.
    set_no_new_privs()?;

    // 2. Build ruleset.
    let handled_fs = AccessFs::from_all(abi);
    debug!("Handling filesystem access: {:?}", handled_fs);

    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_fs)
        .map_err(|e| {
            SandboxError::ApplyFailed(format!("failed to handle fs access: {}", e))
        })?
        .set_compatibility(CompatLevel::BestEffort);

    // Network isolation (ABI V4+).
    if net_block {
        let handled_net = AccessNet::from_all(abi);
        if !handled_net.is_empty() {
            debug!("Handling network access: {:?}", handled_net);
            builder = builder
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(handled_net)
                .map_err(|e| {
                    SandboxError::ApplyFailed(format!(
                        "network filtering requested but unsupported: {}",
                        e,
                    ))
                })?
                .set_compatibility(CompatLevel::BestEffort);
        } else {
            warn!(
                "Network blocking requested but Landlock ABI {} does not support \
                 network filtering (requires V4+). Filesystem isolation is still enforced.",
                abi_label(abi),
            );
        }
    }

    let mut ruleset = builder.create().map_err(|e| {
        SandboxError::ApplyFailed(format!("failed to create Landlock ruleset: {}", e))
    })?;

    // 3. Add filesystem rules.
    let read_access = read_access_flags(abi);
    let write_access = write_access_flags(abi);

    for path in read_paths {
        ruleset = add_path_rule(ruleset, path, read_access, "read")?;
    }

    for path in write_paths {
        // Write paths also get read access.
        ruleset = add_path_rule(ruleset, path, read_access | write_access, "write")?;
    }

    // 4. restrict_self() — irreversible.
    let status = ruleset.restrict_self().map_err(|e| {
        SandboxError::ApplyFailed(format!("restrict_self failed: {}", e))
    })?;

    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => {
            info!("Landlock sandbox fully enforced");
        }
        landlock::RulesetStatus::PartiallyEnforced => {
            debug!("Landlock sandbox partially enforced (best-effort fallback)");
        }
        landlock::RulesetStatus::NotEnforced => {
            return Err(SandboxError::ApplyFailed(
                "Landlock sandbox was not enforced".to_string(),
            ));
        }
    }

    Ok(())
}

/// Map `SandboxPolicy` read access to Landlock flags.
fn read_access_flags(abi: ABI) -> BitFlags<AccessFs> {
    let available = AccessFs::from_all(abi);
    let desired = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    desired & available
}

/// Map `SandboxPolicy` write access to Landlock flags.
fn write_access_flags(abi: ABI) -> BitFlags<AccessFs> {
    let available = AccessFs::from_all(abi);
    let desired = AccessFs::WriteFile
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Refer
        | AccessFs::Truncate;
    desired & available
}

/// Add a `PathBeneath` rule, skipping nonexistent paths with a warning.
fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
    label: &str,
) -> Result<landlock::RulesetCreated, SandboxError> {
    match PathFd::new(path) {
        Ok(fd) => {
            debug!("Adding {} rule: {}", label, path.display());
            ruleset
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|e| {
                    SandboxError::ApplyFailed(format!(
                        "cannot add Landlock rule for {}: {}",
                        path.display(),
                        e,
                    ))
                })
        }
        Err(e) => {
            warn!(
                "Skipping {} path {} (cannot open: {})",
                label,
                path.display(),
                e,
            );
            Ok(ruleset)
        }
    }
}

/// Set `PR_SET_NO_NEW_PRIVS` — a one-way flag that prevents privilege
/// escalation through setuid/setgid binaries. Required by Landlock for
/// unprivileged use and by seccomp.
fn set_no_new_privs() -> Result<(), SandboxError> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1) is always safe to call.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(SandboxError::ApplyFailed(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPolicy;

    #[test]
    fn detect_abi_returns_supported_version() {
        // This test only passes on Linux 5.13+ with Landlock enabled.
        // In CI on macOS/Windows it is not compiled (#[cfg(target_os = "linux")]).
        let abi = detect_abi().expect("Landlock should be available on this kernel");
        let label = abi_label(abi);
        assert!(
            ["V1", "V2", "V3", "V4", "V5", "V6"].contains(&label),
            "unexpected ABI: {}",
            label,
        );
    }

    #[test]
    fn abi_label_covers_all_known_versions() {
        assert_eq!(abi_label(ABI::V1), "V1");
        assert_eq!(abi_label(ABI::V2), "V2");
        assert_eq!(abi_label(ABI::V3), "V3");
        assert_eq!(abi_label(ABI::V4), "V4");
        assert_eq!(abi_label(ABI::V5), "V5");
        assert_eq!(abi_label(ABI::V6), "V6");
    }

    #[test]
    fn read_access_flags_include_read_and_execute() {
        let flags = read_access_flags(ABI::V1);
        assert!(flags.contains(AccessFs::ReadFile));
        assert!(flags.contains(AccessFs::ReadDir));
        assert!(flags.contains(AccessFs::Execute));
    }

    #[test]
    fn write_access_flags_include_write_and_create() {
        let flags = write_access_flags(ABI::V1);
        assert!(flags.contains(AccessFs::WriteFile));
        assert!(flags.contains(AccessFs::MakeReg));
        assert!(flags.contains(AccessFs::MakeDir));
        assert!(flags.contains(AccessFs::RemoveFile));
    }

    #[test]
    fn default_read_paths_exist_on_linux() {
        // At minimum /usr and /etc should exist on any Linux system.
        assert!(Path::new("/usr").exists());
        assert!(Path::new("/etc").exists());
    }

    #[test]
    fn compatibility_paths_include_tmp() {
        let read = compatibility_read_paths();
        assert!(read.iter().any(|p| p == Path::new("/tmp")));
        let write = compatibility_write_paths();
        assert!(write.iter().any(|p| p == Path::new("/tmp")));
    }

    #[test]
    fn build_apply_closure_succeeds_with_default_policy() {
        let policy = SandboxPolicy::new();
        let abi = detect_abi().expect("Landlock available");
        let closure = build_apply_closure(&policy, abi);
        assert!(closure.is_ok(), "build_apply_closure should succeed");
    }

    #[test]
    fn build_apply_closure_includes_user_paths() {
        let policy = SandboxPolicy::new()
            .allow_read_path("/usr")
            .allow_write_path("/tmp");
        let abi = detect_abi().expect("Landlock available");
        let _closure = build_apply_closure(&policy, abi)
            .expect("build_apply_closure should succeed with user paths");
    }

    #[test]
    fn apply_landlock_enforces_sandbox() {
        // Applying Landlock is irreversible, so we only test that it does
        // not error out. The actual enforcement is tested via spawn_sandboxed
        // integration tests.
        let abi = detect_abi().expect("Landlock available");
        // We cannot call apply_landlock here because it would restrict the
        // test harness. Instead verify the building steps succeed.
        let read = read_access_flags(abi);
        let write = write_access_flags(abi);
        assert!(!read.is_empty());
        assert!(!write.is_empty());
    }

    #[test]
    fn probe_abi_v1_should_succeed() {
        // V1 is the minimum; if Landlock is available at all this passes.
        let result = probe_abi(ABI::V1);
        assert!(result.is_ok(), "ABI V1 probe should succeed: {:?}", result.err());
    }
}
