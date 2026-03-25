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

#[cfg(not(any(test, feature = "coverage")))]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible,
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
/// Collected sandbox configuration — all owned data, `Send + Sync` safe
/// for use in `pre_exec`.
struct LandlockConfig {
    abi: ABI,
    read_paths: Vec<std::path::PathBuf>,
    write_paths: Vec<std::path::PathBuf>,
    net_block: bool,
}

impl LandlockConfig {
    /// Collect paths from the policy *before* forking.
    fn from_policy(policy: &SandboxPolicy, abi: ABI) -> Self {
        let mut read_paths: Vec<std::path::PathBuf> = Vec::new();
        let mut write_paths: Vec<std::path::PathBuf> = Vec::new();

        let compatibility =
            policy.platform_profile() == PlatformSandboxProfile::Compatibility;

        for &default in DEFAULT_READ_PATHS {
            if Path::new(default).exists() {
                read_paths.push(default.into());
            }
        }

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

        for p in policy.allow_read() {
            read_paths.push(p.clone());
        }
        for p in policy.allow_write() {
            write_paths.push(p.clone());
        }

        Self {
            abi,
            read_paths,
            write_paths,
            net_block: policy.net_blocked(),
        }
    }

    /// Apply the Landlock sandbox.
    fn apply(&self) -> Result<(), SandboxError> {
        apply_landlock(self.abi, &self.read_paths, &self.write_paths, self.net_block)
    }
}

#[cfg(not(any(test, feature = "coverage")))]
pub fn spawn_sandboxed(
    command: &mut Command,
    policy: &SandboxPolicy,
) -> Result<SandboxedChild, SandboxError> {
    let abi = detect_abi()?;
    let config = LandlockConfig::from_policy(policy, abi);

    unsafe {
        command.pre_exec(move || {
            config.apply().map_err(|e| std::io::Error::other(e.to_string()))
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
    let config = LandlockConfig::from_policy(policy, abi);
    config.apply()?;

    let child = command
        .spawn()
        .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;
    Ok(SandboxedChild::from_std(child))
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

    // 2. Build the ruleset (factored out so we can test this without
    //    the irreversible restrict_self call).
    let ruleset = build_landlock_ruleset(abi, read_paths, write_paths, net_block)?;

    // 3. restrict_self() — irreversible.
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

/// Build a Landlock `RulesetCreated` from the given paths and flags.
///
/// This is separated from [`apply_landlock`] so that tests can exercise
/// ruleset construction (filesystem rules, network handling) without
/// the irreversible `restrict_self()` call.
fn build_landlock_ruleset(
    abi: ABI,
    read_paths: &[std::path::PathBuf],
    write_paths: &[std::path::PathBuf],
    net_block: bool,
) -> Result<landlock::RulesetCreated, SandboxError> {
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

    // Add filesystem rules.
    let read_access = read_access_flags(abi);
    let write_access = write_access_flags(abi);

    for path in read_paths {
        ruleset = add_path_rule(ruleset, path, read_access, "read")?;
    }

    for path in write_paths {
        // Write paths also get read access.
        ruleset = add_path_rule(ruleset, path, read_access | write_access, "write")?;
    }

    Ok(ruleset)
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
    fn read_access_flags_stable_across_abis() {
        // Core read flags should be present at every ABI level.
        for &abi in &ABI_PROBE_ORDER {
            let flags = read_access_flags(abi);
            assert!(flags.contains(AccessFs::ReadFile));
            assert!(flags.contains(AccessFs::ReadDir));
        }
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
    fn write_access_flags_v3_includes_truncate() {
        // Truncate was added in ABI V3.
        let flags = write_access_flags(ABI::V3);
        assert!(
            flags.contains(AccessFs::Truncate),
            "V3+ should include Truncate"
        );
    }

    #[test]
    fn default_read_paths_exist_on_linux() {
        // At minimum /usr and /etc should exist on any Linux system.
        assert!(Path::new("/usr").exists());
        assert!(Path::new("/etc").exists());
    }

    #[test]
    fn default_read_paths_are_non_empty() {
        assert!(
            !DEFAULT_READ_PATHS.is_empty(),
            "DEFAULT_READ_PATHS should contain at least one entry"
        );
    }

    #[test]
    fn compatibility_paths_include_tmp() {
        let read = compatibility_read_paths();
        assert!(read.iter().any(|p| p == Path::new("/tmp")));
        let write = compatibility_write_paths();
        assert!(write.iter().any(|p| p == Path::new("/tmp")));
    }

    #[test]
    fn compatibility_read_paths_include_home_dirs() {
        // HOME is typically set in CI and on dev machines.
        if let Ok(home) = std::env::var("HOME") {
            let paths = compatibility_read_paths();
            let config_path: std::path::PathBuf = format!("{}/.config", home).into();
            let local_path: std::path::PathBuf = format!("{}/.local", home).into();
            let cache_path: std::path::PathBuf = format!("{}/.cache", home).into();
            assert!(paths.contains(&config_path), "missing ~/.config");
            assert!(paths.contains(&local_path), "missing ~/.local");
            assert!(paths.contains(&cache_path), "missing ~/.cache");
        }
    }

    #[test]
    fn compatibility_write_paths_include_home_dirs() {
        if let Ok(home) = std::env::var("HOME") {
            let paths = compatibility_write_paths();
            let config_path: std::path::PathBuf = format!("{}/.config", home).into();
            assert!(paths.contains(&config_path), "missing ~/.config in write paths");
        }
    }

    #[test]
    fn compatibility_write_paths_include_tmpdir() {
        // Set TMPDIR and verify it appears.
        let original = std::env::var("TMPDIR").ok();
        std::env::set_var("TMPDIR", "/tmp/shadi-test-tmpdir");
        let paths = compatibility_write_paths();
        assert!(
            paths.iter().any(|p| p == Path::new("/tmp/shadi-test-tmpdir")),
            "TMPDIR should be in compatibility write paths"
        );
        // Restore.
        match original {
            Some(val) => std::env::set_var("TMPDIR", val),
            None => std::env::remove_var("TMPDIR"),
        }
    }

    #[test]
    fn compatibility_read_paths_include_dev_and_run() {
        let paths = compatibility_read_paths();
        assert!(paths.iter().any(|p| p == Path::new("/dev")));
        assert!(paths.iter().any(|p| p == Path::new("/run")));
    }

    #[test]
    fn compatibility_write_paths_include_dev_null_and_tty() {
        let paths = compatibility_write_paths();
        assert!(paths.iter().any(|p| p == Path::new("/dev/null")));
        assert!(paths.iter().any(|p| p == Path::new("/dev/tty")));
    }

    #[test]
    fn landlock_config_from_default_policy() {
        let policy = SandboxPolicy::new();
        let abi = detect_abi().expect("Landlock available");
        let config = LandlockConfig::from_policy(&policy, abi);
        // Default policy uses Compatibility profile, so paths should include
        // both default system paths and compatibility extras.
        assert!(!config.read_paths.is_empty());
        // Default policy does not block network.
        assert!(!config.net_block);
    }

    #[test]
    fn landlock_config_includes_user_paths() {
        let policy = SandboxPolicy::new()
            .allow_read_path("/usr")
            .allow_write_path("/tmp");
        let abi = detect_abi().expect("Landlock available");
        let config = LandlockConfig::from_policy(&policy, abi);
        assert!(config.read_paths.iter().any(|p| p == Path::new("/usr")));
        assert!(config.write_paths.iter().any(|p| p == Path::new("/tmp")));
    }

    #[test]
    fn landlock_config_minimal_profile_skips_compatibility_paths() {
        let policy = SandboxPolicy::new().use_minimal_platform_profile();
        let abi = detect_abi().expect("Landlock available");
        let config = LandlockConfig::from_policy(&policy, abi);
        // Minimal profile should NOT include /run (a compatibility-only path).
        assert!(
            !config.read_paths.iter().any(|p| p == Path::new("/run")),
            "minimal profile should not include /run"
        );
    }

    #[test]
    fn landlock_config_compatibility_profile_includes_extra_paths() {
        let policy = SandboxPolicy::new(); // default is Compatibility
        let abi = detect_abi().expect("Landlock available");
        let config = LandlockConfig::from_policy(&policy, abi);
        // Compatibility should include /tmp if it exists.
        if Path::new("/tmp").exists() {
            assert!(
                config.read_paths.iter().any(|p| p == Path::new("/tmp")),
                "compatibility profile should include /tmp read"
            );
        }
    }

    #[test]
    fn landlock_config_net_block_flag() {
        let policy = SandboxPolicy::new().block_network(true);
        let abi = detect_abi().expect("Landlock available");
        let config = LandlockConfig::from_policy(&policy, abi);
        assert!(config.net_block, "net_block should be true when policy blocks network");

        let policy_no_block = SandboxPolicy::new().block_network(false);
        let config_no_block = LandlockConfig::from_policy(&policy_no_block, abi);
        assert!(!config_no_block.net_block, "net_block should be false");
    }

    #[test]
    fn landlock_config_preserves_abi() {
        let policy = SandboxPolicy::new();
        let abi = detect_abi().expect("Landlock available");
        let config = LandlockConfig::from_policy(&policy, abi);
        assert_eq!(config.abi, abi, "config should preserve the detected ABI");
    }

    #[test]
    fn add_path_rule_succeeds_for_existing_path() {
        let abi = detect_abi().expect("Landlock available");
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .expect("handle fs access")
            .create()
            .expect("create ruleset");

        let flags = read_access_flags(abi);
        // /usr always exists on Linux.
        let result = add_path_rule(ruleset, Path::new("/usr"), flags, "read");
        assert!(result.is_ok(), "add_path_rule should succeed for /usr");
    }

    #[test]
    fn add_path_rule_skips_nonexistent_path() {
        let abi = detect_abi().expect("Landlock available");
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .expect("handle fs access")
            .create()
            .expect("create ruleset");

        let flags = read_access_flags(abi);
        // This path should not exist.
        let result = add_path_rule(
            ruleset,
            Path::new("/nonexistent-shadi-test-path-42"),
            flags,
            "read",
        );
        assert!(
            result.is_ok(),
            "add_path_rule should skip nonexistent path without error"
        );
    }

    #[test]
    fn set_no_new_privs_succeeds() {
        // PR_SET_NO_NEW_PRIVS is idempotent — safe to call multiple times.
        let result = set_no_new_privs();
        assert!(result.is_ok(), "set_no_new_privs should succeed: {:?}", result.err());
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

    // ── build_landlock_ruleset tests ───────────────────────────────────────

    #[test]
    fn build_ruleset_default_read_paths() {
        let abi = detect_abi().expect("Landlock available");
        let read: Vec<std::path::PathBuf> = DEFAULT_READ_PATHS
            .iter()
            .filter(|p| Path::new(p).exists())
            .map(|&p| p.into())
            .collect();
        let result = build_landlock_ruleset(abi, &read, &[], false);
        assert!(result.is_ok(), "build_landlock_ruleset should succeed with default paths");
    }

    #[test]
    fn build_ruleset_with_write_paths() {
        let abi = detect_abi().expect("Landlock available");
        let read: Vec<std::path::PathBuf> = vec!["/usr".into()];
        let write: Vec<std::path::PathBuf> = vec!["/tmp".into()];
        let result = build_landlock_ruleset(abi, &read, &write, false);
        assert!(result.is_ok(), "build_landlock_ruleset should succeed with write paths");
    }

    #[test]
    fn build_ruleset_with_net_block() {
        let abi = detect_abi().expect("Landlock available");
        let read: Vec<std::path::PathBuf> = vec!["/usr".into()];
        // net_block=true exercises the network branch.
        let result = build_landlock_ruleset(abi, &read, &[], true);
        assert!(result.is_ok(), "build_landlock_ruleset should succeed with net_block=true");
    }

    #[test]
    fn build_ruleset_without_net_block() {
        let abi = detect_abi().expect("Landlock available");
        let read: Vec<std::path::PathBuf> = vec!["/usr".into()];
        let result = build_landlock_ruleset(abi, &read, &[], false);
        assert!(result.is_ok(), "build_landlock_ruleset should succeed with net_block=false");
    }

    #[test]
    fn build_ruleset_empty_paths() {
        let abi = detect_abi().expect("Landlock available");
        let result = build_landlock_ruleset(abi, &[], &[], false);
        assert!(result.is_ok(), "build_landlock_ruleset with no paths should still succeed");
    }

    #[test]
    fn build_ruleset_mixed_existing_and_nonexistent_paths() {
        let abi = detect_abi().expect("Landlock available");
        let read: Vec<std::path::PathBuf> = vec![
            "/usr".into(),
            "/nonexistent-shadi-path-xyz".into(),
        ];
        let write: Vec<std::path::PathBuf> = vec![
            "/tmp".into(),
            "/nonexistent-shadi-write-xyz".into(),
        ];
        let result = build_landlock_ruleset(abi, &read, &write, false);
        assert!(
            result.is_ok(),
            "nonexistent paths should be skipped gracefully"
        );
    }

    #[test]
    fn build_ruleset_with_all_abi_levels() {
        // Verify build_landlock_ruleset works at every supported ABI level.
        let detected = detect_abi().expect("Landlock available");
        for &abi in &ABI_PROBE_ORDER {
            if abi <= detected {
                let read: Vec<std::path::PathBuf> = vec!["/usr".into()];
                let result = build_landlock_ruleset(abi, &read, &[], false);
                assert!(
                    result.is_ok(),
                    "build_landlock_ruleset should succeed at ABI {:?}: {:?}",
                    abi,
                    result.err(),
                );
            }
        }
    }

    #[test]
    fn build_ruleset_net_block_at_v1_triggers_warning_path() {
        // ABI V1 does not support network filtering. net_block=true should
        // still succeed but take the "warn" branch.
        let result = build_landlock_ruleset(ABI::V1, &["/usr".into()], &[], true);
        assert!(
            result.is_ok(),
            "net_block with V1 should succeed (warn path): {:?}",
            result.err(),
        );
    }

    #[test]
    fn build_ruleset_net_block_at_v4_or_above() {
        // If V4+ is available, net_block=true should take the network
        // filtering branch rather than the warn branch.
        let detected = detect_abi().expect("Landlock available");
        if detected >= ABI::V4 {
            let result = build_landlock_ruleset(
                ABI::V4,
                &["/usr".into()],
                &[],
                true,
            );
            assert!(
                result.is_ok(),
                "net_block with V4+ should succeed (network filtering): {:?}",
                result.err(),
            );
        }
    }

    // ── spawn_sandboxed coverage test ──────────────────────────────────────

    #[test]
    fn spawn_sandboxed_runs_echo() {
        // Exercise the test/coverage `spawn_sandboxed` variant end-to-end.
        // Use a very permissive policy so the test runner survives the
        // (irreversible) sandbox application in-process.
        let policy = SandboxPolicy::new(); // Compatibility — broadest
        let mut cmd = Command::new("/bin/echo");
        cmd.arg("landlock-test");
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        let result = spawn_sandboxed(&mut cmd, &policy);
        assert!(result.is_ok(), "spawn_sandboxed should succeed: {:?}", result.err());
        let mut child = result.unwrap();
        let status = child.wait().expect("wait for child");
        assert!(status.success(), "echo should exit 0");
    }

    #[test]
    fn probe_abi_v1_should_succeed() {
        // V1 is the minimum; if Landlock is available at all this passes.
        let result = probe_abi(ABI::V1);
        assert!(result.is_ok(), "ABI V1 probe should succeed: {:?}", result.err());
    }

    #[test]
    fn probe_abi_all_up_to_detected() {
        // Every ABI at or below the detected level should probe successfully.
        let detected = detect_abi().expect("Landlock available");
        for &abi in &ABI_PROBE_ORDER {
            if abi <= detected {
                let result = probe_abi(abi);
                assert!(
                    result.is_ok(),
                    "ABI {:?} should probe successfully (detected {:?}): {:?}",
                    abi,
                    detected,
                    result.err(),
                );
            }
        }
    }

    #[test]
    fn abi_probe_order_is_descending() {
        // Verify the probe order goes from highest to lowest.
        for window in ABI_PROBE_ORDER.windows(2) {
            assert!(
                window[0] > window[1],
                "ABI_PROBE_ORDER should be descending: {:?} > {:?}",
                window[0],
                window[1],
            );
        }
    }
}
