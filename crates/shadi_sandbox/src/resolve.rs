// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Resolving a [`SandboxPolicy`] from layered inputs.
//!
//! Three layers, lowest precedence first: a named [`SandboxProfile`]'s
//! defaults, a policy file's values, then per-invocation overrides. Callers
//! keep their own on-disk and command-line types and map them onto
//! [`PolicyFileValues`] and [`PolicyOverrides`] here, so the layering rules
//! live in one place instead of being restated by every front end that has
//! to build a policy.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{field, info_span};

use crate::policy::{SandboxPolicy, SandboxProfile};

/// A policy file's sandbox-relevant values.
///
/// Paths here are lenient: one that does not exist on the current OS is
/// skipped rather than rejected, so a file can list a preset's macOS, Linux
/// and Windows paths together and still resolve everywhere.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PolicyFileValues {
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    /// `None` leaves the profile's own network default in place.
    pub net_block: Option<bool>,
    pub net_allow: Vec<String>,
    pub allow_command: Vec<String>,
    pub block_command: Vec<String>,
    /// Subtract these paths from compiled platform defaults and from allows.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Per-invocation overrides layered over the profile and the policy file.
///
/// Unlike [`PolicyFileValues`], paths here must exist: they name what this
/// specific run asked for, so a bad one is an error rather than something to
/// skip silently.
#[derive(Debug, Clone, Default)]
pub struct PolicyOverrides {
    /// `None` resolves to [`SandboxProfile::Balanced`].
    pub profile: Option<SandboxProfile>,
    pub allow: Vec<PathBuf>,
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub net_block: bool,
    pub net_allow: Vec<String>,
    pub allow_command: Vec<String>,
    pub deny: Vec<PathBuf>,
}

/// A resolved policy and the command sets that go with it.
#[derive(Debug)]
pub struct ResolvedPolicy {
    pub policy: SandboxPolicy,
    pub blocked: HashSet<String>,
    pub allow: HashSet<String>,
}

/// A resolved policy flattened for display or serialization.
///
/// `allow` holds the paths that are both readable and writable; `read` and
/// `write` hold the ones that are only one or the other.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyDescription {
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net_block: bool,
    pub net_allow: Vec<String>,
    pub platform_profile: String,
    pub allow_command: Vec<String>,
    pub block_command: Vec<String>,
    pub deny: Vec<String>,
}

/// Commands blocked unless a policy explicitly allows them: destructive
/// filesystem operations, privilege escalation, package managers and
/// anything that moves data off the machine.
pub fn default_blocked_commands() -> HashSet<&'static str> {
    [
        "rm", "rmdir", "shred", "srm", "dd", "mkfs", "fdisk", "parted", "wipefs", "chmod", "chown",
        "chgrp", "chattr", "shutdown", "reboot", "halt", "systemctl", "apt", "brew", "pip", "yum",
        "pacman", "mv", "cp", "truncate", "sudo", "su", "doas", "pkexec", "scp", "rsync", "sftp",
        "ftp",
    ]
    .into_iter()
    .collect()
}

/// Whether `cmd` is blocked: in the block set and not rescued by the allow set.
pub fn is_command_blocked(cmd: &str, blocked: &HashSet<String>, allow: &HashSet<String>) -> bool {
    blocked.contains(cmd) && !allow.contains(cmd)
}

pub fn canonicalize_path(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

/// Layer profile defaults, then file values, then overrides, into one policy.
pub fn resolve_policy(
    overrides: &PolicyOverrides,
    file_policy: &PolicyFileValues,
) -> Result<ResolvedPolicy, String> {
    let mut blocked = default_blocked_commands()
        .into_iter()
        .map(|cmd| cmd.to_string())
        .collect::<HashSet<_>>();
    for cmd in file_policy.block_command.iter() {
        blocked.insert(cmd.to_string());
    }

    let mut allow = file_policy
        .allow_command
        .iter()
        .map(|cmd| cmd.to_string())
        .collect::<HashSet<_>>();
    for cmd in overrides.allow_command.iter() {
        allow.insert(cmd.to_string());
    }

    let profile = overrides.profile.unwrap_or(SandboxProfile::Balanced);
    let span = info_span!(
        "shadi.policy.resolve",
        policy.allowed_paths = field::Empty,
        network.mode = field::Empty,
        policy.profile = %profile.as_str(),
    );
    let _guard = span.enter();

    let defaults = profile.defaults();
    let mut policy = SandboxPolicy::new()
        .block_network(overrides.net_block || file_policy.net_block.unwrap_or(defaults.net_block));

    for destination in &file_policy.net_allow {
        policy = policy.allow_network_destination(destination.clone());
    }
    for destination in &overrides.net_allow {
        policy = policy.allow_network_destination(destination.clone());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        policy = policy.use_minimal_platform_profile();
    }

    policy = apply_string_paths(policy, &defaults.read, PathMode::Read)?;
    policy = apply_string_paths(policy, &defaults.write, PathMode::Write)?;
    policy = apply_string_paths(policy, &defaults.allow, PathMode::Allow)?;

    policy = apply_preset_paths(policy, &file_policy.read, PathMode::Read);
    policy = apply_preset_paths(policy, &file_policy.write, PathMode::Write);
    policy = apply_preset_paths(policy, &file_policy.allow, PathMode::Allow);

    policy = apply_paths(policy, &overrides.read, PathMode::Read)?;
    policy = apply_paths(policy, &overrides.write, PathMode::Write)?;
    policy = apply_paths(policy, &overrides.allow, PathMode::Allow)?;

    policy = apply_deny_strings(policy, &file_policy.deny);
    policy = apply_deny_paths(policy, &overrides.deny);

    let allowed_paths = policy
        .allow_read()
        .iter()
        .chain(policy.allow_write().iter())
        .collect::<std::collections::BTreeSet<_>>();
    span.record("policy.allowed_paths", allowed_paths.len() as i64);
    let network_mode = if policy.net_blocked() { "blocked" } else { "allowed" };
    span.record("network.mode", field::display(network_mode));

    Ok(ResolvedPolicy {
        policy,
        blocked,
        allow,
    })
}

/// Flatten a resolved policy for display or serialization.
pub fn describe_policy(
    policy: &SandboxPolicy,
    blocked: &HashSet<String>,
    allow: &HashSet<String>,
) -> PolicyDescription {
    let is_writable = |path: &PathBuf| policy.allow_write().iter().any(|write| write == path);
    let is_readable = |path: &PathBuf| policy.allow_read().iter().any(|read| read == path);
    let display = |paths: Vec<&PathBuf>| {
        paths
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
    };

    let mut blocked_list = blocked.iter().cloned().collect::<Vec<_>>();
    blocked_list.sort();
    let mut allow_list = allow.iter().cloned().collect::<Vec<_>>();
    allow_list.sort();

    PolicyDescription {
        allow: display(policy.allow_read().iter().filter(|p| is_writable(p)).collect()),
        read: display(policy.allow_read().iter().filter(|p| !is_writable(p)).collect()),
        write: display(policy.allow_write().iter().filter(|p| !is_readable(p)).collect()),
        net_block: policy.net_blocked(),
        net_allow: policy.net_allow().to_vec(),
        platform_profile: policy.platform_profile().as_str().to_string(),
        allow_command: allow_list,
        block_command: blocked_list,
        deny: display(policy.deny().iter().collect()),
    }
}

enum PathMode {
    Read,
    Write,
    Allow,
}

impl PathMode {
    fn label(&self) -> &'static str {
        match self {
            PathMode::Read => "read",
            PathMode::Write => "write",
            PathMode::Allow => "allow",
        }
    }
}

/// Expand a leading `~` to `$HOME`. Policy files and profile defaults are
/// plain JSON/string data with no shell to do this for them, unlike
/// command-line paths (which the shell already expands before argv ever
/// reaches us).
fn expand_home(path: &str) -> PathBuf {
    expand_home_with(path, std::env::var("HOME").ok().as_deref())
}

fn expand_home_with(path: &str, home: Option<&str>) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => match home {
            Some(home) => PathBuf::from(home).join(rest),
            None => PathBuf::from(path),
        },
        None if path == "~" => home.map(PathBuf::from).unwrap_or_else(|| PathBuf::from(path)),
        None => PathBuf::from(path),
    }
}

fn apply_string_paths(
    mut policy: SandboxPolicy,
    paths: &[String],
    mode: PathMode,
) -> Result<SandboxPolicy, String> {
    for path in paths.iter() {
        let expanded = expand_home(path);
        let canonical = canonicalize_path(&expanded)
            .map_err(|err| format!("invalid {} path {}: {}", mode.label(), path, err))?;
        policy = apply_path(policy, &canonical, &mode);
    }
    Ok(policy)
}

/// Like [`apply_string_paths`], but skips paths that do not exist, so a
/// cross-platform preset resolves on every OS.
fn apply_preset_paths(mut policy: SandboxPolicy, paths: &[String], mode: PathMode) -> SandboxPolicy {
    for path in paths.iter() {
        if let Ok(canonical) = canonicalize_path(expand_home(path)) {
            policy = apply_path(policy, &canonical, &mode);
        }
    }
    policy
}

fn apply_paths(
    mut policy: SandboxPolicy,
    paths: &[PathBuf],
    mode: PathMode,
) -> Result<SandboxPolicy, String> {
    for path in paths.iter() {
        let path = canonicalize_path(path)
            .map_err(|err| format!("invalid {} path {}: {}", mode.label(), path.display(), err))?;
        policy = apply_path(policy, &path, &mode);
    }
    Ok(policy)
}

fn apply_path(policy: SandboxPolicy, path: &PathBuf, mode: &PathMode) -> SandboxPolicy {
    match mode {
        PathMode::Read => policy.allow_read_path(path),
        PathMode::Write => policy.allow_write_path(path),
        PathMode::Allow => policy.allow_read_path(path).allow_write_path(path),
    }
}

fn apply_deny_strings(mut policy: SandboxPolicy, paths: &[String]) -> SandboxPolicy {
    for path in paths {
        policy = remember_deny(policy, expand_home(path));
    }
    policy
}

fn apply_deny_paths(mut policy: SandboxPolicy, paths: &[PathBuf]) -> SandboxPolicy {
    for path in paths {
        policy = remember_deny(policy, path.clone());
    }
    policy
}

fn remember_deny(mut policy: SandboxPolicy, path: PathBuf) -> SandboxPolicy {
    policy = policy.deny_path(&path);
    if let Ok(canonical) = canonicalize_path(&path) {
        policy = policy.deny_path(canonical);
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static HOME_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn expand_home_replaces_leading_tilde() {
        assert_eq!(
            expand_home_with("~/.claude", Some("/Users/mo")),
            PathBuf::from("/Users/mo/.claude")
        );
        assert_eq!(expand_home_with("~", Some("/Users/mo")), PathBuf::from("/Users/mo"));
    }

    #[test]
    fn expand_home_leaves_other_paths_and_missing_home_untouched() {
        assert_eq!(
            expand_home_with("/already/absolute", Some("/Users/mo")),
            PathBuf::from("/already/absolute")
        );
        assert_eq!(expand_home_with("~/.claude", None), PathBuf::from("~/.claude"));
    }

    #[test]
    fn preset_paths_with_a_leading_tilde_resolve_under_home() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let home = tempfile::tempdir().expect("tempdir");
        let claude_dir = home.path().join(".claude");
        std::fs::create_dir(&claude_dir).expect("mkdir");

        let original = std::env::var("HOME").ok();
        std::env::set_var("HOME", home.path());
        let file_policy = PolicyFileValues {
            allow: vec!["~/.claude".to_string()],
            ..Default::default()
        };
        let resolved = resolve_policy(&PolicyOverrides::default(), &file_policy).expect("resolve");
        if let Some(value) = original {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }

        let canonical = canonicalize_path(&claude_dir).expect("canonical");
        assert!(resolved.policy.allow_read().contains(&canonical));
        assert!(resolved.policy.allow_write().contains(&canonical));
    }

    #[test]
    fn overrides_layer_over_the_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let overrides = PolicyOverrides {
            profile: Some(SandboxProfile::Strict),
            allow: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let resolved =
            resolve_policy(&overrides, &PolicyFileValues::default()).expect("resolve");

        let canonical = canonicalize_path(dir.path()).expect("canonical");
        assert!(resolved.policy.allow_read().contains(&canonical));
        assert!(resolved.policy.allow_write().contains(&canonical));
    }

    #[test]
    fn a_missing_file_path_is_skipped_but_a_missing_override_is_an_error() {
        let file_policy = PolicyFileValues {
            read: vec!["/definitely/not/here".to_string()],
            ..Default::default()
        };
        resolve_policy(&PolicyOverrides::default(), &file_policy)
            .expect("a missing policy-file path is skipped");

        let overrides = PolicyOverrides {
            read: vec![PathBuf::from("/definitely/not/here")],
            ..Default::default()
        };
        let err = resolve_policy(&overrides, &PolicyFileValues::default())
            .expect_err("a missing override path is rejected");
        assert!(err.contains("invalid read path"), "unexpected error: {err}");
    }

    #[test]
    fn net_block_comes_from_the_profile_unless_something_overrides_it() {
        let connected = PolicyOverrides {
            profile: Some(SandboxProfile::Connected),
            ..Default::default()
        };
        let resolved =
            resolve_policy(&connected, &PolicyFileValues::default()).expect("resolve");
        assert!(!resolved.policy.net_blocked(), "connected leaves network on");

        let file_policy = PolicyFileValues {
            net_block: Some(true),
            ..Default::default()
        };
        let resolved = resolve_policy(&connected, &file_policy).expect("resolve");
        assert!(resolved.policy.net_blocked(), "the file turns it back off");
    }

    #[test]
    fn file_and_override_commands_both_reach_the_allow_set() {
        let overrides = PolicyOverrides {
            allow_command: vec!["rm".to_string()],
            ..Default::default()
        };
        let file_policy = PolicyFileValues {
            allow_command: vec!["mv".to_string()],
            block_command: vec!["git".to_string()],
            ..Default::default()
        };
        let resolved = resolve_policy(&overrides, &file_policy).expect("resolve");

        assert!(!is_command_blocked("rm", &resolved.blocked, &resolved.allow));
        assert!(!is_command_blocked("mv", &resolved.blocked, &resolved.allow));
        assert!(is_command_blocked("git", &resolved.blocked, &resolved.allow));
        assert!(is_command_blocked("sudo", &resolved.blocked, &resolved.allow));
    }

    #[test]
    fn describe_policy_splits_read_write_and_both() {
        let dir = tempfile::tempdir().expect("tempdir");
        let read_only = dir.path().join("read");
        let write_only = dir.path().join("write");
        let both = dir.path().join("both");
        for path in [&read_only, &write_only, &both] {
            std::fs::create_dir(path).expect("mkdir");
        }

        let overrides = PolicyOverrides {
            read: vec![read_only.clone()],
            write: vec![write_only.clone()],
            allow: vec![both.clone()],
            ..Default::default()
        };
        let resolved =
            resolve_policy(&overrides, &PolicyFileValues::default()).expect("resolve");
        let described = describe_policy(&resolved.policy, &resolved.blocked, &resolved.allow);

        let canonical = |path: &PathBuf| {
            canonicalize_path(path)
                .expect("canonical")
                .display()
                .to_string()
        };
        assert!(described.allow.contains(&canonical(&both)));
        assert!(described.read.contains(&canonical(&read_only)));
        assert!(described.write.contains(&canonical(&write_only)));
        assert!(!described.read.contains(&canonical(&both)));
    }

    #[test]
    fn deny_paths_are_recorded_from_file_and_overrides() {
        let overrides = PolicyOverrides {
            deny: vec![PathBuf::from("/etc")],
            ..Default::default()
        };
        let file_policy = PolicyFileValues {
            deny: vec!["/tmp".to_string()],
            ..Default::default()
        };
        let resolved = resolve_policy(&overrides, &file_policy).expect("resolve");
        assert!(resolved.policy.path_is_denied(Path::new("/etc")));
        assert!(resolved.policy.path_is_denied(Path::new("/tmp")));
    }
}
