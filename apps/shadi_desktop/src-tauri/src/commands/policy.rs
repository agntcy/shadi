// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Policy inspector and editor (agntcy/shadi#116) — replaces `shadictl
//! shell`'s `/policy query|patch|explain|diff` and the `--profile` presets.
//!
//! `query` and `patch` reach a live session over its control socket;
//! `explain` and `diff` resolve a policy from its inputs without one, so
//! they answer what a set of flags *would* produce as well as what a running
//! session currently has. Both halves go through `shadi_sandbox`, so the
//! answers match what `shadictl` would give for the same inputs.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use shadi_sandbox::{
    control, PolicyDescription, PolicyFileValues, PolicyOverrides, PolicyPatch,
    PolicyPatchResponse, ResolvedPolicy, SandboxProfile,
};

/// Blocking round trip to a session's control socket, off the async runtime
/// — same reasoning as the sandbox panel's commands: the client is blocking
/// socket I/O, so this must not tie up a Tauri async worker.
async fn blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|err| format!("policy task failed: {err}"))?
}

/// Mirrors the JSON `handle_query` sends over the control socket
/// (`crates/shadictl/src/policy_watch.rs`) — the live effective policy of an
/// attached session, not shadictl's own private `SandboxPolicy` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivePolicySnapshot {
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub net_allow: Vec<String>,
    pub net_blocked: bool,
    pub allow_command: Vec<String>,
    pub block_command: Vec<String>,
    /// Filesystem and command changes staged by a prior patch, pending the
    /// restart that applies them.
    pub staged_read: Vec<String>,
    pub staged_write: Vec<String>,
    pub staged_allow: Vec<String>,
    /// The live network allowlist, when the session's proxy applied a
    /// network patch immediately rather than staging it.
    pub net_allow_live: Option<Vec<String>>,
}

/// The policy a sandbox is launched with (`sandbox_launch`'s
/// `LaunchSandboxRequest`) — a config to build a fresh `SandboxPolicy` from,
/// not the live, already-resolved shape `LivePolicySnapshot` reads back.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net_block: bool,
    pub net_allow: Vec<String>,
    /// "strict" | "balanced" | "connected", matching `shadictl --profile`.
    pub profile: Option<String>,
}

/// What to resolve a policy from: a named profile, an optional policy file,
/// and the overrides layered on top — the same three inputs `shadictl policy
/// explain` takes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PolicyInputs {
    pub profile: Option<String>,
    pub policy_file: Option<String>,
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net_block: bool,
    pub net_allow: Vec<String>,
    pub allow_command: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyExplanation {
    pub effective: PolicyDescription,
    pub sources: PolicySources,
    /// The attached session's live policy, when one was given. A session that
    /// has been patched since it started will not match `effective`, which is
    /// what these inputs resolve to rather than what is currently running.
    pub live: Option<LivePolicySnapshot>,
}

/// Where each part of the effective policy came from.
#[derive(Debug, Clone, Serialize)]
pub struct PolicySources {
    pub profile: String,
    pub profile_defaults: ProfileDefaultsView,
    pub policy_file: Option<PolicyFileSource>,
    pub overrides: PolicyInputsView,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileDefaultsView {
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net_block: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyFileSource {
    pub path: String,
    pub values: PolicyFileValues,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyInputsView {
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net_block: bool,
    pub net_allow: Vec<String>,
    pub allow_command: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyDiff {
    pub equivalent: bool,
    pub changed: Vec<PolicyFieldDiff>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyFieldDiff {
    pub field: String,
    pub current: Vec<String>,
    pub baseline: Vec<String>,
}

/// Show the effective policy of the attached session (`/policy query`).
#[tauri::command]
pub async fn policy_query(socket_path: String) -> Result<LivePolicySnapshot, String> {
    blocking(move || {
        let value = control::query_policy(&PathBuf::from(socket_path))?;
        serde_json::from_value(value)
            .map_err(|err| format!("session returned an unexpected policy shape: {err}"))
    })
    .await
}

/// Patch the policy of the attached session live (`/policy patch`).
#[tauri::command]
pub async fn policy_patch(
    socket_path: String,
    patch: PolicyPatch,
) -> Result<PolicyPatchResponse, String> {
    blocking(move || control::send_patch(&PathBuf::from(socket_path), &patch)).await
}

fn parse_profile(name: Option<&str>) -> Result<SandboxProfile, String> {
    match name {
        Some(name) => SandboxProfile::from_name(name).ok_or_else(|| {
            format!("unknown profile '{name}'; expected strict, balanced or connected")
        }),
        None => Ok(SandboxProfile::Balanced),
    }
}

/// Read the sandbox-relevant values out of a policy file. Fields the file
/// carries for other purposes (shadictl's keychain and trusted-secret rules)
/// are ignored rather than rejected.
fn read_policy_file(path: &str) -> Result<PolicyFileValues, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|err| format!("could not read policy file {path}: {err}"))?;
    serde_json::from_str(&data).map_err(|err| format!("{path} is not a valid policy file: {err}"))
}

fn resolve(inputs: &PolicyInputs) -> Result<(ResolvedPolicy, SandboxProfile, PolicyFileValues), String> {
    let profile = parse_profile(inputs.profile.as_deref())?;
    let file_values = match inputs.policy_file.as_deref() {
        Some(path) => read_policy_file(path)?,
        None => PolicyFileValues::default(),
    };

    let overrides = PolicyOverrides {
        profile: Some(profile),
        allow: inputs.allow.iter().map(PathBuf::from).collect(),
        read: inputs.read.iter().map(PathBuf::from).collect(),
        write: inputs.write.iter().map(PathBuf::from).collect(),
        net_block: inputs.net_block,
        net_allow: inputs.net_allow.clone(),
        allow_command: inputs.allow_command.clone(),
    };

    let resolved = shadi_sandbox::resolve_policy(&overrides, &file_values)?;
    Ok((resolved, profile, file_values))
}

fn describe(inputs: &PolicyInputs) -> Result<PolicyDescription, String> {
    let (resolved, _, _) = resolve(inputs)?;
    Ok(shadi_sandbox::describe_policy(
        &resolved.policy,
        &resolved.blocked,
        &resolved.allow,
    ))
}

/// Resolved policy plus source inputs (`/policy explain`).
#[tauri::command]
pub async fn policy_explain(
    inputs: PolicyInputs,
    socket_path: Option<String>,
) -> Result<PolicyExplanation, String> {
    blocking(move || {
        let (resolved, profile, file_values) = resolve(&inputs)?;
        let defaults = profile.defaults();

        let live = match socket_path.as_deref() {
            Some(path) => control::query_policy(&PathBuf::from(path))
                .ok()
                .and_then(|value| serde_json::from_value(value).ok()),
            None => None,
        };

        Ok(PolicyExplanation {
            effective: shadi_sandbox::describe_policy(
                &resolved.policy,
                &resolved.blocked,
                &resolved.allow,
            ),
            sources: PolicySources {
                profile: profile.as_str().to_string(),
                profile_defaults: ProfileDefaultsView {
                    allow: defaults.allow,
                    read: defaults.read,
                    write: defaults.write,
                    net_block: defaults.net_block,
                },
                policy_file: inputs.policy_file.clone().map(|path| PolicyFileSource {
                    path,
                    values: file_values,
                }),
                overrides: PolicyInputsView {
                    allow: inputs.allow.clone(),
                    read: inputs.read.clone(),
                    write: inputs.write.clone(),
                    net_block: inputs.net_block,
                    net_allow: inputs.net_allow.clone(),
                    allow_command: inputs.allow_command.clone(),
                },
            },
            live,
        })
    })
    .await
}

/// Diff a resolved policy against a baseline profile's own (`/policy diff`).
#[tauri::command]
pub async fn policy_diff(
    inputs: PolicyInputs,
    baseline_profile: String,
) -> Result<PolicyDiff, String> {
    blocking(move || {
        let current = describe(&inputs)?;
        let baseline = describe(&PolicyInputs {
            profile: Some(baseline_profile),
            ..Default::default()
        })?;

        let mut changed = Vec::new();
        let mut compare = |field: &str, current: &[String], baseline: &[String]| {
            if current != baseline {
                changed.push(PolicyFieldDiff {
                    field: field.to_string(),
                    current: current.to_vec(),
                    baseline: baseline.to_vec(),
                });
            }
        };

        compare("allow", &current.allow, &baseline.allow);
        compare("read", &current.read, &baseline.read);
        compare("write", &current.write, &baseline.write);
        compare("net_allow", &current.net_allow, &baseline.net_allow);
        compare("allow_command", &current.allow_command, &baseline.allow_command);
        compare("block_command", &current.block_command, &baseline.block_command);
        if current.net_block != baseline.net_block {
            changed.push(PolicyFieldDiff {
                field: "net_block".to_string(),
                current: vec![current.net_block.to_string()],
                baseline: vec![baseline.net_block.to_string()],
            });
        }

        Ok(PolicyDiff {
            equivalent: changed.is_empty(),
            changed,
        })
    })
    .await
}

/// The named profile presets `shadictl --profile` accepts.
#[tauri::command]
pub async fn policy_profiles() -> Result<Vec<String>, String> {
    Ok(vec!["strict".into(), "balanced".into(), "connected".into()])
}
