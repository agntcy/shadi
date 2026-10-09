// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Incremental policy patch types for runtime sandbox policy updates.
//!
//! macOS Seatbelt profiles are compiled once at exec; filesystem and network
//! rules cannot be widened after `sandbox_init`. Only user-space axes (command
//! allow/block lists) can be applied instantly. Filesystem and network patches
//! are staged and reported as `PendingRestart` in the response.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::net_proxy::normalize_net_allow;

/// An incremental patch to the effective sandbox policy.
///
/// All fields are additive or subtractive lists.  Omitted (empty) fields leave
/// the corresponding policy axis unchanged.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PolicyPatch {
    /// Paths to add to the read-write allowlist.
    #[serde(default)]
    pub add_allow: Vec<String>,
    /// Paths to add to the read-only allowlist.
    #[serde(default)]
    pub add_read: Vec<String>,
    /// Paths to add to the write-only allowlist.
    #[serde(default)]
    pub add_write: Vec<String>,

    /// Commands to add to the allow set (overrides the blocklist).
    #[serde(default)]
    pub add_allow_command: Vec<String>,
    /// Commands to remove from the allow set.
    #[serde(default)]
    pub remove_allow_command: Vec<String>,
    /// Commands to add to the block set.
    #[serde(default)]
    pub add_block_command: Vec<String>,
    /// Commands to remove from the block set.
    #[serde(default)]
    pub remove_block_command: Vec<String>,

    /// Network destinations to add to the allowlist.
    #[serde(default)]
    pub add_net_allow: Vec<String>,
    /// Network destinations to remove from the allowlist.
    #[serde(default)]
    pub remove_net_allow: Vec<String>,
}

/// Outcome for each axis of a policy patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchAxisStatus {
    /// The change was applied immediately.
    Applied,
    /// The change was staged but requires a process restart to take effect
    /// (kernel sandbox cannot be updated at runtime).
    PendingRestart,
    /// No change was requested for this axis.
    Unchanged,
    /// The change was rejected (e.g. invalid path).
    Rejected,
}

/// Response returned after evaluating a policy patch.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyPatchResponse {
    /// Whether the overall patch was accepted (possibly partially).
    pub accepted: bool,
    /// Status for filesystem path additions.
    pub filesystem: PatchAxisStatus,
    /// Status for command allow/block changes.
    pub commands: PatchAxisStatus,
    /// Status for network allow changes.
    pub network: PatchAxisStatus,
    /// Human-readable message.
    #[serde(default)]
    pub message: String,
    /// Axes that need a restart to take effect.
    #[serde(default)]
    pub pending_restart: Vec<String>,
}

/// A wire-level message sent over the control socket.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum ControlMessage {
    /// Request the current effective policy.
    QueryPolicy,
    /// Submit a policy patch.
    Patch(PolicyPatch),
    /// Request that the running sandboxed process terminate.
    Terminate,
    /// Request resource usage of the sandboxed child process.
    QueryResources,
}

/// Resource usage of the sandboxed child process.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProcessResources {
    /// PID of the sandboxed child process.
    pub pid: u32,
    /// Resident set size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    /// Virtual memory size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_bytes: Option<u64>,
    /// Total user CPU time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_user_ms: Option<u64>,
    /// Total system CPU time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_system_ms: Option<u64>,
    /// Thread count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_count: Option<u32>,
}

/// A wire-level response sent back over the control socket.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    /// Current effective policy (JSON value).
    Policy { policy: serde_json::Value },
    /// Result of a patch request.
    PatchResult(PolicyPatchResponse),
    /// Resource usage of the sandboxed child.
    Resources(ProcessResources),
    /// Acknowledge a control action.
    Ack { message: String },
    /// Error response.
    Error { message: String },
}

/// Mutable axes a [`PolicyPatch`] can change. The control-socket listener
/// maps live session state onto this so the apply path can be fuzzed
/// without a Unix socket or a `Mutex`.
#[derive(Debug, Clone, Default)]
pub struct PatchState {
    pub allow: HashSet<String>,
    pub blocked: HashSet<String>,
    pub staged_read: Vec<String>,
    pub staged_write: Vec<String>,
    pub staged_allow: Vec<String>,
    pub net_allow: Vec<String>,
    /// When false, network changes are rejected (kernel sandbox cannot
    /// update in place and a restart would kill the workload).
    pub has_live_proxy: bool,
}

/// Apply a patch to [`PatchState`]. Command changes take effect immediately;
/// filesystem paths are staged; network changes apply only when a live
/// proxy allowlist is present.
pub fn apply_policy_patch(state: &mut PatchState, patch: &PolicyPatch) -> PolicyPatchResponse {
    let mut commands_status = PatchAxisStatus::Unchanged;
    let mut fs_status = PatchAxisStatus::Unchanged;
    let mut net_status = PatchAxisStatus::Unchanged;
    let mut pending_restart = Vec::new();

    let has_cmd_changes = !patch.add_allow_command.is_empty()
        || !patch.remove_allow_command.is_empty()
        || !patch.add_block_command.is_empty()
        || !patch.remove_block_command.is_empty();

    if has_cmd_changes {
        for cmd in &patch.add_allow_command {
            state.allow.insert(cmd.clone());
        }
        for cmd in &patch.remove_allow_command {
            state.allow.remove(cmd);
        }
        for cmd in &patch.add_block_command {
            state.blocked.insert(cmd.clone());
        }
        for cmd in &patch.remove_block_command {
            state.blocked.remove(cmd);
        }
        commands_status = PatchAxisStatus::Applied;
    }

    let has_fs_changes =
        !patch.add_read.is_empty() || !patch.add_write.is_empty() || !patch.add_allow.is_empty();

    if has_fs_changes {
        state.staged_read.extend(patch.add_read.iter().cloned());
        state.staged_write.extend(patch.add_write.iter().cloned());
        state.staged_allow.extend(patch.add_allow.iter().cloned());
        fs_status = PatchAxisStatus::PendingRestart;
        pending_restart.push("filesystem".to_string());
    }

    let has_net_changes = !patch.add_net_allow.is_empty() || !patch.remove_net_allow.is_empty();

    if has_net_changes {
        if state.has_live_proxy {
            for dest in &patch.add_net_allow {
                let entry = normalize_net_allow(dest);
                if !state.net_allow.contains(&entry) {
                    state.net_allow.push(entry);
                }
            }
            for dest in &patch.remove_net_allow {
                let entry = normalize_net_allow(dest);
                state.net_allow.retain(|d| d != &entry);
            }
            net_status = PatchAxisStatus::Applied;
        } else {
            net_status = PatchAxisStatus::Rejected;
        }
    }

    let accepted = commands_status != PatchAxisStatus::Rejected
        && fs_status != PatchAxisStatus::Rejected
        && net_status != PatchAxisStatus::Rejected;

    let message = if pending_restart.is_empty() {
        "patch applied".to_string()
    } else {
        format!(
            "patch accepted; staged axes ({}) require manual process restart",
            pending_restart.join(", ")
        )
    };

    PolicyPatchResponse {
        accepted,
        filesystem: fs_status,
        commands: commands_status,
        network: net_status,
        message,
        pending_restart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_round_trips_through_json() {
        let patch = PolicyPatch {
            add_allow_command: vec!["npm".to_string()],
            add_block_command: vec!["curl".to_string()],
            add_read: vec!["/opt/new-tool".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&patch).expect("serialize");
        let back: PolicyPatch = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.add_allow_command, vec!["npm"]);
        assert_eq!(back.add_block_command, vec!["curl"]);
        assert_eq!(back.add_read, vec!["/opt/new-tool"]);
    }

    #[test]
    fn control_message_round_trips() {
        let msg = ControlMessage::Patch(PolicyPatch {
            add_allow_command: vec!["node".to_string()],
            ..Default::default()
        });
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: ControlMessage = serde_json::from_str(&json).expect("deserialize");
        match back {
            ControlMessage::Patch(p) => assert_eq!(p.add_allow_command, vec!["node"]),
            _ => panic!("expected Patch"),
        }
    }

    #[test]
    fn control_response_round_trips() {
        let resp = ControlResponse::PatchResult(PolicyPatchResponse {
            accepted: true,
            filesystem: PatchAxisStatus::PendingRestart,
            commands: PatchAxisStatus::Applied,
            network: PatchAxisStatus::Unchanged,
            message: "partial".to_string(),
            pending_restart: vec!["filesystem".to_string()],
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: ControlResponse = serde_json::from_str(&json).expect("deserialize");
        match back {
            ControlResponse::PatchResult(r) => {
                assert!(r.accepted);
                assert_eq!(r.filesystem, PatchAxisStatus::PendingRestart);
                assert_eq!(r.commands, PatchAxisStatus::Applied);
            }
            _ => panic!("expected PatchResult"),
        }
    }

    #[test]
    fn empty_patch_defaults() {
        let patch: PolicyPatch = serde_json::from_str("{}").expect("deserialize");
        assert!(patch.add_allow.is_empty());
        assert!(patch.add_allow_command.is_empty());
        assert!(patch.add_net_allow.is_empty());
    }

    #[test]
    fn query_policy_message_round_trips() {
        let msg = ControlMessage::QueryPolicy;
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: ControlMessage = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(back, ControlMessage::QueryPolicy));
    }

    #[test]
    fn terminate_message_round_trips() {
        let msg = ControlMessage::Terminate;
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: ControlMessage = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(back, ControlMessage::Terminate));
    }

    #[test]
    fn ack_response_round_trips() {
        let resp = ControlResponse::Ack {
            message: "termination requested".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: ControlResponse = serde_json::from_str(&json).expect("deserialize");
        match back {
            ControlResponse::Ack { message } => assert_eq!(message, "termination requested"),
            _ => panic!("expected Ack"),
        }
    }

    #[test]
    fn query_resources_message_round_trips() {
        let msg = ControlMessage::QueryResources;
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: ControlMessage = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(back, ControlMessage::QueryResources));
    }

    #[test]
    fn a_runtime_net_allow_keeps_its_port() {
        let mut state = PatchState {
            has_live_proxy: true,
            ..PatchState::default()
        };
        let add = PolicyPatch {
            add_net_allow: vec!["https://Example.com:443/".into(), "example.org".into()],
            ..PolicyPatch::default()
        };
        apply_policy_patch(&mut state, &add);
        assert_eq!(state.net_allow, ["example.com:443", "example.org"]);

        // Removal matches the entry as normalized, port included.
        let remove = PolicyPatch {
            remove_net_allow: vec!["example.com".into(), "EXAMPLE.org".into()],
            ..PolicyPatch::default()
        };
        apply_policy_patch(&mut state, &remove);
        assert_eq!(state.net_allow, ["example.com:443"]);
    }

    #[test]
    fn apply_policy_patch_stages_fs_and_rejects_net_without_proxy() {
        let mut state = PatchState::default();
        let patch = PolicyPatch {
            add_allow_command: vec!["npm".to_string()],
            add_read: vec!["/opt/tool".to_string()],
            add_net_allow: vec!["https://example.com/".to_string()],
            ..Default::default()
        };
        let result = apply_policy_patch(&mut state, &patch);
        assert!(state.allow.contains("npm"));
        assert_eq!(state.staged_read, vec!["/opt/tool".to_string()]);
        assert!(result.pending_restart.contains(&"filesystem".to_string()));
        assert_eq!(result.network, PatchAxisStatus::Rejected);
        assert!(state.net_allow.is_empty());
    }

    #[test]
    fn apply_policy_patch_normalizes_net_allow_with_proxy() {
        let mut state = PatchState {
            has_live_proxy: true,
            ..Default::default()
        };
        let patch = PolicyPatch {
            add_net_allow: vec!["https://Example.com:443/path".to_string()],
            ..Default::default()
        };
        let result = apply_policy_patch(&mut state, &patch);
        assert_eq!(result.network, PatchAxisStatus::Applied);
        // The port stays: the proxy enforces it (agntcy/shadi#430).
        assert_eq!(state.net_allow, vec!["example.com:443".to_string()]);
    }

    #[test]
    fn resources_response_round_trips() {
        let resp = ControlResponse::Resources(ProcessResources {
            pid: 42,
            rss_bytes: Some(1024 * 1024),
            virtual_bytes: Some(128 * 1024 * 1024),
            cpu_user_ms: Some(500),
            cpu_system_ms: Some(100),
            thread_count: Some(4),
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: ControlResponse = serde_json::from_str(&json).expect("deserialize");
        match back {
            ControlResponse::Resources(r) => {
                assert_eq!(r.pid, 42);
                assert_eq!(r.rss_bytes, Some(1024 * 1024));
                assert_eq!(r.thread_count, Some(4));
            }
            _ => panic!("expected Resources"),
        }
    }
}
