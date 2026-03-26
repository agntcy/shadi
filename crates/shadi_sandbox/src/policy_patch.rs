// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Incremental policy patch types for runtime sandbox policy updates.
//!
//! macOS Seatbelt profiles are compiled once at exec; filesystem and network
//! rules cannot be widened after `sandbox_init`. Only user-space axes (command
//! allow/block lists) can be applied instantly. Filesystem and network patches
//! are staged and reported as `PendingRestart` in the response.

use serde::{Deserialize, Serialize};

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
pub enum ControlMessage {
    /// Request the current effective policy.
    QueryPolicy,
    /// Submit a policy patch.
    Patch(PolicyPatch),
    /// Request that the running sandboxed process terminate.
    Terminate,
}

/// A wire-level response sent back over the control socket.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    /// Current effective policy (JSON value).
    Policy { policy: serde_json::Value },
    /// Result of a patch request.
    PatchResult(PolicyPatchResponse),
    /// Acknowledge a control action.
    Ack { message: String },
    /// Error response.
    Error { message: String },
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
}
