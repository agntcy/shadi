// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The Tauri IPC command contract — see ../../docs/ipc-contract.md.
//!
//! `agentbridge`, `slim`, `sandbox`, policy query/patch/explain/diff, and
//! identity onboarding are implemented. DIR, remaining identity/secrets
//! commands, and trace/memory still return [`not_implemented`]
//! (agntcy/shadi#117, #119, #121).

pub mod agentbridge;
pub mod bootstrap;
pub mod dir;
pub mod identity;
pub mod policy;
pub mod sandbox;
pub mod slim;
pub mod trace_memory;

/// Placeholder error for every stub command. `issue` is the panel issue that
/// will replace this stub with a real implementation.
pub(crate) fn not_implemented<T>(issue: u32) -> Result<T, String> {
    Err(format!(
        "not implemented yet — see agntcy/shadi#{issue}"
    ))
}
