// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The Tauri IPC command contract — see ../../docs/ipc-contract.md.
//!
//! Every command here is a stub (agntcy/shadi#114): it defines the request
//! and response shapes the frontend can rely on, but returns
//! [`not_implemented`] instead of doing real work. Each panel issue
//! (agntcy/shadi#115-#121) replaces its own module's stubs with real calls
//! into the corresponding SHADI crate — the signatures below should not need
//! to change when that happens.

pub mod agentbridge;
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
