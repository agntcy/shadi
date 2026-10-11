// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The Tauri IPC command contract — see ../../docs/ipc-contract.md.
//!
//! `agentbridge`, `slim`, `sandbox`, policy query/patch/explain/diff, and
//! identity, secrets, DIR, and trace/memory are implemented, plus an
//! embedded `shadictl` terminal.

pub mod agentbridge;
pub mod bootstrap;
pub mod channel_manager;
pub mod dir;
pub mod identity;
pub mod owner;
pub mod policy;
pub mod sandbox;
pub mod slim;
pub mod terminal;
pub mod trace_memory;
