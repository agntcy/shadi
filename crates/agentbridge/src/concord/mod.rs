// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! CONCORD negotiation between agents over an A2A group.
//!
//! [`binding`] is how a CONCORD message sits in an A2A message. It needs
//! nothing beyond A2A. The rest is behind the `concord` feature and builds on
//! the `ioc-concord` library:
//!
//! - [`node`] runs the state machine for one agent, with a harness as its
//!   model.
//! - [`reply`] turns what the harness writes into a call the library accepts.
//! - [`channel`] is the broadcast channel a node talks through.

pub mod binding;

/// The CONCORD library the node is built on, so that a caller uses the
/// version this crate is pinned to.
#[cfg(feature = "concord")]
pub use ioc_concord;

#[cfg(feature = "concord")]
pub mod channel;
#[cfg(feature = "concord")]
pub mod node;
#[cfg(feature = "concord")]
pub mod reply;
