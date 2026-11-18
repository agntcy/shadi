// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The broadcast channel a node talks through.
//!
//! Every CONCORD message goes to every other member of the run, and a member
//! does not get its own back. The node is blocking and does not care how the
//! channel does that: a transport (an A2A group over SLIM) implements
//! [`Channel`].

use std::time::Duration;

/// One member's end of a broadcast group.
pub trait Channel: Send {
    /// Send `text` to every other member.
    fn broadcast(&mut self, text: &str) -> Result<(), String>;

    /// The next message from another member, waiting at most `wait`. `Ok(None)`
    /// when nothing came; `Err` when the channel is closed for good.
    fn recv(&mut self, wait: Duration) -> Result<Option<String>, String>;
}
