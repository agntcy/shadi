// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod channel;
mod locator;
pub mod message_content;
mod trace_context;

pub use channel::{
    challenge_from_message, dest_did_from_message, insert_challenge, insert_dest_did,
    request_context, A2AChannel, A2AChannelBuilder, A2AGroupChannel, A2AGroupChannelBuilder,
    GroupMember, A2A_CHALLENGE_METADATA_KEY, A2A_DST_DID_METADATA_KEY, A2A_SRC_DID_METADATA_KEY,
};
pub use locator::{A2ABinding, A2ALocator};
pub use trace_context::set_remote_parent;
pub use a2a_slimrpc::{
    SLIM_PEER_SUBJECT_METADATA_KEY, SLIM_SRC_METADATA_KEY, SlimRpcHandler, register_collaborate,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The key under which SLIM's verified session peer reaches a handler.
    /// Open admission relies on it, so a rename upstream must fail here.
    #[test]
    fn the_session_peer_key_is_the_one_slim_sets() {
        assert_eq!(SLIM_PEER_SUBJECT_METADATA_KEY, "slim-peer-subject");
    }
}
