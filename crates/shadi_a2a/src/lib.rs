// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod channel;
mod locator;

pub use a2a_slimrpc::{register_collaborate, SlimRpcHandler, SLIM_SRC_METADATA_KEY};
pub use channel::{
    dest_did_from_message, insert_dest_did, A2AChannel, A2AChannelBuilder, A2AGroupChannel,
    A2AGroupChannelBuilder, GroupMember, A2A_DST_DID_METADATA_KEY, A2A_SRC_DID_METADATA_KEY,
};
pub use locator::{A2ABinding, A2ALocator};
