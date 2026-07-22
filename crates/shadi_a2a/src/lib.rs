// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod channel;

pub use channel::{A2AChannel, A2AChannelBuilder, A2AGroupChannel, A2AGroupChannelBuilder};
pub use a2a_slimrpc::{SLIM_SRC_METADATA_KEY, SlimRpcHandler, register_collaborate};
