// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub agent_id: String,
    pub session_id: String,
    pub verified: bool,
    pub claims: Vec<String>,
    /// The peer's DID, once established for this session. `None` until an
    /// identity layer sets it (asserted by the caller in the app-layer phase;
    /// cryptographically proven from a DID-signed token in later phases).
    pub did: Option<String>,
}

impl SessionContext {
    pub fn new(agent_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            verified: false,
            claims: Vec::new(),
            did: None,
        }
    }

    /// Attach the peer's DID to this session context.
    pub fn with_did(mut self, did: impl Into<String>) -> Self {
        self.did = Some(did.into());
        self
    }
}
