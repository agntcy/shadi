// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub agent_id: String,
    pub session_id: String,
    pub verified: bool,
    pub claims: Vec<String>,
    /// The peer's DID, once established for this session. `None` until an
    /// identity layer sets it. On the agentbridge SLIM path this is proven
    /// from a DID-signed payload (`did_proven`); a locally set `verified`
    /// bool is not application auth.
    pub did: Option<String>,
    /// True only after a signature on the message bound this [`did`].
    pub did_proven: bool,
}

impl SessionContext {
    pub fn new(agent_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            verified: false,
            claims: Vec::new(),
            did: None,
            did_proven: false,
        }
    }

    /// Attach a DID that has not been proven. Not sufficient for the
    /// agentbridge SLIM send/recv gate.
    pub fn with_did(mut self, did: impl Into<String>) -> Self {
        self.did = Some(did.into());
        self.did_proven = false;
        self
    }

    /// Attach a DID that was verified from a signature on the message.
    pub fn with_proven_did(mut self, did: impl Into<String>) -> Self {
        self.did = Some(did.into());
        self.did_proven = true;
        self.verified = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_did_does_not_mark_proven() {
        let session = SessionContext::new("agent", "s").with_did("did:key:zexample");
        assert_eq!(session.did.as_deref(), Some("did:key:zexample"));
        assert!(!session.did_proven);
        assert!(!session.verified);
    }

    #[test]
    fn with_proven_did_sets_proof_and_verified() {
        let session = SessionContext::new("agent", "s").with_proven_did("did:key:zexample");
        assert!(session.did_proven);
        assert!(session.verified);
    }
}
