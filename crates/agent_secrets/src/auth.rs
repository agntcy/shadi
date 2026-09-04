// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use crate::{SecretError, SecretResult};
use crate::session::SessionContext;

pub trait AgentVerifier: Send + Sync {
    fn verify(&self, session: &SessionContext) -> SecretResult<()>;
}

pub struct NoopVerifier;

impl AgentVerifier for NoopVerifier {
    fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
        Err(SecretError::NotAuthorized)
    }
}

/// Accepts a session only when [`SessionContext::did`] was proven from a
/// signature on the message. A caller-set `verified` flag is not enough.
pub struct DidProofVerifier;

impl AgentVerifier for DidProofVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        if session.did_proven && session.did.as_ref().is_some_and(|did| !did.is_empty()) {
            Ok(())
        } else {
            Err(SecretError::NotAuthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_verifier_denies() {
        let verifier = NoopVerifier;
        let session = SessionContext::new("agent", "session");
        let err = verifier.verify(&session).unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));
    }

    #[test]
    fn did_proof_verifier_rejects_asserted_only_session() {
        let verifier = DidProofVerifier;
        let mut asserted = SessionContext::new("agent", "session");
        asserted.verified = true;
        asserted.did = Some("did:key:zexample".to_string());
        assert!(matches!(
            verifier.verify(&asserted),
            Err(SecretError::NotAuthorized)
        ));

        let proven = SessionContext::new("agent", "session").with_proven_did("did:key:zexample");
        verifier.verify(&proven).expect("proven DID must pass");
    }
}
