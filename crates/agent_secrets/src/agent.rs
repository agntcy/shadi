// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use crate::{AgentVerifier, SecretError, SecretResult, SecretStore};
use crate::memory::SecretBytes;
use crate::policy::SecretPolicy;
use crate::session::SessionContext;

pub struct AgentSecretAccess<'a> {
    store: &'a dyn SecretStore,
    verifier: &'a dyn AgentVerifier,
}

impl<'a> AgentSecretAccess<'a> {
    pub fn new(store: &'a dyn SecretStore, verifier: &'a dyn AgentVerifier) -> Self {
        Self { store, verifier }
    }

    pub fn put_for_session(
        &self,
        session: &SessionContext,
        key: &str,
        secret: &[u8],
        policy: SecretPolicy,
    ) -> SecretResult<()> {
        self.verifier.verify(session)?;
        self.store.put(key, secret, policy)
    }

    pub fn get_for_session(&self, session: &SessionContext, key: &str) -> SecretResult<SecretBytes> {
        self.verifier.verify(session)?;
        self.store.get(key)
    }

    pub fn delete_for_session(&self, session: &SessionContext, key: &str) -> SecretResult<()> {
        self.verifier.verify(session)?;
        self.store.delete(key)
    }

    pub fn require_verified(session: &SessionContext) -> SecretResult<()> {
        if session.verified {
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
    fn require_verified_accepts_verified_session() {
        let mut session = SessionContext::new("agent", "session");
        session.verified = true;
        AgentSecretAccess::require_verified(&session).unwrap();
    }

    #[test]
    fn require_verified_rejects_unverified_session() {
        let session = SessionContext::new("agent", "session");
        let err = AgentSecretAccess::require_verified(&session).unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));
    }
}
