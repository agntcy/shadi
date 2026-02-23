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
}
