// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod native;
mod stdio_bridge;

use agent_secrets::{AgentVerifier, SecretError, SecretResult, SecretStore, SessionContext};
use shadi_identity::{
    looks_like_did_proof, unwrap_signed_message, wrap_signed_message, Admission, Admitter,
    AgentIdentity,
};

pub use native::{NativeSlimBootstrap, NativeSlimSession};
pub use stdio_bridge::{
    bridge_usage, parse_bridge_args, run_stdio_bridge, start_bridge_with_io, BridgeArgs,
    BridgeReport, BridgeSessionInfo, RunningBridge,
};

pub trait SlimSession: Send + Sync {
    fn send(&self, message: &[u8]) -> SecretResult<()>;
    fn recv(&self) -> SecretResult<Vec<u8>>;
}

pub struct SecureAgentChannel<'a> {
    session: &'a dyn SlimSession,
    verifier: &'a dyn AgentVerifier,
    store: &'a dyn SecretStore,
    /// When set, send wraps the payload in a DID-proof envelope and recv
    /// requires a valid envelope. This is the agentbridge SLIM path.
    signer: Option<&'a AgentIdentity>,
    /// When set, an inbound peer must also be attested and policy-permitted,
    /// not merely in possession of a key. The same gate the A2A path applies.
    admitter: Option<&'a Admitter>,
}

impl<'a> SecureAgentChannel<'a> {
    pub fn new(
        session: &'a dyn SlimSession,
        verifier: &'a dyn AgentVerifier,
        store: &'a dyn SecretStore,
    ) -> Self {
        Self {
            session,
            verifier,
            store,
            signer: None,
            admitter: None,
        }
    }

    /// Prove the agent DID on every send/recv. The verifier sees a
    /// [`SessionContext`] with `did_proven` only after the signature checks.
    pub fn with_signer(mut self, identity: &'a AgentIdentity) -> Self {
        self.signer = Some(identity);
        self
    }

    /// Also require that an authority vouches for an inbound peer's DID.
    ///
    /// SLIM carries no A2A metadata, so there is no principal hint on this
    /// path: anchors that need one abstain. A SLIM-first deployment therefore
    /// wants an anchor that resolves a DID without a hint, such as
    /// `LocalAnchor`, rather than `GithubAnchor`.
    pub fn with_admitter(mut self, admitter: &'a Admitter) -> Self {
        self.admitter = Some(admitter);
        self
    }

    pub fn send(&self, ctx: &SessionContext, message: &[u8]) -> SecretResult<()> {
        let outgoing = if let Some(identity) = self.signer {
            wrap_signed_message(identity, message).map_err(|_| SecretError::NotAuthorized)?
        } else {
            message.to_vec()
        };
        self.authorize_bytes(ctx, &outgoing, Direction::Outbound)?;
        let _ = self.store;
        self.session.send(&outgoing)
    }

    pub fn recv(&self, ctx: &SessionContext) -> SecretResult<Vec<u8>> {
        let raw = self.session.recv()?;
        if self.signer.is_some() || looks_like_did_proof(&raw) {
            let proven = self.authorize_bytes(ctx, &raw, Direction::Inbound)?;
            return Ok(proven.unwrap_or(raw));
        }
        self.verifier.verify(ctx)?;
        let _ = self.store;
        Ok(raw)
    }

    /// Verify a DID-proof envelope (or reject unsigned bytes on a proven
    /// channel). Returns the inner payload when an envelope was present.
    fn authorize_bytes(
        &self,
        ctx: &SessionContext,
        bytes: &[u8],
        direction: Direction,
    ) -> SecretResult<Option<Vec<u8>>> {
        if looks_like_did_proof(bytes) {
            let verified = unwrap_signed_message(bytes).map_err(|_| SecretError::NotAuthorized)?;
            if let Some(expected) = ctx.did.as_deref() {
                if expected != verified.did {
                    // Mesh member presenting another agent's DID.
                    return Err(SecretError::NotAuthorized);
                }
            }
            // The same policy gate the A2A path applies in
            // `admit_incoming_message`, so a peer rejected there is not
            // accepted here. Inbound only: `send` runs this on its own
            // outgoing bytes, and a sender must not have to be admitted by
            // its own policy to speak.
            if let (Direction::Inbound, Some(admitter)) = (direction, self.admitter) {
                match admitter.admit(&verified.did, None) {
                    Admission::Admitted { .. } => {}
                    // `SecretError`'s variants carry no payload, so the reason
                    // dies at this boundary — log it or the operator sees a
                    // bare "not authorized".
                    denied => {
                        tracing::warn!(did = %verified.did, "SLIM peer not admitted: {denied:?}");
                        return Err(SecretError::NotAuthorized);
                    }
                }
            }
            let proven = ctx.clone().with_proven_did(&verified.did);
            self.verifier.verify(&proven)?;
            return Ok(Some(verified.payload));
        }
        if self.signer.is_some() {
            return Err(SecretError::NotAuthorized);
        }
        self.verifier.verify(ctx)?;
        Ok(None)
    }
}

/// Which way the bytes are travelling. Only an inbound peer is subject to
/// admission policy.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_secrets::{SecretError, SecretStore};
    use agent_secrets::policy::SecretPolicy;
    use agent_secrets::memory::SecretBytes;
    use std::sync::Mutex;

    struct AllowVerifier;

    impl AgentVerifier for AllowVerifier {
        fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
            Ok(())
        }
    }

    struct DenyVerifier;

    impl AgentVerifier for DenyVerifier {
        fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
            Err(SecretError::NotAuthorized)
        }
    }

    struct MemoryStore;

    impl SecretStore for MemoryStore {
        fn put(&self, _key: &str, _secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
            Ok(())
        }

        fn get(&self, _key: &str) -> SecretResult<SecretBytes> {
            Err(SecretError::InvalidInput)
        }

        fn delete(&self, _key: &str) -> SecretResult<()> {
            Ok(())
        }

        fn list_keys(&self) -> SecretResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    struct TestSession {
        sent: Mutex<Vec<u8>>,
        recv_data: Vec<u8>,
    }

    impl TestSession {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                recv_data: b"reply".to_vec(),
            }
        }
    }

    impl SlimSession for TestSession {
        fn send(&self, message: &[u8]) -> SecretResult<()> {
            let mut guard = self.sent.lock().map_err(|_| SecretError::StorageFailure)?;
            guard.extend_from_slice(message);
            Ok(())
        }

        fn recv(&self) -> SecretResult<Vec<u8>> {
            Ok(self.recv_data.clone())
        }
    }

    struct FailingSession;

    impl SlimSession for FailingSession {
        fn send(&self, _message: &[u8]) -> SecretResult<()> {
            Err(SecretError::StorageFailure)
        }

        fn recv(&self) -> SecretResult<Vec<u8>> {
            Err(SecretError::StorageFailure)
        }
    }

    #[test]
    fn send_requires_verifier_success() {
        let session = TestSession::new();
        let store = MemoryStore;
        let allow = AllowVerifier;
        let channel = SecureAgentChannel::new(&session, &allow, &store);
        let ctx = SessionContext::new("agent", "session");

        channel.send(&ctx, b"hello").unwrap();
        let sent = session.sent.lock().unwrap().clone();
        assert_eq!(sent, b"hello".to_vec());
    }

    #[test]
    fn recv_denied_when_verifier_fails() {
        let session = TestSession::new();
        let store = MemoryStore;
        let deny = DenyVerifier;
        let channel = SecureAgentChannel::new(&session, &deny, &store);
        let ctx = SessionContext::new("agent", "session");

        let err = channel.recv(&ctx).unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));
    }

    #[test]
    fn recv_returns_payload_when_allowed() {
        let session = TestSession::new();
        let store = MemoryStore;
        let allow = AllowVerifier;
        let channel = SecureAgentChannel::new(&session, &allow, &store);
        let ctx = SessionContext::new("agent", "session");

        let payload = channel.recv(&ctx).unwrap();
        assert_eq!(payload, b"reply".to_vec());
    }

    #[test]
    fn send_denied_when_verifier_fails() {
        let session = TestSession::new();
        let store = MemoryStore;
        let deny = DenyVerifier;
        let channel = SecureAgentChannel::new(&session, &deny, &store);
        let ctx = SessionContext::new("agent", "session");

        let err = channel.send(&ctx, b"hello").unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));
    }

    #[test]
    fn send_propagates_session_error() {
        let session = FailingSession;
        let store = MemoryStore;
        let allow = AllowVerifier;
        let channel = SecureAgentChannel::new(&session, &allow, &store);
        let ctx = SessionContext::new("agent", "session");

        let err = channel.send(&ctx, b"hello").unwrap_err();
        assert!(matches!(err, SecretError::StorageFailure));
    }

    #[test]
    fn recv_propagates_session_error() {
        let session = FailingSession;
        let store = MemoryStore;
        let allow = AllowVerifier;
        let channel = SecureAgentChannel::new(&session, &allow, &store);
        let ctx = SessionContext::new("agent", "session");

        let err = channel.recv(&ctx).unwrap_err();
        assert!(matches!(err, SecretError::StorageFailure));
    }

    #[test]
    fn memory_store_methods_return_ok() {
        let store = MemoryStore;
        store.put("key", b"value", SecretPolicy::default()).unwrap();
        assert!(store.list_keys().unwrap().is_empty());
        store.delete("key").unwrap();
    }

    #[test]
    fn send_wraps_payload_in_did_proof() {
        let session = TestSession::new();
        let store = MemoryStore;
        let allow = AllowVerifier;
        let identity = shadi_identity::AgentIdentity::generate().unwrap();
        let channel = SecureAgentChannel::new(&session, &allow, &store).with_signer(&identity);
        let ctx = SessionContext::new("agent", "session").with_did(identity.did());

        channel.send(&ctx, b"hello").unwrap();
        let sent = session.sent.lock().unwrap().clone();
        assert!(shadi_identity::looks_like_did_proof(&sent));
        let verified = shadi_identity::unwrap_signed_message(&sent).unwrap();
        assert_eq!(verified.did, identity.did());
        assert_eq!(verified.payload, b"hello");
    }

    #[test]
    fn recv_rejects_forged_peer_did() {
        let honest = shadi_identity::AgentIdentity::generate().unwrap();
        let impostor = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&honest, b"task").unwrap();

        let session = TestSession {
            sent: Mutex::new(Vec::new()),
            recv_data: envelope,
        };
        let store = MemoryStore;
        let proof = agent_secrets::DidProofVerifier;
        let channel = SecureAgentChannel::new(&session, &proof, &store).with_signer(&impostor);
        // Context claims the impostor's DID; the message is signed by someone else.
        let ctx = SessionContext::new("agent", "session").with_did(impostor.did());

        let err = channel.recv(&ctx).unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));
    }

    #[test]
    fn recv_accepts_matching_proven_did() {
        let honest = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&honest, b"task").unwrap();
        let session = TestSession {
            sent: Mutex::new(Vec::new()),
            recv_data: envelope,
        };
        let store = MemoryStore;
        let proof = agent_secrets::DidProofVerifier;
        let channel = SecureAgentChannel::new(&session, &proof, &store).with_signer(&honest);
        let ctx = SessionContext::new("agent", "session").with_did(honest.did());

        let payload = channel.recv(&ctx).unwrap();
        assert_eq!(payload, b"task");
    }

    #[test]
    fn proven_channel_rejects_unsigned_recv() {
        let identity = shadi_identity::AgentIdentity::generate().unwrap();
        let session = TestSession::new();
        let store = MemoryStore;
        let proof = agent_secrets::DidProofVerifier;
        let channel = SecureAgentChannel::new(&session, &proof, &store).with_signer(&identity);
        let ctx = SessionContext::new("agent", "session").with_did(identity.did());
        let err = channel.recv(&ctx).unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));
    }

    #[test]
    fn recv_accepts_envelope_when_session_did_is_unset() {
        let identity = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&identity, b"task").unwrap();
        let session = TestSession {
            sent: Mutex::new(Vec::new()),
            recv_data: envelope,
        };
        let store = MemoryStore;
        let allow = AllowVerifier;
        let channel = SecureAgentChannel::new(&session, &allow, &store).with_signer(&identity);
        let ctx = SessionContext::new("agent", "session");
        let payload = channel.recv(&ctx).unwrap();
        assert_eq!(payload, b"task");
    }
}
