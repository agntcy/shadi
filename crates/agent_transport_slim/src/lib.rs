// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod native;
mod stdio_bridge;

use agent_secrets::{AgentVerifier, SecretResult, SecretStore, SessionContext};

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
        }
    }

    pub fn send(&self, ctx: &SessionContext, message: &[u8]) -> SecretResult<()> {
        self.verifier.verify(ctx)?;
        let _ = self.store;
        self.session.send(message)
    }

    pub fn recv(&self, ctx: &SessionContext) -> SecretResult<Vec<u8>> {
        self.verifier.verify(ctx)?;
        let _ = self.store;
        self.session.recv()
    }
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
}
