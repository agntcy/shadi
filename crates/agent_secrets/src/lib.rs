// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

pub mod agent;
pub mod auth;
pub mod memory;
pub mod platform;
pub mod policy;
pub mod session;

use std::fmt;

pub use agent::AgentSecretAccess;
pub use auth::AgentVerifier;
pub use memory::SecretBytes;
pub use policy::SecretPolicy;
pub use session::SessionContext;

#[cfg(feature = "onepassword")]
pub use platform::onepassword::OnePasswordStore;

#[derive(Debug)]
pub enum SecretError {
    NotSupported,
    NotAuthorized,
    InvalidInput,
    StorageFailure,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            SecretError::NotSupported => "operation not supported",
            SecretError::NotAuthorized => "not authorized",
            SecretError::InvalidInput => "invalid input",
            SecretError::StorageFailure => "storage failure",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SecretError {}

pub type SecretResult<T> = Result<T, SecretError>;

pub trait SecretStore: Send + Sync {
    fn put(&self, key: &str, secret: &[u8], policy: SecretPolicy) -> SecretResult<()>;
    fn get(&self, key: &str) -> SecretResult<SecretBytes>;
    fn delete(&self, key: &str) -> SecretResult<()>;
    fn list_keys(&self) -> SecretResult<Vec<String>>;
}

pub fn default_store() -> Box<dyn SecretStore> {
    platform::default_store()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::agent::AgentSecretAccess;
    use crate::auth::AgentVerifier;

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

    struct MemoryStore {
        entries: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
    }

    impl SecretStore for MemoryStore {
        fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
            let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            guard.insert(key.to_string(), secret.to_vec());
            Ok(())
        }

        fn get(&self, key: &str) -> SecretResult<SecretBytes> {
            let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            let value = guard
                .get(key)
                .ok_or(SecretError::InvalidInput)?
                .clone();
            Ok(SecretBytes::new(value))
        }

        fn delete(&self, key: &str) -> SecretResult<()> {
            let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            guard.remove(key);
            Ok(())
        }

        fn list_keys(&self) -> SecretResult<Vec<String>> {
            let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            Ok(guard.keys().cloned().collect())
        }
    }

    #[test]
    fn agent_access_allows_put_get_delete_when_verified() {
        let store = MemoryStore::new();
        let verifier = AllowVerifier;
        let access = AgentSecretAccess::new(&store, &verifier);
        let session = SessionContext::new("agent", "session");

        access
            .put_for_session(&session, "key", b"value", SecretPolicy::default())
            .unwrap();

        let secret = access.get_for_session(&session, "key").unwrap();
        let got = secret.expose(|bytes| bytes.to_vec());
        assert_eq!(got, b"value");

        access.delete_for_session(&session, "key").unwrap();
    }

    #[test]
    fn agent_access_denies_when_verifier_rejects() {
        let store = MemoryStore::new();
        let verifier = DenyVerifier;
        let access = AgentSecretAccess::new(&store, &verifier);
        let session = SessionContext::new("agent", "session");

        let err = access
            .put_for_session(&session, "key", b"value", SecretPolicy::default())
            .unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));
    }

    #[test]
    fn secret_error_display_formats_messages() {
        assert_eq!(SecretError::NotSupported.to_string(), "operation not supported");
        assert_eq!(SecretError::NotAuthorized.to_string(), "not authorized");
        assert_eq!(SecretError::InvalidInput.to_string(), "invalid input");
        assert_eq!(SecretError::StorageFailure.to_string(), "storage failure");
    }
}
