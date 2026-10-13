// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! A local store for issued verifiable credentials.
//!
//! A credential arrives rarely — one browser login every few months — and is
//! read once per task a peer gates on a claim, so it has to survive restarts,
//! stay encrypted at rest and work the same on a laptop and in a container.
//!
//! **This module does not know what a credential looks like.** It stores the
//! bytes verbatim and queries the columns a caller lifted out of them, so
//! adding a credential format means adding a sibling of [`crate::sd_jwt`],
//! never touching the vault.

use std::path::Path;

use agent_secrets::SecretStore;
use shadi_memory::{CredentialRecord, SqlCipherStore};

use crate::CredentialError;

/// Keychain items are named `credentials/<id>`; enumeration filters on this.
pub const CREDENTIAL_KEY_PREFIX: &str = "credentials/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultBackend {
    Keychain,
    SqlCipher,
}

impl std::str::FromStr for VaultBackend {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "keychain" => Ok(Self::Keychain),
            "sqlcipher" => Ok(Self::SqlCipher),
            other => Err(format!("unknown vault backend: {other}")),
        }
    }
}

/// Which backend to use when the operator did not say.
///
/// Goes through the existing secret-store dispatch — keychain, 1Password or
/// no-op — rather than naming a backend per target OS. Asks whether the store
/// works instead of trying an operation on it: a probe would prompt the
/// keychain, and a cancelled prompt would then be indistinguishable from
/// having no keychain, silently picking the wrong backend.
pub fn default_backend() -> VaultBackend {
    if agent_secrets::default_store().is_available() {
        VaultBackend::Keychain
    } else {
        VaultBackend::SqlCipher
    }
}

pub trait CredentialVault: Send + Sync {
    fn put(&self, record: &CredentialRecord) -> Result<(), CredentialError>;
    fn get(&self, id: &str) -> Result<Option<CredentialRecord>, CredentialError>;
    fn list(&self) -> Result<Vec<CredentialRecord>, CredentialError>;
    /// `true` when a record was removed.
    fn delete(&self, id: &str) -> Result<bool, CredentialError>;
    /// Credentials this agent could present: bound to its own key, from a
    /// trusted issuer, of the requested type, unexpired. Answers "which could
    /// possibly apply", never "what to disclose".
    fn find_valid(
        &self,
        agent_did: &str,
        issuer: &str,
        credential_type: &str,
        now: i64,
    ) -> Result<Vec<CredentialRecord>, CredentialError>;
}

// --- SQLCipher ---------------------------------------------------------------

/// The path every Linux developer, every container and every CI run takes,
/// because the keychain backend is a no-op off macOS.
pub struct SqlCipherVault {
    store: SqlCipherStore,
}

impl SqlCipherVault {
    pub fn open(path: &Path, key: &str) -> Result<Self, CredentialError> {
        let store = SqlCipherStore::open(path, key)
            .map_err(|err| CredentialError::Storage(err.to_string()))?;
        Ok(Self { store })
    }
}

fn storage<T>(result: Result<T, shadi_memory::MemoryError>) -> Result<T, CredentialError> {
    result.map_err(|err| CredentialError::Storage(err.to_string()))
}

impl CredentialVault for SqlCipherVault {
    fn put(&self, record: &CredentialRecord) -> Result<(), CredentialError> {
        storage(self.store.put_credential(record))
    }

    fn get(&self, id: &str) -> Result<Option<CredentialRecord>, CredentialError> {
        storage(self.store.get_credential(id))
    }

    fn list(&self) -> Result<Vec<CredentialRecord>, CredentialError> {
        storage(self.store.list_credentials())
    }

    fn delete(&self, id: &str) -> Result<bool, CredentialError> {
        Ok(storage(self.store.delete_credential(id))? > 0)
    }

    fn find_valid(
        &self,
        agent_did: &str,
        issuer: &str,
        credential_type: &str,
        now: i64,
    ) -> Result<Vec<CredentialRecord>, CredentialError> {
        storage(
            self.store
                .find_valid_credentials(agent_did, issuer, credential_type, now),
        )
    }
}

// --- Keychain ----------------------------------------------------------------

/// One keychain item per credential. No index to maintain: the store's own key
/// registry is already kept and self-heals stale entries.
pub struct KeychainVault {
    store: Box<dyn SecretStore>,
}

impl KeychainVault {
    pub fn new(store: Box<dyn SecretStore>) -> Self {
        Self { store }
    }

    pub fn with_default_store() -> Self {
        Self::new(agent_secrets::default_store())
    }

    fn item_key(id: &str) -> String {
        format!("{CREDENTIAL_KEY_PREFIX}{id}")
    }
}

impl CredentialVault for KeychainVault {
    fn put(&self, record: &CredentialRecord) -> Result<(), CredentialError> {
        let payload = serde_json::to_vec(record)
            .map_err(|err| CredentialError::Storage(format!("serialise record: {err}")))?;
        self.store
            .put(&Self::item_key(&record.id), &payload)
            .map_err(|err| CredentialError::Storage(err.to_string()))
    }

    fn get(&self, id: &str) -> Result<Option<CredentialRecord>, CredentialError> {
        match self.store.get(&Self::item_key(id)) {
            Ok(secret) => {
                let bytes = secret.expose(|bytes| bytes.to_vec());
                let record = serde_json::from_slice(&bytes).map_err(|err| {
                    CredentialError::Storage(format!("stored record is unreadable: {err}"))
                })?;
                Ok(Some(record))
            }
            // How this store reports not-found.
            Err(agent_secrets::SecretError::InvalidInput) => Ok(None),
            Err(err) => Err(CredentialError::Storage(err.to_string())),
        }
    }

    fn list(&self) -> Result<Vec<CredentialRecord>, CredentialError> {
        let keys = self
            .store
            .list_keys()
            .map_err(|err| CredentialError::Storage(err.to_string()))?;
        let mut records = Vec::new();
        for key in keys {
            let Some(id) = key.strip_prefix(CREDENTIAL_KEY_PREFIX) else {
                continue;
            };
            if let Some(record) = self.get(id)? {
                records.push(record);
            }
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.created_at));
        Ok(records)
    }

    fn delete(&self, id: &str) -> Result<bool, CredentialError> {
        match self.store.delete(&Self::item_key(id)) {
            Ok(()) => Ok(true),
            Err(agent_secrets::SecretError::InvalidInput) => Ok(false),
            Err(err) => Err(CredentialError::Storage(err.to_string())),
        }
    }

    // No query engine here, so filter in memory. The population is single
    // digits — one credential per agent — and will stay that way.
    fn find_valid(
        &self,
        agent_did: &str,
        issuer: &str,
        credential_type: &str,
        now: i64,
    ) -> Result<Vec<CredentialRecord>, CredentialError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|record| {
                record.agent_did == agent_did
                    && record.issuer == issuer
                    && record.credential_type == credential_type
                    && record.expires_at.is_none_or(|exp| exp > now)
            })
            .collect())
    }
}

/// Build the configured backend. `db`/`key` are only consulted for SQLCipher.
pub fn default_vault(
    backend: VaultBackend,
    db: Option<&Path>,
    key: Option<&str>,
) -> Result<Box<dyn CredentialVault>, CredentialError> {
    match backend {
        VaultBackend::Keychain => Ok(Box::new(KeychainVault::with_default_store())),
        VaultBackend::SqlCipher => {
            let db = db.ok_or_else(|| {
                CredentialError::Storage("the sqlcipher vault needs a database path".to_string())
            })?;
            let key = key.ok_or_else(|| {
                CredentialError::Storage("the sqlcipher vault needs a database key".to_string())
            })?;
            Ok(Box::new(SqlCipherVault::open(db, key)?))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use agent_secrets::memory::SecretBytes;
    use agent_secrets::{SecretError, SecretResult};

    // These tests build records directly rather than importing a credential:
    // the vault is not supposed to know what one looks like.
    fn record(id: &str) -> CredentialRecord {
        CredentialRecord {
            id: id.to_string(),
            agent_did: "did:key:zAgent".to_string(),
            issuer: "https://idp.example/realms/eng".to_string(),
            credential_type: "urn:shadi:agent-admission:1".to_string(),
            format: "dc+sd-jwt".to_string(),
            raw: "opaque-credential-bytes".to_string(),
            created_at: 1_000,
            expires_at: Some(2_000),
        }
    }

    #[derive(Default)]
    struct FakeSecretStore {
        items: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl SecretStore for FakeSecretStore {
        fn put(&self, key: &str, secret: &[u8]) -> SecretResult<()> {
            self.items
                .lock()
                .unwrap()
                .insert(key.to_string(), secret.to_vec());
            Ok(())
        }

        fn get(&self, key: &str) -> SecretResult<SecretBytes> {
            self.items
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .map(SecretBytes::new)
                .ok_or(SecretError::InvalidInput)
        }

        fn delete(&self, key: &str) -> SecretResult<()> {
            self.items
                .lock()
                .unwrap()
                .remove(key)
                .map(|_| ())
                .ok_or(SecretError::InvalidInput)
        }

        fn list_keys(&self) -> SecretResult<Vec<String>> {
            Ok(self.items.lock().unwrap().keys().cloned().collect())
        }
    }

    pub(crate) fn sqlcipher_vault() -> SqlCipherVault {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let path = file.path().to_path_buf();
        std::mem::forget(file);
        SqlCipherVault::open(&path, "test-key").expect("open")
    }

    fn keychain_vault() -> KeychainVault {
        KeychainVault::new(Box::new(FakeSecretStore::default()))
    }

    fn round_trip(vault: &dyn CredentialVault) {
        let stored = record("cred-1");
        vault.put(&stored).expect("put");
        assert_eq!(vault.get("cred-1").expect("get").as_ref(), Some(&stored));
        assert_eq!(vault.list().expect("list"), vec![stored.clone()]);

        let found = vault
            .find_valid(
                "did:key:zAgent",
                "https://idp.example/realms/eng",
                "urn:shadi:agent-admission:1",
                1_500,
            )
            .expect("find");
        assert_eq!(found, vec![stored]);

        // Expired, other agent, other issuer, other type: all excluded.
        for (agent, issuer, credential_type, now) in [
            (
                "did:key:zAgent",
                "https://idp.example/realms/eng",
                "urn:shadi:agent-admission:1",
                3_000,
            ),
            (
                "did:key:zOther",
                "https://idp.example/realms/eng",
                "urn:shadi:agent-admission:1",
                1_500,
            ),
            (
                "did:key:zAgent",
                "https://evil.example",
                "urn:shadi:agent-admission:1",
                1_500,
            ),
            (
                "did:key:zAgent",
                "https://idp.example/realms/eng",
                "urn:shadi:other:1",
                1_500,
            ),
        ] {
            assert!(
                vault
                    .find_valid(agent, issuer, credential_type, now)
                    .expect("find")
                    .is_empty(),
                "{agent} {issuer} {credential_type} {now} should not match"
            );
        }

        assert!(vault.delete("cred-1").expect("delete"));
        assert!(!vault.delete("cred-1").expect("delete again"));
        assert!(vault.get("cred-1").expect("get").is_none());
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn sqlcipher_backend_round_trips() {
        round_trip(&sqlcipher_vault());
    }

    #[test]
    fn keychain_backend_round_trips() {
        round_trip(&keychain_vault());
    }

    fn keeps_a_credential_without_exp(vault: &dyn CredentialVault) {
        let mut forever = record("forever");
        forever.expires_at = None;
        vault.put(&forever).expect("put");
        assert_eq!(
            vault
                .find_valid(
                    "did:key:zAgent",
                    "https://idp.example/realms/eng",
                    "urn:shadi:agent-admission:1",
                    i64::MAX,
                )
                .expect("find")
                .len(),
            1
        );
    }

    #[test]
    fn a_credential_without_exp_never_expires() {
        keeps_a_credential_without_exp(&sqlcipher_vault());
        keeps_a_credential_without_exp(&keychain_vault());
    }

    fn replaces_in_place(vault: &dyn CredentialVault) {
        vault.put(&record("cred-1")).expect("put");
        let mut updated = record("cred-1");
        updated.credential_type = "urn:shadi:other:1".to_string();
        vault.put(&updated).expect("put");
        assert_eq!(vault.list().expect("list"), vec![updated]);
    }

    #[test]
    fn storing_over_an_existing_id_replaces() {
        replaces_in_place(&sqlcipher_vault());
        replaces_in_place(&keychain_vault());
    }

    #[test]
    fn keychain_backend_ignores_unrelated_items() {
        let store = FakeSecretStore::default();
        store
            .put("shadi/memory/sqlcipher_key", b"not-a-credential")
            .unwrap();
        let vault = KeychainVault::new(Box::new(store));
        vault.put(&record("cred-1")).expect("put");
        assert_eq!(vault.list().expect("list").len(), 1);
    }

    #[test]
    fn backend_names_parse() {
        assert_eq!("keychain".parse(), Ok(VaultBackend::Keychain));
        assert_eq!("SQLCipher".parse(), Ok(VaultBackend::SqlCipher));
        assert!("other".parse::<VaultBackend>().is_err());
    }

    #[test]
    fn the_sqlcipher_backend_needs_a_path_and_a_key() {
        assert!(default_vault(VaultBackend::SqlCipher, None, Some("k"))
            .err()
            .expect("error")
            .to_string()
            .contains("database path"));
        assert!(
            default_vault(VaultBackend::SqlCipher, Some(Path::new("/tmp/x.db")), None)
                .err()
                .expect("error")
                .to_string()
                .contains("database key")
        );
    }
}
