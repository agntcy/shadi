// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(any(test, feature = "coverage")))]
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework_sys::base::errSecItemNotFound;

#[cfg(any(test, feature = "coverage"))]
use std::collections::HashMap;
#[cfg(any(test, feature = "coverage"))]
use std::fmt;
#[cfg(any(test, feature = "coverage"))]
use std::sync::{Mutex, OnceLock};

use crate::{SecretError, SecretResult, SecretStore};
use crate::memory::SecretBytes;

pub struct MacosKeychainStore {
    service: String,
}

const REGISTRY_ACCOUNT: &str = "__shadi_registry__";

#[cfg(any(test, feature = "coverage"))]
#[derive(Debug, Clone)]
struct KeychainError {
    code: i32,
    message: &'static str,
}

#[cfg(any(test, feature = "coverage"))]
impl KeychainError {
    fn not_found() -> Self {
        Self {
            code: errSecItemNotFound,
            message: "item not found",
        }
    }

    fn code(&self) -> i32 {
        self.code
    }
}

#[cfg(any(test, feature = "coverage"))]
impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

#[cfg(any(test, feature = "coverage"))]
type KeychainFixture = Mutex<HashMap<(String, String), Vec<u8>>>;

#[cfg(any(test, feature = "coverage"))]
fn keychain_fixture() -> &'static KeychainFixture {
    static FIXTURE: OnceLock<KeychainFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(test, feature = "coverage"))]
fn set_generic_password(service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
    let mut guard = keychain_fixture()
        .lock()
        .map_err(|_| KeychainError {
            code: -1,
            message: "fixture lock poisoned",
        })?;
    guard.insert((service.to_string(), account.to_string()), secret.to_vec());
    Ok(())
}

#[cfg(any(test, feature = "coverage"))]
fn get_generic_password(service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
    let guard = keychain_fixture()
        .lock()
        .map_err(|_| KeychainError {
            code: -1,
            message: "fixture lock poisoned",
        })?;
    guard
        .get(&(service.to_string(), account.to_string()))
        .cloned()
        .ok_or_else(KeychainError::not_found)
}

#[cfg(any(test, feature = "coverage"))]
fn delete_generic_password(service: &str, account: &str) -> Result<(), KeychainError> {
    let mut guard = keychain_fixture()
        .lock()
        .map_err(|_| KeychainError {
            code: -1,
            message: "fixture lock poisoned",
        })?;
    if guard
        .remove(&(service.to_string(), account.to_string()))
        .is_some()
    {
        Ok(())
    } else {
        Err(KeychainError::not_found())
    }
}

impl MacosKeychainStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn load_registry(&self) -> SecretResult<Vec<String>> {
        #[cfg(any(test, feature = "coverage"))]
        if self.service == "__force_error__" {
            return Err(SecretError::StorageFailure);
        }
        match get_generic_password(&self.service, REGISTRY_ACCOUNT) {
            Ok(value) => {
                let text = String::from_utf8(value).map_err(|_| SecretError::StorageFailure)?;
                let keys = text
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .map(String::from)
                    .collect::<Vec<_>>();
                Ok(keys)
            }
            Err(err) if err.code() == errSecItemNotFound => Ok(Vec::new()),
            Err(err) => {
                eprintln!("keychain registry read failed: {}", err);
                Err(SecretError::StorageFailure)
            }
        }
    }

    fn store_registry(&self, keys: &[String]) -> SecretResult<()> {
        let mut unique = keys.to_vec();
        unique.sort();
        unique.dedup();
        let payload = unique.join("\n");
        set_generic_password(&self.service, REGISTRY_ACCOUNT, payload.as_bytes()).map_err(|err| {
            eprintln!("keychain registry write failed: {}", err);
            SecretError::StorageFailure
        })
    }

    fn update_registry_on_put(&self, key: &str) -> SecretResult<()> {
        if key == REGISTRY_ACCOUNT {
            return Ok(());
        }
        let mut keys = self.load_registry()?;
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.to_string());
            self.store_registry(&keys)?;
        }
        Ok(())
    }

    fn update_registry_on_delete(&self, key: &str) -> SecretResult<()> {
        if key == REGISTRY_ACCOUNT {
            return Ok(());
        }
        let mut keys = self.load_registry()?;
        let before = keys.len();
        keys.retain(|existing| existing != key);
        if keys.len() != before {
            self.store_registry(&keys)?;
        }
        Ok(())
    }
}

impl SecretStore for MacosKeychainStore {
    fn put(&self, key: &str, secret: &[u8]) -> SecretResult<()> {
        set_generic_password(&self.service, key, secret).map_err(|err| {
            eprintln!("keychain put failed: {}", err);
            SecretError::StorageFailure
        })?;
        self.update_registry_on_put(key)
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        match get_generic_password(&self.service, key) {
            Ok(value) => Ok(SecretBytes::new(value)),
            // A miss is ordinary control flow — "is this secret set yet?" is a
            // question callers ask. Reporting it as a storage failure hid real
            // ones, and logging it filled the console on every first run.
            // Matches the 1Password backend, which maps not-found the same way.
            Err(err) if err.code() == errSecItemNotFound => Err(SecretError::InvalidInput),
            Err(err) => {
                eprintln!("keychain get failed: {}", err);
                Err(SecretError::StorageFailure)
            }
        }
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        match delete_generic_password(&self.service, key) {
            Ok(()) => {}
            Err(err) if err.code() == errSecItemNotFound => {
                return Err(SecretError::InvalidInput)
            }
            Err(err) => {
                eprintln!("keychain delete failed: {}", err);
                return Err(SecretError::StorageFailure);
            }
        }
        self.update_registry_on_delete(key)
    }

    /// Registry entries whose keychain item still exists.
    ///
    /// The registry is only maintained by this store's own put and delete, so
    /// anything removed with Keychain Access or `security` leaves an entry
    /// behind. Reporting those made the inventory disagree with reality, and
    /// deleting the registry item is not a fix: it hides live keys instead.
    /// A missing item is definitive — a locked or unavailable keychain reports
    /// something other than not-found — so a stale entry is pruned rather than
    /// re-checked on every listing.
    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let mut live = Vec::new();
        let mut stale = false;
        for key in self.load_registry()? {
            if key == REGISTRY_ACCOUNT {
                continue;
            }
            match self.get(&key) {
                // The value is dropped straight away; this only asks whether
                // the item is there.
                Ok(_) => live.push(key),
                Err(SecretError::InvalidInput) => stale = true,
                Err(err) => return Err(err),
            }
        }
        if stale {
            self.store_registry(&live)?;
        }
        Ok(live)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_key(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let seq = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}-{}-{}", prefix, std::process::id(), nanos, seq)
    }

    fn unique_service() -> String {
        unique_key("shadi_tests")
    }

    #[test]
    fn keychain_roundtrip_put_get_delete() {
        let store = MacosKeychainStore::new(unique_service());
        let key = unique_key("shadi-key");
        let secret = b"secret-value";

        store.put(&key, secret).unwrap();
        let got = store.get(&key).unwrap();
        let value = got.expose(|bytes| bytes.to_vec());
        assert_eq!(value, secret);
        store.delete(&key).unwrap();
    }

    #[test]
    fn list_keys_tracks_registry_updates() {
        let store = MacosKeychainStore::new(unique_service());
        let key_one = unique_key("shadi-key-a");
        let key_two = unique_key("shadi-key-b");

        store.put(&key_one, b"value-a").unwrap();
        store.put(&key_two, b"value-b").unwrap();

        let keys = store.list_keys().unwrap();
        assert!(keys.iter().any(|item| item == &key_one));
        assert!(keys.iter().any(|item| item == &key_two));

        store.delete(&key_one).unwrap();
        let keys = store.list_keys().unwrap();
        assert!(!keys.iter().any(|item| item == &key_one));

        store.delete(&key_two).unwrap();
    }

    #[test]
    fn list_keys_excludes_registry_account() {
        let store = MacosKeychainStore::new(unique_service());
        store.put(REGISTRY_ACCOUNT, b"value").unwrap();
        let keys = store.list_keys().unwrap();
        assert!(!keys.iter().any(|key| key == REGISTRY_ACCOUNT));
        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    fn list_keys_dedups_registry_entries() {
        let store = MacosKeychainStore::new(unique_service());
        let key = unique_key("shadi-key");

        store.put(&key, b"value").unwrap();
        store.put(&key, b"value").unwrap();

        let keys = store.list_keys().unwrap();
        let count = keys.iter().filter(|item| *item == &key).count();
        assert_eq!(count, 1);
        store.delete(&key).unwrap();
    }

    #[test]
    fn list_keys_empty_when_registry_missing() {
        let store = MacosKeychainStore::new(unique_service());
        let keys = store.list_keys().unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn list_keys_reports_forced_error() {
        let store = MacosKeychainStore::new("__force_error__");
        let err = store.list_keys().unwrap_err();
        assert!(matches!(err, SecretError::StorageFailure));
    }

    #[test]
    fn list_keys_trims_registry_entries() {
        let service = unique_service();
        let store = MacosKeychainStore::new(service.clone());
        // The items have to exist: an entry naming a missing item is stale and
        // is no longer reported, so this would otherwise pass vacuously.
        store.put("key-a", b"a").unwrap();
        store.put("key-b", b"b").unwrap();
        let payload = b"key-a\n\n  key-b  \n";
        set_generic_password(&service, REGISTRY_ACCOUNT, payload).unwrap();

        let keys = store.list_keys().unwrap();
        assert!(keys.contains(&"key-a".to_string()));
        assert!(keys.contains(&"key-b".to_string()));

        store.delete("key-a").unwrap();
        store.delete("key-b").unwrap();
        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    fn list_keys_drops_an_entry_whose_item_is_gone() {
        let service = unique_service();
        let store = MacosKeychainStore::new(service.clone());
        store.put("kept", b"1").unwrap();
        store.put("removed", b"2").unwrap();

        // Removed behind the store's back, as Keychain Access or `security
        // delete-generic-password` would.
        delete_generic_password(&service, "removed").unwrap();

        assert_eq!(store.list_keys().unwrap(), vec!["kept".to_string()]);

        // Pruned, so the missing item is not re-checked on every listing.
        assert_eq!(store.load_registry().unwrap(), vec!["kept".to_string()]);

        store.delete("kept").unwrap();
        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    fn list_keys_leaves_the_registry_alone_when_nothing_is_stale() {
        let service = unique_service();
        let store = MacosKeychainStore::new(service.clone());
        store.put("a", b"1").unwrap();
        store.put("b", b"2").unwrap();

        let before = store.load_registry().unwrap();
        assert_eq!(store.list_keys().unwrap(), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(store.load_registry().unwrap(), before);

        store.delete("a").unwrap();
        store.delete("b").unwrap();
        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    fn list_keys_errors_on_invalid_utf8_registry() {
        let service = unique_service();
        let store = MacosKeychainStore::new(service.clone());
        let payload = vec![0xff, 0xfe, 0xfd];
        set_generic_password(&service, REGISTRY_ACCOUNT, &payload).unwrap();

        let err = store.list_keys().unwrap_err();
        assert!(matches!(err, SecretError::StorageFailure));

        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    /// A missing key is not a storage failure. Callers ask "is this set yet?"
    /// and need to tell that apart from a keychain that is actually broken.
    fn get_missing_key_reports_not_found() {
        let store = MacosKeychainStore::new(unique_service());
        let err = store.get("missing-key").expect_err("error");
        assert!(
            matches!(err, SecretError::InvalidInput),
            "expected not-found, got {err:?}"
        );
    }

    #[test]
    fn delete_missing_key_reports_not_found() {
        let store = MacosKeychainStore::new(unique_service());
        let err = store.delete("missing-key").unwrap_err();
        assert!(
            matches!(err, SecretError::InvalidInput),
            "expected not-found, got {err:?}"
        );
    }

    /// A real backend failure must still be distinguishable from a miss.
    #[test]
    fn storage_failure_is_still_reported_as_such() {
        let store = MacosKeychainStore::new("__force_error__");
        assert!(matches!(
            store.list_keys().unwrap_err(),
            SecretError::StorageFailure
        ));
    }
}
