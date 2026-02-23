// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework_sys::base::errSecItemNotFound;

use crate::{SecretError, SecretResult, SecretStore};
use crate::memory::SecretBytes;
use crate::policy::SecretPolicy;

pub struct MacosKeychainStore {
    service: String,
}

const REGISTRY_ACCOUNT: &str = "__shadi_registry__";

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
    fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
        set_generic_password(&self.service, key, secret).map_err(|err| {
            eprintln!("keychain put failed: {}", err);
            SecretError::StorageFailure
        })?;
        self.update_registry_on_put(key)
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        let value = get_generic_password(&self.service, key)
            .map_err(|err| {
                eprintln!("keychain get failed: {}", err);
                SecretError::StorageFailure
            })?;
        Ok(SecretBytes::new(value))
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        delete_generic_password(&self.service, key).map_err(|err| {
            eprintln!("keychain delete failed: {}", err);
            SecretError::StorageFailure
        })?;
        self.update_registry_on_delete(key)
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let keys = self.load_registry()?;
        Ok(keys.into_iter().filter(|key| key != REGISTRY_ACCOUNT).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_key(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    fn unique_service() -> String {
        unique_key("shadi_tests")
    }

    #[test]
    fn keychain_roundtrip_put_get_delete() {
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let store = MacosKeychainStore::new(unique_service());
        let key = unique_key("shadi-key");
        let secret = b"secret-value";

        store.put(&key, secret, SecretPolicy::default()).unwrap();
        let got = store.get(&key).unwrap();
        let value = got.expose(|bytes| bytes.to_vec());
        assert_eq!(value, secret);
        store.delete(&key).unwrap();
    }

    #[test]
    fn list_keys_tracks_registry_updates() {
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let store = MacosKeychainStore::new(unique_service());
        let key_one = unique_key("shadi-key-a");
        let key_two = unique_key("shadi-key-b");

        store.put(&key_one, b"value-a", SecretPolicy::default()).unwrap();
        store.put(&key_two, b"value-b", SecretPolicy::default()).unwrap();

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
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let store = MacosKeychainStore::new(unique_service());
        store
            .put(REGISTRY_ACCOUNT, b"value", SecretPolicy::default())
            .unwrap();
        let keys = store.list_keys().unwrap();
        assert!(!keys.iter().any(|key| key == REGISTRY_ACCOUNT));
        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    fn list_keys_dedups_registry_entries() {
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let store = MacosKeychainStore::new(unique_service());
        let key = unique_key("shadi-key");

        store.put(&key, b"value", SecretPolicy::default()).unwrap();
        store.put(&key, b"value", SecretPolicy::default()).unwrap();

        let keys = store.list_keys().unwrap();
        let count = keys.iter().filter(|item| *item == &key).count();
        assert_eq!(count, 1);
        store.delete(&key).unwrap();
    }

    #[test]
    fn list_keys_empty_when_registry_missing() {
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
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
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let service = unique_service();
        let store = MacosKeychainStore::new(service.clone());
        let payload = b"key-a\n\n  key-b  \n";
        set_generic_password(&service, REGISTRY_ACCOUNT, payload).unwrap();

        let keys = store.list_keys().unwrap();
        assert!(keys.contains(&"key-a".to_string()));
        assert!(keys.contains(&"key-b".to_string()));

        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    fn list_keys_errors_on_invalid_utf8_registry() {
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let service = unique_service();
        let store = MacosKeychainStore::new(service.clone());
        let payload = vec![0xff, 0xfe, 0xfd];
        set_generic_password(&service, REGISTRY_ACCOUNT, &payload).unwrap();

        let err = store.list_keys().unwrap_err();
        assert!(matches!(err, SecretError::StorageFailure));

        store.delete(REGISTRY_ACCOUNT).unwrap();
    }

    #[test]
    fn get_missing_key_returns_error() {
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let store = MacosKeychainStore::new(unique_service());
        let err = store.get("missing-key").err().expect("error");
        assert!(matches!(err, SecretError::StorageFailure));
    }

    #[test]
    fn delete_missing_key_returns_error() {
        if std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() != Ok("1") {
            return;
        }
        let store = MacosKeychainStore::new(unique_service());
        let err = store.delete("missing-key").unwrap_err();
        assert!(matches!(err, SecretError::StorageFailure));
    }
}
