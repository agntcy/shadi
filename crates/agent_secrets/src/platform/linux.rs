// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Encrypted keyring file in the libsecret file format. No D-Bus, no daemon:
//! the password comes from a file, so it also works headless in containers.
//! Without `SHADI_KEYRING_PASSWORD_FILE` the store is unavailable, like the
//! no-op store.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use oo7::file::UnlockedKeyring;
use oo7::Secret;
use zeroize::Zeroizing;

use crate::memory::SecretBytes;
use crate::{SecretError, SecretResult, SecretStore};

const SERVICE: &str = "agent_secrets";
/// Tries when another process saved between our load and our save.
const SAVE_ATTEMPTS: usize = 5;

/// Serialises load, modify and save within the process: oo7 refuses a save
/// when the file changed since it was loaded.
static KEYRING_LOCK: Mutex<()> = Mutex::new(());

pub struct KeyringFileStore {
    /// (keyring file, password file); `None` when not configured.
    config: Option<(PathBuf, PathBuf)>,
}

impl KeyringFileStore {
    pub fn from_env() -> Self {
        Self::from_vars(|name| std::env::var_os(name))
    }

    fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Self {
        let set = |name| var(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        let path = set("SHADI_KEYRING_PATH").or_else(|| {
            let base = set("XDG_DATA_HOME").or_else(|| set("HOME").map(|h| h.join(".local/share")));
            base.map(|b| b.join("shadi/agent_secrets.keyring"))
        });
        Self {
            config: path.zip(set("SHADI_KEYRING_PASSWORD_FILE")),
        }
    }

    #[cfg(test)]
    fn new(path: PathBuf, password_file: PathBuf) -> Self {
        Self {
            config: Some((path, password_file)),
        }
    }

    fn password(file: &Path) -> SecretResult<Secret> {
        let mut raw = Zeroizing::new(std::fs::read(file).map_err(|_| SecretError::StorageFailure)?);
        while matches!(raw.last(), Some(b'\n' | b'\r')) {
            raw.pop();
        }
        if raw.is_empty() {
            return Err(SecretError::StorageFailure);
        }
        Ok(Secret::blob(&*raw))
    }

    /// Opens the keyring (a missing file is an empty keyring) and runs `f` on
    /// a private thread and runtime, so callers inside a runtime are fine.
    /// `f` runs again on a fresh load if another process changed the file.
    fn with_keyring<T: Send>(
        &self,
        f: impl AsyncFn(UnlockedKeyring) -> Result<T, oo7::file::Error> + Send,
    ) -> SecretResult<T> {
        let (path, password_file) = self.config.as_ref().ok_or(SecretError::NotSupported)?;
        let secret = Self::password(password_file)?;
        let _guard = KEYRING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::thread::scope(|s| {
            s.spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .map_err(|_| SecretError::StorageFailure)?
                    .block_on(async {
                        let mut attempt = 1;
                        loop {
                            let keyring = UnlockedKeyring::load(path, Some(secret.clone())).await?;
                            match f(keyring).await {
                                Err(oo7::file::Error::TargetFileChanged(_))
                                    if attempt < SAVE_ATTEMPTS =>
                                {
                                    attempt += 1;
                                }
                                result => break result,
                            }
                        }
                    })
                    .map_err(|err| match err {
                        oo7::file::Error::IncorrectSecret => SecretError::NotAuthorized,
                        err => {
                            eprintln!("keyring failed: {err}");
                            SecretError::StorageFailure
                        }
                    })
            })
            .join()
            .map_err(|_| SecretError::StorageFailure)?
        })
    }
}

fn attrs(key: &str) -> [(&str, &str); 2] {
    [("service", SERVICE), ("account", key)]
}

fn check(key: &str) -> SecretResult<()> {
    if key.is_empty() {
        return Err(SecretError::InvalidInput);
    }
    Ok(())
}

impl SecretStore for KeyringFileStore {
    fn put(&self, key: &str, secret: &[u8]) -> SecretResult<()> {
        check(key)?;
        self.with_keyring(async |k| {
            k.create_item(key, &attrs(key), Secret::blob(secret), true)
                .await
                .map(drop)
        })
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        check(key)?;
        self.with_keyring(async |k| {
            Ok(k.lookup_item(&attrs(key))
                .await?
                .map(|item| SecretBytes::new(item.secret().as_bytes().to_vec())))
        })?
        .ok_or(SecretError::InvalidInput)
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        check(key)?;
        let found = self.with_keyring(async |k| {
            if k.lookup_item(&attrs(key)).await?.is_none() {
                return Ok(false);
            }
            k.delete(&attrs(key)).await.map(|()| true)
        })?;
        found.then_some(()).ok_or(SecretError::InvalidInput)
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let mut keys = self.with_keyring(async |k| {
            Ok(k.search_items(&[("service", SERVICE)])
                .await?
                .iter()
                .filter_map(|item| item.attributes().get("account").cloned())
                .collect::<Vec<_>>())
        })?;
        keys.sort();
        Ok(keys)
    }

    fn is_available(&self) -> bool {
        // Opening the password file is enough: inside the sandbox the
        // variables are set but the files are denied.
        self.config
            .as_ref()
            .is_some_and(|(_, password_file)| std::fs::File::open(password_file).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn store(dir: &Path, password: &[u8]) -> KeyringFileStore {
        let pw = dir.join("pw");
        std::fs::write(&pw, password).unwrap();
        KeyringFileStore::new(dir.join("data/shadi/x.keyring"), pw)
    }

    fn value(s: &KeyringFileStore, key: &str) -> Vec<u8> {
        s.get(key).unwrap().into_vec()
    }

    #[test]
    fn roundtrip_binary_replace_list_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"hunter2\n");
        assert!(s.is_available());
        assert!(s.list_keys().unwrap().is_empty());

        let bin = [0u8, 255, 10, 13, 0, 128];
        s.put("agent_keys/a/private", &bin).unwrap();
        s.put("agent_keys/b/private", b"text").unwrap();
        s.put("other", b"x").unwrap();
        assert_eq!(value(&s, "agent_keys/a/private"), bin);

        s.put("other", b"y").unwrap();
        assert_eq!(value(&s, "other"), b"y");

        assert_eq!(
            s.list_keys().unwrap(),
            ["agent_keys/a/private", "agent_keys/b/private", "other"]
        );
        assert_eq!(
            s.list_keys_prefixed("agent_keys/").unwrap(),
            ["agent_keys/a/private", "agent_keys/b/private"]
        );

        s.delete("other").unwrap();
        assert!(matches!(s.get("other"), Err(SecretError::InvalidInput)));
        assert!(matches!(s.delete("other"), Err(SecretError::InvalidInput)));
        assert!(matches!(s.get(""), Err(SecretError::InvalidInput)));
        assert!(matches!(s.put("", b"x"), Err(SecretError::InvalidInput)));
        assert!(matches!(s.delete(""), Err(SecretError::InvalidInput)));
    }

    #[test]
    fn concurrent_puts_are_all_saved() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"pw");
        std::thread::scope(|scope| {
            for i in 0..8 {
                let s = &s;
                scope.spawn(move || s.put(&format!("k{i}"), b"v").unwrap());
            }
        });
        assert_eq!(s.list_keys().unwrap().len(), 8);
    }

    #[test]
    fn unavailable_without_a_readable_password_file() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"pw");
        assert!(s.is_available());
        std::fs::remove_file(dir.path().join("pw")).unwrap();
        assert!(!s.is_available());
    }

    #[test]
    fn wrong_password_is_not_authorized() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"right");
        s.put("k", b"v").unwrap();
        std::fs::write(dir.path().join("pw"), b"wrong\r\n").unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::NotAuthorized)));
        assert!(matches!(s.list_keys(), Err(SecretError::NotAuthorized)));
        std::fs::write(dir.path().join("pw"), b"right\r\n").unwrap();
        assert_eq!(value(&s, "k"), b"v");
    }

    #[test]
    fn unreadable_or_empty_password_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"\n");
        assert!(matches!(s.put("k", b"v"), Err(SecretError::StorageFailure)));
        std::fs::remove_file(dir.path().join("pw")).unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
    }

    #[test]
    fn corrupt_keyring_file_is_a_storage_failure() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"pw");
        s.put("k", b"v").unwrap();
        std::fs::write(dir.path().join("data/shadi/x.keyring"), b"junk").unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
    }

    #[test]
    fn files_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"pw");
        s.put("k", b"v").unwrap();
        let mode = |p: &str| {
            std::fs::metadata(dir.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("data/shadi/x.keyring"), 0o600);
        assert_eq!(mode("data"), 0o700);
        assert_eq!(mode("data/shadi"), 0o700);
    }

    #[test]
    fn works_inside_a_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"pw");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { s.put("k", b"v").unwrap() });
        assert_eq!(value(&s, "k"), b"v");
    }

    #[test]
    fn config_comes_from_the_environment() {
        fn vars(pairs: &[(&str, &str)]) -> KeyringFileStore {
            KeyringFileStore::from_vars(|n| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| (*v).into())
            })
        }
        let cfg = |s: KeyringFileStore| s.config.unwrap().0;

        // No password file: unavailable and NotSupported, like the no-op store.
        let off = vars(&[("HOME", "/h")]);
        assert!(!off.is_available());
        assert!(matches!(off.get("k"), Err(SecretError::NotSupported)));
        assert!(matches!(off.put("k", b"v"), Err(SecretError::NotSupported)));
        assert!(matches!(off.delete("k"), Err(SecretError::NotSupported)));
        assert!(matches!(off.list_keys(), Err(SecretError::NotSupported)));

        let pw = ("SHADI_KEYRING_PASSWORD_FILE", "/pw");
        assert_eq!(
            cfg(vars(&[pw, ("HOME", "/h")])),
            Path::new("/h/.local/share/shadi/agent_secrets.keyring")
        );
        assert_eq!(
            cfg(vars(&[pw, ("HOME", "/h"), ("XDG_DATA_HOME", "/x")])),
            Path::new("/x/shadi/agent_secrets.keyring")
        );
        assert_eq!(
            cfg(vars(&[
                pw,
                ("XDG_DATA_HOME", "/x"),
                ("SHADI_KEYRING_PATH", "/k")
            ])),
            Path::new("/k")
        );
        assert!(vars(&[pw]).config.is_none());
        assert!(vars(&[
            ("SHADI_KEYRING_PATH", "/k"),
            ("SHADI_KEYRING_PASSWORD_FILE", "")
        ])
        .config
        .is_none());
    }
}
