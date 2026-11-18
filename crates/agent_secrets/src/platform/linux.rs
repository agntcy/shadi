// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Encrypted keyring file in the libsecret file format. No D-Bus, no daemon:
//! the password comes from a file, so it also works headless in containers.
//! Without `SHADI_KEYRING_PASSWORD_FILE` the store is unavailable, like the
//! no-op store; so it is when the keyring file does not exist, unless the
//! store was built to create it (only key provisioning does). A relative
//! `SHADI_KEYRING_PATH`, `SHADI_KEYRING_PASSWORD_FILE` or `HOME` is a
//! misconfiguration: unavailable, and every operation fails.
//!
//! Writers also hold an exclusive lock on `<keyring>.lock`; readers do not
//! lock, so they work on a read-only mount.

use std::ffi::OsString;
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
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
    /// (keyring file, password file); `None` when not configured, `Err` when
    /// misconfigured.
    config: Result<Option<(PathBuf, PathBuf)>, ()>,
    /// Whether a missing keyring file may be created.
    create: bool,
}

impl KeyringFileStore {
    pub fn from_env(create: bool) -> Self {
        Self::from_vars(|name| std::env::var_os(name), create)
    }

    fn from_vars(var: impl Fn(&str) -> Option<OsString>, create: bool) -> Self {
        let abs = |name: &str| {
            match var(name).filter(|v| !v.is_empty()).map(PathBuf::from) {
                Some(p) if !p.is_absolute() => {
                    eprintln!("{name} must be an absolute path");
                    Err(())
                }
                p => Ok(p),
            }
        };
        let config = (|| {
            let path = match abs("SHADI_KEYRING_PATH")? {
                Some(p) => Some(p),
                // Outside the paths the sandbox grants to children.
                None => abs("HOME")?.map(|h| h.join(".shadi/keyring/agent_secrets.keyring")),
            };
            Ok(path.zip(abs("SHADI_KEYRING_PASSWORD_FILE")?))
        })();
        Self { config, create }
    }

    #[cfg(test)]
    fn new(path: PathBuf, password_file: PathBuf, create: bool) -> Self {
        Self {
            config: Ok(Some((path, password_file))),
            create,
        }
    }

    /// Takes the exclusive writer lock, creating the keyring directory first
    /// when this store may create the keyring.
    fn lock_file(&self, path: &Path) -> SecretResult<std::fs::File> {
        let fail = |err: std::io::Error| {
            eprintln!("keyring lock failed: {err}");
            SecretError::StorageFailure
        };
        if let (true, Some(dir)) = (self.create, path.parent()) {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(fail)?;
        }
        let mut name = path.as_os_str().to_owned();
        name.push(".lock");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(name)
            .map_err(fail)?;
        file.lock().map_err(fail)?;
        Ok(file)
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

    /// Opens the keyring and runs `f` on a private thread and runtime, so
    /// callers inside a runtime are fine. `f` runs again on a fresh load if
    /// another process changed the file. A `write` holds the file lock; only a
    /// creating store may write a keyring that does not exist yet.
    fn with_keyring<T: Send>(
        &self,
        write: bool,
        f: impl AsyncFn(UnlockedKeyring) -> Result<T, oo7::file::Error> + Send,
    ) -> SecretResult<T> {
        let (path, password_file) = match &self.config {
            Ok(Some((path, password_file))) => (path, password_file),
            Ok(None) => return Err(SecretError::NotSupported),
            Err(()) => return Err(SecretError::InvalidInput),
        };
        let secret = Self::password(password_file)?;
        let _guard = KEYRING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !path.exists() && !(write && self.create) {
            eprintln!("keyring not found: {}", path.display());
            return Err(SecretError::StoreNotFound);
        }
        let _file_lock = if write { Some(self.lock_file(path)?) } else { None };
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
        self.with_keyring(true, async |k| {
            k.create_item(key, &attrs(key), Secret::blob(secret), true)
                .await
                .map(drop)
        })
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        check(key)?;
        self.with_keyring(false, async |k| {
            Ok(k.lookup_item(&attrs(key))
                .await?
                .map(|item| SecretBytes::new(item.secret().as_bytes().to_vec())))
        })?
        .ok_or(SecretError::InvalidInput)
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        check(key)?;
        let found = self.with_keyring(true, async |k| {
            if k.lookup_item(&attrs(key)).await?.is_none() {
                return Ok(false);
            }
            k.delete(&attrs(key)).await.map(|()| true)
        })?;
        found.then_some(()).ok_or(SecretError::InvalidInput)
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let mut keys = self.with_keyring(false, async |k| {
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
        // Opening the password file and looking for the keyring is enough:
        // inside the sandbox the variables are set but the files are denied.
        matches!(&self.config, Ok(Some((path, password_file)))
            if std::fs::File::open(password_file).is_ok() && (self.create || path.exists()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn store(dir: &Path, password: &[u8]) -> KeyringFileStore {
        let pw = dir.join("pw");
        std::fs::write(&pw, password).unwrap();
        KeyringFileStore::new(dir.join("data/shadi/x.keyring"), pw, true)
    }

    fn readonly(s: &KeyringFileStore) -> KeyringFileStore {
        let (path, pw) = s.config.clone().unwrap().unwrap();
        KeyringFileStore::new(path, pw, false)
    }

    fn value(s: &KeyringFileStore, key: &str) -> Vec<u8> {
        s.get(key).unwrap().into_vec()
    }

    #[test]
    fn roundtrip_binary_replace_list_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"hunter2\n");
        assert!(s.is_available());

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
            KeyringFileStore::from_vars(
                |n| {
                    pairs
                        .iter()
                        .find(|(k, _)| *k == n)
                        .map(|(_, v)| (*v).into())
                },
                false,
            )
        }
        let cfg = |s: KeyringFileStore| s.config.unwrap().unwrap().0;

        // No password file: unavailable and NotSupported, like the no-op store.
        let off = vars(&[("HOME", "/h")]);
        assert!(!off.is_available());
        assert!(matches!(off.get("k"), Err(SecretError::NotSupported)));
        assert!(matches!(off.put("k", b"v"), Err(SecretError::NotSupported)));
        assert!(matches!(off.delete("k"), Err(SecretError::NotSupported)));
        assert!(matches!(off.list_keys(), Err(SecretError::NotSupported)));

        let pw = ("SHADI_KEYRING_PASSWORD_FILE", "/pw");
        assert_eq!(
            cfg(vars(&[pw, ("HOME", "/h"), ("XDG_DATA_HOME", "/x")])),
            Path::new("/h/.shadi/keyring/agent_secrets.keyring")
        );
        assert_eq!(
            cfg(vars(&[pw, ("HOME", "relative"), ("SHADI_KEYRING_PATH", "/k")])),
            Path::new("/k")
        );
        assert!(vars(&[pw]).config.unwrap().is_none());
        assert!(vars(&[
            ("SHADI_KEYRING_PATH", "/k"),
            ("SHADI_KEYRING_PASSWORD_FILE", "")
        ])
        .config
        .unwrap()
        .is_none());
    }

    #[test]
    fn relative_paths_are_a_misconfiguration() {
        let pw = ("SHADI_KEYRING_PASSWORD_FILE", "/pw");
        for pairs in [
            vec![pw, ("HOME", "h")],
            vec![pw, ("SHADI_KEYRING_PATH", "k")],
            vec![("SHADI_KEYRING_PASSWORD_FILE", "pw"), ("HOME", "/h")],
        ] {
            let s = KeyringFileStore::from_vars(
                |n| pairs.iter().find(|(k, _)| *k == n).map(|(_, v)| (*v).into()),
                true,
            );
            assert!(!s.is_available());
            assert!(matches!(s.get("k"), Err(SecretError::InvalidInput)));
            assert!(matches!(s.put("k", b"v"), Err(SecretError::InvalidInput)));
            assert!(matches!(s.delete("k"), Err(SecretError::InvalidInput)));
            assert!(matches!(s.list_keys(), Err(SecretError::InvalidInput)));
        }
    }

    #[test]
    fn missing_keyring_is_not_found_unless_creating() {
        let dir = tempfile::tempdir().unwrap();
        let creating = store(dir.path(), b"pw");
        let s = readonly(&creating);
        assert!(!s.is_available());
        assert!(matches!(s.get("k"), Err(SecretError::StoreNotFound)));
        assert!(matches!(s.put("k", b"v"), Err(SecretError::StoreNotFound)));
        assert!(matches!(s.delete("k"), Err(SecretError::StoreNotFound)));
        assert!(matches!(s.list_keys(), Err(SecretError::StoreNotFound)));
        assert!(!dir.path().join("data").exists());

        assert!(creating.is_available());
        creating.put("k", b"v").unwrap();
        assert!(s.is_available());
        assert_eq!(value(&s, "k"), b"v");
    }

    #[test]
    fn writes_take_a_lock_file_and_reads_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"pw");
        s.put("k", b"v").unwrap();
        let lock = dir.path().join("data/shadi/x.keyring.lock");
        assert_eq!(std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777, 0o600);

        std::fs::remove_file(&lock).unwrap();
        assert_eq!(value(&s, "k"), b"v");
        s.list_keys().unwrap();
        assert!(!lock.exists());
        s.delete("k").unwrap();
        assert!(lock.exists());
    }

    #[test]
    fn reads_work_on_a_read_only_keyring_dir() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), b"pw");
        s.put("k", b"v").unwrap();
        let keyring_dir = dir.path().join("data/shadi");
        let lock = keyring_dir.join("x.keyring.lock");
        std::fs::remove_file(&lock).unwrap();
        std::fs::set_permissions(&keyring_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let r = readonly(&s);
        assert!(r.is_available());
        assert_eq!(value(&r, "k"), b"v");
        assert_eq!(r.list_keys().unwrap(), ["k"]);
        assert!(!lock.exists());

        std::fs::set_permissions(&keyring_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
