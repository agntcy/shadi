// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Encrypted keyring file in the libsecret file format. No D-Bus, no daemon:
//! the password comes from a file, so it also works headless in containers.
//! Without `SHADI_KEYRING_PASSWORD_FILE` the store is unavailable, like the
//! no-op store, whatever else is set. With it set, a relative
//! `SHADI_KEYRING_PATH`, `SHADI_KEYRING_PASSWORD_FILE` or `HOME` is a
//! misconfiguration: unavailable, and every operation fails.
//! Only a store built to create the keyring (key provisioning) writes one that
//! does not exist yet.
//!
//! Writers also hold an exclusive lock on `<keyring>.lock`; readers do not
//! lock, so they work on a read-only mount.

use std::ffi::OsString;
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use oo7::file::UnlockedKeyring;
use oo7::Secret;
use zeroize::Zeroizing;

use crate::memory::SecretBytes;
use crate::{SecretError, SecretResult, SecretStore};

const SERVICE: &str = "agent_secrets";
/// oo7 accepts any password for a keyring with no items, so every keyring
/// keeps this item to check the password against. Its `service` differs from
/// [`SERVICE`], so it is never listed, read or deleted as a key.
const CANARY: [(&str, &str); 1] = [("service", "agent_secrets/canary")];
/// Tries when another process saved between our load and our save.
const SAVE_ATTEMPTS: usize = 5;
/// How long a writer waits for another process to release `<keyring>.lock`.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(50);

/// Serialises load, modify and save within the process: oo7 refuses a save
/// when the file changed since it was loaded.
static KEYRING_LOCK: Mutex<()> = Mutex::new(());

/// Queues this process's writers before the file lock, so they don't use up
/// each other's [`LOCK_TIMEOUT`].
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Misconfigurations already reported, so each is printed once per process.
static WARNED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// How the environment configures the keyring file store, for reporting.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyringConfig {
    /// `SHADI_KEYRING_PASSWORD_FILE` is unset: the store is off, like the
    /// no-op store.
    NotConfigured,
    /// A path variable is relative, so every operation fails.
    Misconfigured,
    Configured {
        keyring: PathBuf,
        password_file: PathBuf,
    },
}

/// The configuration [`default_store`](crate::default_store) would use. It
/// reads no file, so it answers the same inside a sandbox as outside.
pub fn keyring_config() -> KeyringConfig {
    KeyringFileStore::from_env(false).describe()
}

pub struct KeyringFileStore {
    /// (keyring file, password file); `None` when not configured, `Err` when
    /// misconfigured.
    config: Result<Option<(PathBuf, PathBuf)>, ()>,
    /// Whether a missing keyring file may be created.
    create: bool,
    lock_timeout: Duration,
}

impl KeyringFileStore {
    pub fn from_env(create: bool) -> Self {
        Self::from_vars(|name| std::env::var_os(name), create)
    }

    fn describe(&self) -> KeyringConfig {
        match &self.config {
            Ok(Some((keyring, password_file))) => KeyringConfig::Configured {
                keyring: keyring.clone(),
                password_file: password_file.clone(),
            },
            Ok(None) => KeyringConfig::NotConfigured,
            Err(()) => KeyringConfig::Misconfigured,
        }
    }

    fn from_vars(var: impl Fn(&str) -> Option<OsString>, create: bool) -> Self {
        let abs = |name: &str| {
            match var(name).filter(|v| !v.is_empty()).map(PathBuf::from) {
                Some(p) if !p.is_absolute() => {
                    let mut warned = WARNED.lock().unwrap_or_else(|e| e.into_inner());
                    if !warned.iter().any(|w| w == name) {
                        eprintln!("{name} must be an absolute path");
                        warned.push(name.to_owned());
                    }
                    Err(())
                }
                p => Ok(p),
            }
        };
        let config = (|| {
            // The password file decides whether the store is on at all, so it
            // comes first: a relative HOME is no error for a store that is off.
            let Some(password_file) = abs("SHADI_KEYRING_PASSWORD_FILE")? else {
                return Ok(None);
            };
            let path = match abs("SHADI_KEYRING_PATH")? {
                Some(p) => p,
                // Outside the paths the sandbox grants to children.
                None => match abs("HOME")? {
                    Some(h) => h.join(".shadi/keyring/agent_secrets.keyring"),
                    None => return Ok(None),
                },
            };
            Ok(Some((path, password_file)))
        })();
        Self {
            config,
            create,
            lock_timeout: LOCK_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn new(path: PathBuf, password_file: PathBuf, create: bool) -> Self {
        Self {
            config: Ok(Some((path, password_file))),
            create,
            lock_timeout: LOCK_TIMEOUT,
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
        let name = PathBuf::from(name);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&name)
            .map_err(fail)?;
        let deadline = Instant::now() + self.lock_timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(LOCK_POLL);
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    eprintln!(
                        "keyring lock still held after {}s: {}",
                        self.lock_timeout.as_secs_f32(),
                        name.display()
                    );
                    return Err(SecretError::StorageFailure);
                }
                Err(std::fs::TryLockError::Error(err)) => return Err(fail(err)),
            }
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
            Err(()) => return Err(SecretError::StorageFailure),
        };
        let secret = Self::password(password_file)?;
        let gone = || !path.exists() && !(write && self.create);
        if gone() {
            eprintln!("keyring not found: {}", path.display());
            return Err(SecretError::StoreNotFound);
        }
        // The file lock is taken before KEYRING_LOCK, so a writer waiting on
        // another process holds up neither this process's reads nor, past
        // the timeout, its writes.
        let _write_guard = write.then(|| WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner()));
        let _file_lock = if write {
            Some(self.lock_file(path)?)
        } else {
            None
        };
        let _guard = KEYRING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::thread::scope(|s| {
            s.spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .map_err(|_| SecretError::StorageFailure)?
                    .block_on(async {
                        let mut attempt = 1;
                        loop {
                            // Deleted while we waited for the lock or retried.
                            if gone() {
                                eprintln!("keyring not found: {}", path.display());
                                return Err(SecretError::StoreNotFound);
                            }
                            let created = !path.exists();
                            let keyring = UnlockedKeyring::load(path, Some(secret.clone()))
                                .await
                                .map_err(to_secret)?;
                            let checked = if write {
                                ensure_canary(&keyring, created, path).await
                            } else {
                                Ok(Ok(()))
                            };
                            let result = match checked {
                                Ok(Ok(())) => f(keyring).await,
                                Ok(Err(refused)) => return Err(refused),
                                Err(err) => Err(err),
                            };
                            match result {
                                Err(oo7::file::Error::TargetFileChanged(_))
                                    if attempt < SAVE_ATTEMPTS =>
                                {
                                    attempt += 1;
                                }
                                result => break result.map_err(to_secret),
                            }
                        }
                    })
            })
            .join()
            .map_err(|_| SecretError::StorageFailure)?
        })
    }
}

fn to_secret(err: oo7::file::Error) -> SecretError {
    match err {
        oo7::file::Error::IncorrectSecret => SecretError::NotAuthorized,
        err => {
            eprintln!("keyring failed: {err}");
            SecretError::StorageFailure
        }
    }
}

/// Before a write, make sure the keyring holds [`CANARY`], so the password is
/// checked on every later load even once the last key is deleted. A keyring
/// with items has had its password checked by the load; one with none can
/// only be trusted if this call is creating it. The inner `Err` refuses the
/// write.
async fn ensure_canary(
    keyring: &UnlockedKeyring,
    created: bool,
    path: &Path,
) -> Result<SecretResult<()>, oo7::file::Error> {
    if !keyring.search_items(&CANARY).await?.is_empty() {
        return Ok(Ok(()));
    }
    if keyring.n_items().await == 0 && !created {
        eprintln!(
            "keyring has no items to check the password against: {}; remove it and \
             provision the keys again",
            path.display()
        );
        return Ok(Err(SecretError::NotAuthorized));
    }
    keyring
        .create_item("agent_secrets canary", &CANARY, Secret::blob(SERVICE), true)
        .await?;
    Ok(Ok(()))
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
        // Configuration only, never whether the files can be opened: inside
        // the sandbox the variables are set but the files are denied, and a
        // caller choosing a backend by file access (the credential vault)
        // would then pick a different one there than on the host.
        matches!(self.config, Ok(Some(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A password that differs on every run, so the tests hard-code none.
    fn random_password() -> String {
        use std::io::Read;
        let mut raw = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut raw)
            .unwrap();
        raw.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A creating store whose password file holds a fresh random password;
    /// [`password_file`] reads it back.
    fn store(dir: &Path) -> KeyringFileStore {
        let pw = dir.join("pw");
        std::fs::write(&pw, random_password()).unwrap();
        KeyringFileStore::new(dir.join("data/shadi/x.keyring"), pw, true)
    }

    fn password_file(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("pw")).unwrap()
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
        let s = store(dir.path());
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
        let s = store(dir.path());
        std::thread::scope(|scope| {
            for i in 0..8 {
                let s = &s;
                scope.spawn(move || s.put(&format!("k{i}"), b"v").unwrap());
            }
        });
        assert_eq!(s.list_keys().unwrap().len(), 8);
    }

    /// The credential vault picks its backend from `is_available`; a sandbox
    /// that denies the password file must not make it pick another one.
    #[test]
    fn availability_follows_configuration_not_file_access() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        std::fs::remove_file(dir.path().join("pw")).unwrap();
        assert!(s.is_available());
        assert!(readonly(&s).is_available());
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
    }

    #[test]
    fn an_emptied_keyring_still_rejects_a_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let right = password_file(dir.path());
        s.put("k", b"v").unwrap();
        s.delete("k").unwrap();
        assert!(s.list_keys().unwrap().is_empty());

        std::fs::write(dir.path().join("pw"), random_password()).unwrap();
        assert!(matches!(s.put("k", b"v"), Err(SecretError::NotAuthorized)));
        assert!(matches!(s.get("k"), Err(SecretError::NotAuthorized)));

        std::fs::write(dir.path().join("pw"), &right).unwrap();
        s.put("k", b"v2").unwrap();
        assert_eq!(value(&s, "k"), b"v2");
    }

    /// A keyring with no items at all, as written before the canary, can't
    /// tell a wrong password from the right one, so it is not written to.
    #[test]
    fn a_keyring_with_no_items_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let (path, pw) = s.config.clone().unwrap().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let secret = KeyringFileStore::password(&pw).unwrap();
                UnlockedKeyring::load(&path, Some(secret))
                    .await
                    .unwrap()
                    .write()
                    .await
                    .unwrap();
            });
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(s.put("k", b"v"), Err(SecretError::NotAuthorized)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn wrong_password_is_not_authorized() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let right = password_file(dir.path());
        s.put("k", b"v").unwrap();
        std::fs::write(dir.path().join("pw"), format!("{}\r\n", random_password())).unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::NotAuthorized)));
        assert!(matches!(s.list_keys(), Err(SecretError::NotAuthorized)));
        // The line ending after the password is not part of it.
        for ending in ["\r\n", "\n"] {
            std::fs::write(dir.path().join("pw"), format!("{right}{ending}")).unwrap();
            assert_eq!(value(&s, "k"), b"v");
        }
    }

    #[test]
    fn unreadable_or_empty_password_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        std::fs::write(dir.path().join("pw"), b"\n").unwrap();
        assert!(matches!(s.put("k", b"v"), Err(SecretError::StorageFailure)));
        std::fs::remove_file(dir.path().join("pw")).unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
    }

    #[test]
    fn corrupt_keyring_file_is_a_storage_failure() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        std::fs::write(dir.path().join("data/shadi/x.keyring"), b"junk").unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
    }

    #[test]
    fn files_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
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
        let s = store(dir.path());
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

        // A relative HOME or keyring path matters only once the store is on:
        // without a password file it is NotSupported, not StorageFailure.
        for pairs in [
            vec![("HOME", "relative")],
            vec![("SHADI_KEYRING_PATH", "relative")],
            vec![("HOME", "relative"), ("SHADI_KEYRING_PATH", "relative")],
        ] {
            let off = vars(&pairs);
            assert_eq!(off.describe(), KeyringConfig::NotConfigured);
            assert!(!off.is_available());
            assert!(matches!(off.get("k"), Err(SecretError::NotSupported)));
            assert!(matches!(off.put("k", b"v"), Err(SecretError::NotSupported)));
        }
        assert_eq!(
            vars(&[pw, ("HOME", "/h")]).describe(),
            KeyringConfig::Configured {
                keyring: "/h/.shadi/keyring/agent_secrets.keyring".into(),
                password_file: "/pw".into(),
            }
        );
        assert_eq!(
            vars(&[pw, ("HOME", "relative")]).describe(),
            KeyringConfig::Misconfigured
        );
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
            assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
            assert!(matches!(s.put("k", b"v"), Err(SecretError::StorageFailure)));
            assert!(matches!(s.delete("k"), Err(SecretError::StorageFailure)));
            assert!(matches!(s.list_keys(), Err(SecretError::StorageFailure)));
        }
    }

    #[test]
    fn missing_keyring_is_not_found_unless_creating() {
        let dir = tempfile::tempdir().unwrap();
        let creating = store(dir.path());
        let s = readonly(&creating);
        assert!(s.is_available());
        assert!(matches!(s.get("k"), Err(SecretError::StoreNotFound)));
        assert!(matches!(s.put("k", b"v"), Err(SecretError::StoreNotFound)));
        assert!(matches!(s.delete("k"), Err(SecretError::StoreNotFound)));
        assert!(matches!(s.list_keys(), Err(SecretError::StoreNotFound)));
        assert!(!dir.path().join("data").exists());

        creating.put("k", b"v").unwrap();
        assert_eq!(value(&s, "k"), b"v");
    }

    #[test]
    fn writes_take_a_lock_file_and_reads_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
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
        let s = store(dir.path());
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

    fn lock_path(dir: &Path) -> PathBuf {
        dir.join("data/shadi/x.keyring.lock")
    }

    fn hold_lock(dir: &Path) -> std::fs::File {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_path(dir))
            .unwrap();
        f.lock().unwrap();
        f
    }

    #[test]
    fn writers_wait_for_the_file_lock() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("seed", b"v").unwrap();
        // Held outside the store, so only the file lock can block the put.
        let held = hold_lock(dir.path());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| tx.send(s.put("k", b"v")).unwrap());
            assert!(rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err());
            drop(held);
            rx.recv_timeout(std::time::Duration::from_secs(30))
                .unwrap()
                .unwrap();
        });
        assert_eq!(value(&s, "k"), b"v");
    }

    /// A process that never releases `<keyring>.lock` fails a write after the
    /// timeout and, meanwhile, doesn't hold up a read.
    #[test]
    fn a_stuck_lock_holder_times_out_writes_and_spares_reads() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        s.put("seed", b"v").unwrap();
        s.lock_timeout = Duration::from_secs(5);
        let _held = hold_lock(dir.path());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| tx.send(s.put("k", b"v")).unwrap());
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(value(&s, "seed"), b"v");
            assert!(rx.try_recv().is_err(), "the write gave up before the read finished");
            let res = rx.recv_timeout(Duration::from_secs(30)).unwrap();
            assert!(matches!(res, Err(SecretError::StorageFailure)));
        });
    }

    #[test]
    fn non_creating_writer_does_not_recreate_a_keyring_deleted_while_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let creating = store(dir.path());
        creating.put("k", b"v").unwrap();
        let s = readonly(&creating);
        let held = hold_lock(dir.path());
        let keyring = dir.path().join("data/shadi/x.keyring");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| tx.send(s.put("n", b"v")).unwrap());
            assert!(rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err());
            std::fs::remove_file(&keyring).unwrap();
            drop(held);
            let res = rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            assert!(matches!(res, Err(SecretError::StoreNotFound)));
        });
        assert!(!keyring.exists());
    }

    #[test]
    fn lock_file_is_not_followed_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        let target = dir.path().join("victim");
        let lock = lock_path(dir.path());
        std::fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        assert!(matches!(s.put("k2", b"v"), Err(SecretError::StorageFailure)));
        assert!(matches!(s.delete("k"), Err(SecretError::StorageFailure)));
        assert!(!target.exists());
    }

    #[test]
    fn save_retries_when_the_file_changed_after_load() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("seed", b"v").unwrap();
        let (path, pw) = s.config.clone().unwrap().unwrap();
        let first = std::sync::atomic::AtomicBool::new(true);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        s.with_keyring(true, async |k| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                // A concurrent writer in another process.
                let secret = KeyringFileStore::password(&pw).unwrap();
                let other = UnlockedKeyring::load(&path, Some(secret)).await?;
                other
                    .create_item("a", &attrs("a"), Secret::blob(b"1"), true)
                    .await?;
            }
            k.create_item("b", &attrs("b"), Secret::blob(b"2"), true)
                .await
                .map(drop)
        })
        .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(s.list_keys().unwrap(), ["a", "b", "seed"]);
    }
}
