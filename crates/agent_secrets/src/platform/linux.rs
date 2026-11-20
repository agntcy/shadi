// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Encrypted keyring file: a SQLCipher database. No D-Bus, no daemon: the
//! password comes from a file, so it also works headless in containers.
//! Without `SHADI_KEYRING_PASSWORD_FILE` the store is unavailable, like the
//! no-op store, whatever else is set. With it set, a relative
//! `SHADI_KEYRING_PATH`, `SHADI_KEYRING_PASSWORD_FILE` or `HOME` is a
//! misconfiguration: unavailable, and every operation fails.
//! Only a store built to create the keyring (key provisioning) writes one that
//! does not exist yet.
//!
//! SQLite's file locks order writers across processes. Readers open the file
//! read-only, except to roll back a write that was interrupted, so they work
//! on a read-only mount. Nothing else may open the
//! keyring file: closing any descriptor to it drops this process's SQLite
//! locks on it.

use std::ffi::OsString;
use std::fs::{DirBuilder, Metadata, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{ffi, Connection, ErrorCode, OpenFlags, OptionalExtension};
use zeroize::Zeroizing;

use crate::memory::SecretBytes;
use crate::{SecretError, SecretResult, SecretStore};

/// How long an operation waits for another process's lock on the keyring.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// SQLCipher 4's page size: an intact keyring is a whole number of pages.
const PAGE_SIZE: u64 = 4096;
const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = "CREATE TABLE secrets (
    name TEXT PRIMARY KEY NOT NULL CHECK (name <> ''),
    value BLOB NOT NULL
) WITHOUT ROWID;";

/// Numbers the temporary files new keyrings are built in.
static NEXT_NEW: AtomicU64 = AtomicU64::new(0);
/// Temporary file names a create tries before giving up.
const NEW_ATTEMPTS: usize = 100;

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
                    Some(h) => h.join(".shadi/keyring/agent_secrets.db"),
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

    /// The password, without the line ending after it. SQLCipher takes the
    /// passphrase as text.
    fn password(file: &Path) -> SecretResult<Zeroizing<String>> {
        let raw = Zeroizing::new(std::fs::read(file).map_err(|_| SecretError::StorageFailure)?);
        let Ok(text) = std::str::from_utf8(&raw) else {
            eprintln!("keyring password file is not UTF-8: {}", file.display());
            return Err(SecretError::StorageFailure);
        };
        let text = text.trim_end_matches(['\n', '\r']);
        if text.is_empty() {
            return Err(SecretError::StorageFailure);
        }
        if text.contains('\0') {
            eprintln!(
                "keyring password file contains a NUL byte: {}",
                file.display()
            );
            return Err(SecretError::StorageFailure);
        }
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Runs `f` on the unlocked keyring. A `write` opens it read-write; only a
    /// creating store writes a keyring that does not exist yet.
    fn with_db<T>(
        &self,
        write: bool,
        f: impl Fn(&Connection) -> rusqlite::Result<T>,
    ) -> SecretResult<T> {
        let (path, password_file) = match &self.config {
            Ok(Some((path, password_file))) => (path, password_file),
            Ok(None) => return Err(SecretError::NotSupported),
            Err(()) => return Err(SecretError::StorageFailure),
        };
        let password = Self::password(password_file)?;
        let meta = match stat(path)? {
            Some(meta) => meta,
            None if write && self.create => {
                create(path, &password, self.lock_timeout)?;
                stat(path)?.ok_or(SecretError::StoreNotFound)?
            }
            None => {
                eprintln!("keyring not found: {}", path.display());
                return Err(SecretError::StoreNotFound);
            }
        };
        if meta.len() == 0 {
            eprintln!(
                "keyring file is empty, so it can't check the password: {}; remove it and \
                 provision the keys again",
                path.display()
            );
            return Err(SecretError::NotAuthorized);
        }
        let run = |rw: bool| -> rusqlite::Result<SecretResult<T>> {
            let conn = unlock(path, &password, rw, self.lock_timeout)?;
            let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            if version != SCHEMA_VERSION {
                eprintln!(
                    "keyring has schema version {version}, not {SCHEMA_VERSION}: {}",
                    path.display()
                );
                return Ok(Err(SecretError::StorageFailure));
            }
            f(&conn).map(Ok)
        };
        match run(write) {
            // Only a read-write connection can roll back an interrupted write.
            Err(err) if !write && interrupted(&err) => run(true),
            result => result,
        }
        .unwrap_or_else(|err| Err(failure(err, path, meta.len())))
    }
}

/// Whether `err` is SQLite refusing to roll back a hot journal on a read-only
/// connection.
fn interrupted(err: &rusqlite::Error) -> bool {
    err.sqlite_error()
        .is_some_and(|e| e.extended_code == ffi::SQLITE_READONLY_ROLLBACK)
}

/// The keyring's metadata, `None` when it does not exist. Anything but a
/// regular file is refused: SQLite would follow a symlink.
fn stat(path: &Path) -> SecretResult<Option<Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(Some(meta)),
        Ok(_) => {
            eprintln!("keyring is not a regular file: {}", path.display());
            Err(SecretError::StorageFailure)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            eprintln!("keyring failed: {err}");
            Err(SecretError::StorageFailure)
        }
    }
}

/// Opens and unlocks `path`. A wrong password fails here, not on first use.
fn unlock(
    path: &Path,
    password: &str,
    write: bool,
    timeout: Duration,
) -> rusqlite::Result<Connection> {
    let access = if write {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let conn = Connection::open_with_flags(
        path,
        access | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(timeout)?;
    // The error would quote the statement, and with it the password.
    conn.pragma_update(None, "key", password).map_err(|_| {
        rusqlite::Error::SqliteFailure(
            ffi::Error::new(ffi::SQLITE_MISUSE),
            Some("the keyring password was not accepted".to_owned()),
        )
    })?;
    conn.pragma_update(None, "cipher_compatibility", 4)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    conn.pragma_update(None, "secure_delete", true)?;
    conn.pragma_update(None, "temp_store", 2)?;
    Ok(conn)
}

/// Builds a new keyring next to `path` and links it into place, so no process
/// ever sees one without its schema. Losing the race to another creator is
/// fine: the caller then opens theirs.
fn create(path: &Path, password: &str, timeout: Duration) -> SecretResult<()> {
    let fail = |err: &dyn std::fmt::Display| {
        eprintln!("keyring create failed: {err}");
        SecretError::StorageFailure
    };
    if let Some(dir) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|err| fail(&err))?;
    }
    let mut attempt = 1;
    let tmp = loop {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(format!(
            ".{}-{}.new",
            std::process::id(),
            NEXT_NEW.fetch_add(1, Ordering::Relaxed)
        ));
        let tmp = PathBuf::from(tmp);
        // create_new never follows a symlink at `tmp`.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(_) => break tmp,
            // Left by a crashed create, maybe in a container that reused our PID.
            Err(err)
                if err.kind() == std::io::ErrorKind::AlreadyExists && attempt < NEW_ATTEMPTS =>
            {
                attempt += 1;
            }
            Err(err) => return Err(fail(&err)),
        }
    };
    let linked = (|| {
        let conn = unlock(&tmp, password, true, timeout).map_err(|err| fail(&err))?;
        conn.execute_batch(SCHEMA).map_err(|err| fail(&err))?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|err| fail(&err))?;
        drop(conn);
        match std::fs::hard_link(&tmp, path) {
            Err(err) if err.kind() != std::io::ErrorKind::AlreadyExists => {
                eprintln!(
                    "keyring create failed: {err}; the keyring directory must support hard links: {}",
                    path.display()
                );
                Err(SecretError::StorageFailure)
            }
            _ => Ok(()),
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    linked
}

/// SQLCipher can't tell a wrong password from a damaged first page. A file
/// that isn't a whole number of pages is damaged; anything else is taken as
/// the wrong password. A keyring removed or replaced while in use counts as
/// not found.
fn failure(err: rusqlite::Error, path: &Path, len: u64) -> SecretError {
    if err
        .sqlite_error()
        .is_some_and(|e| e.extended_code == ffi::SQLITE_READONLY_DBMOVED)
    {
        eprintln!("keyring was removed or replaced: {}", path.display());
        return SecretError::StoreNotFound;
    }
    match err.sqlite_error_code() {
        Some(ErrorCode::NotADatabase) if len.is_multiple_of(PAGE_SIZE) => {
            eprintln!(
                "keyring cannot be decrypted: wrong password or damaged file: {}; check the \
                 password file, and restore the keyring from a backup rather than \
                 provisioning it again",
                path.display()
            );
            SecretError::NotAuthorized
        }
        Some(ErrorCode::ReadOnly) if interrupted(&err) => {
            eprintln!(
                "keyring has an interrupted write that needs a writable keyring to roll back: {}",
                path.display()
            );
            SecretError::StorageFailure
        }
        Some(ErrorCode::DatabaseBusy) => {
            eprintln!("keyring is locked by another process: {}", path.display());
            SecretError::StorageFailure
        }
        _ => {
            eprintln!("keyring failed: {err}");
            SecretError::StorageFailure
        }
    }
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
        self.with_db(true, |db| {
            db.execute(
                "INSERT INTO secrets (name, value) VALUES (?1, ?2) \
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value",
                (key, secret),
            )
            .map(drop)
        })
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        check(key)?;
        self.with_db(false, |db| {
            db.query_row("SELECT value FROM secrets WHERE name = ?1", [key], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .optional()
        })?
        .map(SecretBytes::new)
        .ok_or(SecretError::InvalidInput)
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        check(key)?;
        let deleted = self.with_db(true, |db| {
            db.execute("DELETE FROM secrets WHERE name = ?1", [key])
        })?;
        (deleted > 0).then_some(()).ok_or(SecretError::InvalidInput)
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        self.with_db(false, |db| {
            db.prepare("SELECT name FROM secrets ORDER BY name")?
                .query_map([], |row| row.get(0))?
                .collect()
        })
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
    use rusqlite::TransactionBehavior;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;

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

    fn keyring(dir: &Path) -> PathBuf {
        dir.join("data/shadi/x.keyring")
    }

    /// A connection of its own, as another process would open it.
    fn other_process(s: &KeyringFileStore) -> Connection {
        let (path, pw) = s.config.clone().unwrap().unwrap();
        unlock(
            &path,
            &KeyringFileStore::password(&pw).unwrap(),
            true,
            LOCK_TIMEOUT,
        )
        .unwrap()
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
    fn unreadable_empty_or_binary_password_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        std::fs::write(dir.path().join("pw"), b"\n").unwrap();
        assert!(matches!(s.put("k", b"v"), Err(SecretError::StorageFailure)));
        std::fs::write(dir.path().join("pw"), [0xff, 0xfe]).unwrap();
        assert!(matches!(s.put("k", b"v"), Err(SecretError::StorageFailure)));
        // SQLite stops reading the key pragma at a NUL, and the error would
        // carry the password.
        let nul = format!("{}\0{}", random_password(), random_password());
        std::fs::write(dir.path().join("pw"), nul).unwrap();
        assert!(matches!(s.put("k", b"v"), Err(SecretError::StorageFailure)));
        std::fs::remove_file(dir.path().join("pw")).unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
    }

    #[test]
    fn a_truncated_keyring_is_a_storage_failure() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        std::fs::remove_file(keyring(dir.path())).unwrap();
        std::fs::write(keyring(dir.path()), b"junk").unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
    }

    /// SQLCipher can't tell a damaged first page from a wrong password.
    #[test]
    fn a_damaged_keyring_of_whole_pages_is_not_authorized() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        let mut bytes = std::fs::read(keyring(dir.path())).unwrap();
        bytes[100] ^= 0xff;
        std::fs::remove_file(keyring(dir.path())).unwrap();
        std::fs::write(keyring(dir.path()), &bytes).unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::NotAuthorized)));
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
            Path::new("/h/.shadi/keyring/agent_secrets.db")
        );
        assert_eq!(
            cfg(vars(&[
                pw,
                ("HOME", "relative"),
                ("SHADI_KEYRING_PATH", "/k")
            ])),
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
                keyring: "/h/.shadi/keyring/agent_secrets.db".into(),
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
                |n| {
                    pairs
                        .iter()
                        .find(|(k, _)| *k == n)
                        .map(|(_, v)| (*v).into())
                },
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
    fn reads_work_on_a_read_only_keyring_dir() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        let keyring_dir = dir.path().join("data/shadi");
        std::fs::set_permissions(&keyring_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let r = readonly(&s);
        assert!(r.is_available());
        assert_eq!(value(&r, "k"), b"v");
        assert_eq!(r.list_keys().unwrap(), ["k"]);
        let left: Vec<_> = std::fs::read_dir(&keyring_dir).unwrap().collect();
        assert_eq!(left.len(), 1, "a read left a journal or temp file behind");

        std::fs::set_permissions(&keyring_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// An empty file takes any password, so it is not written to, even by a
    /// store allowed to create keyrings.
    #[test]
    fn an_empty_keyring_file_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let path = keyring(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(s.put("k", b"v"), Err(SecretError::NotAuthorized)));
        assert!(matches!(s.get("k"), Err(SecretError::NotAuthorized)));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    /// A writer that died mid-transaction leaves a hot journal, which only a
    /// read-write connection can roll back.
    #[test]
    fn a_read_rolls_back_an_interrupted_write() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        let (path, pw) = s.config.clone().unwrap().unwrap();
        let password = KeyringFileStore::password(&pw).unwrap();

        let conn = unlock(&path, &password, true, LOCK_TIMEOUT).unwrap();
        conn.pragma_update(None, "cache_size", 1).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        conn.execute("UPDATE secrets SET value = x'00' WHERE name = 'k'", [])
            .unwrap();
        for i in 0..200 {
            conn.execute(
                "INSERT INTO secrets (name, value) VALUES (?1, zeroblob(4096))",
                [format!("filler{i}")],
            )
            .unwrap();
        }
        // Opening the file while `conn` holds its locks is safe only because
        // the file is private to this test: closing the copy's descriptor
        // drops this process's SQLite locks on it.
        let mut journal = path.as_os_str().to_owned();
        journal.push("-journal");
        let crashed = dir.path().join("crashed/x.keyring");
        std::fs::create_dir_all(crashed.parent().unwrap()).unwrap();
        let mut crashed_journal = crashed.as_os_str().to_owned();
        crashed_journal.push("-journal");
        std::fs::copy(&path, &crashed).unwrap();
        std::fs::copy(&journal, &crashed_journal).unwrap();
        drop(conn);

        let r = KeyringFileStore::new(crashed.clone(), pw, false);
        assert_eq!(value(&r, "k"), b"v");
        assert_eq!(r.list_keys().unwrap(), ["k"]);
        assert!(!Path::new(&crashed_journal).exists());
    }

    /// A crashed create leaves its temporary file behind, and a container
    /// that restarts reuses the PID in its name.
    #[test]
    fn a_leftover_temporary_file_does_not_block_create() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let path = keyring(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let next = NEXT_NEW.load(Ordering::Relaxed);
        for n in next..next + 50 {
            let mut tmp = path.as_os_str().to_owned();
            tmp.push(format!(".{}-{n}.new", std::process::id()));
            std::fs::write(tmp, b"").unwrap();
        }
        s.put("k", b"v").unwrap();
        assert_eq!(value(&s, "k"), b"v");
    }

    #[test]
    fn writes_are_seen_across_connections() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("mine", b"1").unwrap();
        let other = other_process(&s);
        other
            .execute(
                "INSERT INTO secrets (name, value) VALUES ('theirs', x'02')",
                [],
            )
            .unwrap();
        assert_eq!(value(&s, "theirs"), [2]);
        s.put("mine", b"3").unwrap();
        let mine: Vec<u8> = other
            .query_row("SELECT value FROM secrets WHERE name = 'mine'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(mine, b"3");
    }

    #[test]
    fn writers_wait_for_another_writer() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("seed", b"v").unwrap();
        let mut other = other_process(&s);
        let held = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| tx.send(s.put("k", b"v")).unwrap());
            assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
            held.commit().unwrap();
            rx.recv_timeout(Duration::from_secs(30)).unwrap().unwrap();
        });
        assert_eq!(value(&s, "k"), b"v");
    }

    /// A process that never finishes its write fails this process's writes
    /// after the timeout and, meanwhile, doesn't hold up a read.
    #[test]
    fn a_stuck_writer_times_out_writes_and_spares_reads() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(dir.path());
        s.lock_timeout = Duration::from_secs(3);
        s.put("seed", b"v").unwrap();
        let mut other = other_process(&s);
        let _held = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| tx.send(s.put("k", b"v")).unwrap());
            std::thread::sleep(Duration::from_millis(500));
            assert_eq!(value(&s, "seed"), b"v");
            assert!(
                rx.try_recv().is_err(),
                "the write gave up before the read finished"
            );
            let res = rx.recv_timeout(Duration::from_secs(30)).unwrap();
            assert!(matches!(res, Err(SecretError::StorageFailure)));
        });
    }

    #[test]
    fn keyring_is_not_opened_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        let target = dir.path().join("victim");
        std::fs::rename(keyring(dir.path()), &target).unwrap();
        std::os::unix::fs::symlink(&target, keyring(dir.path())).unwrap();
        let before = std::fs::read(&target).unwrap();
        assert!(matches!(
            s.put("k2", b"v"),
            Err(SecretError::StorageFailure)
        ));
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
        let pw = KeyringFileStore::password(&dir.path().join("pw")).unwrap();
        assert!(unlock(&keyring(dir.path()), &pw, false, LOCK_TIMEOUT).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), before);
    }

    #[test]
    fn a_keyring_with_another_schema_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.put("k", b"v").unwrap();
        other_process(&s)
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(s.get("k"), Err(SecretError::StorageFailure)));
        assert!(matches!(s.put("k", b"w"), Err(SecretError::StorageFailure)));
    }

    #[test]
    fn a_keyring_deleted_while_a_write_waits_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let creating = store(dir.path());
        creating.put("k", b"v").unwrap();
        let s = readonly(&creating);
        let mut other = other_process(&creating);
        let held = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let path = keyring(dir.path());
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| tx.send(s.put("n", b"v")).unwrap());
            assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
            std::fs::remove_file(&path).unwrap();
            drop(held);
            let res = rx.recv_timeout(Duration::from_secs(30)).unwrap();
            assert!(matches!(res, Err(SecretError::StoreNotFound)), "{res:?}");
        });
        assert!(!path.exists());
    }
}
