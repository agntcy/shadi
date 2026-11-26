pub mod announce;
pub mod card;
pub mod coordinate;
pub mod delegate;
pub mod egress;
pub mod handoff;
pub mod list;
pub mod names;
pub mod record;
pub mod register;
pub mod request_invite;

/// Tests that set process-wide environment variables (`A2A_TLS_KEY`,
/// `SHADI_TMP_DIR`, `SHADI_DIRCTL_BINARY`, ...) hold this across the change
/// and the code that reads it, whichever module they are in.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Holds `test_env_lock` with `SHADI_SLIM_ADMISSION` and `SLIM_MEMBER_DIDS` set
/// to the given values (`None`: unset) and restores both on drop.
/// [`Self::closed`] is closed admission (the allow-list), [`Self::open`] is
/// open admission (`SHADI_SLIM_ADMISSION=open`, no allow-list).
#[cfg(test)]
pub(crate) struct AdmissionEnv {
    prev: [(&'static str, Option<std::ffi::OsString>); 2],
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl AdmissionEnv {
    pub(crate) fn set(admission: Option<&str>, members: Option<&str>) -> Self {
        let lock = test_env_lock();
        let prev = [
            (
                "SHADI_SLIM_ADMISSION",
                std::env::var_os("SHADI_SLIM_ADMISSION"),
            ),
            ("SLIM_MEMBER_DIDS", std::env::var_os("SLIM_MEMBER_DIDS")),
        ];
        for (key, value) in [
            ("SHADI_SLIM_ADMISSION", admission),
            ("SLIM_MEMBER_DIDS", members),
        ] {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        Self { prev, _lock: lock }
    }

    /// Closed admission: the switch unset, `SLIM_MEMBER_DIDS` = `members`.
    pub(crate) fn closed(members: &str) -> Self {
        Self::set(None, Some(members))
    }

    /// Open admission: `SHADI_SLIM_ADMISSION=open`, `SLIM_MEMBER_DIDS` unset.
    pub(crate) fn open() -> Self {
        Self::set(Some("open"), None)
    }
}

#[cfg(test)]
impl Drop for AdmissionEnv {
    fn drop(&mut self) {
        for (key, value) in self.prev.iter_mut() {
            match value.take() {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}
