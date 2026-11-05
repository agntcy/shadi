pub mod announce;
pub mod card;
pub mod coordinate;
pub mod delegate;
pub mod egress;
pub mod handoff;
pub mod list;
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
