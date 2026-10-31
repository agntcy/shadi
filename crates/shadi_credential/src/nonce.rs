//! Single-use, task-scoped challenge nonces for the verifier.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use base64::Engine as _;

use crate::CredentialError;

/// Short enough that a leaked challenge goes stale fast, long enough for one round trip.
pub const NONCE_TTL_SECS: i64 = 60;

/// Hard bound on parked nonces; the TTL alone is bounded only by inbound rate.
pub const MAX_NONCES: usize = 4096;

/// What the listener puts in the challenge. `expires_at` is advisory for the
/// holder; the store's own record decides.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Challenge {
    pub nonce: String,
    pub aud: String,
    pub expires_at: i64,
}

struct Issued {
    task_id: String,
    expires_at: i64,
    seq: u64,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Issued>,
    next_seq: u64,
}

/// Issues and consumes nonces. Share one per listener.
#[non_exhaustive]
pub struct NonceStore {
    aud: String,
    inner: Mutex<Inner>,
}

// One message for unknown, expired and wrong-task: telling them apart would let
// a caller probe which nonces are live or which task owns them.
fn rejected() -> CredentialError {
    CredentialError::Refused("challenge nonce is not valid".into())
}

impl NonceStore {
    /// `aud` is this listener's own DID, the only audience it will accept.
    pub fn new(aud: impl Into<String>) -> Self {
        Self {
            aud: aud.into(),
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, CredentialError> {
        self.inner
            .lock()
            .map_err(|_| CredentialError::Storage("nonce store lock poisoned".into()))
    }

    pub fn issue(&self, task_id: &str, now: i64) -> Result<Challenge, CredentialError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|e| CredentialError::Storage(format!("nonce generation failed: {e}")))?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let expires_at = now.saturating_add(NONCE_TTL_SECS);

        let mut g = self.lock()?;
        g.map.retain(|_, v| v.expires_at > now);
        while g.map.len() >= MAX_NONCES {
            let Some(oldest) = g
                .map
                .iter()
                .min_by_key(|(_, v)| v.seq)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            g.map.remove(&oldest);
        }
        let seq = g.next_seq;
        g.next_seq += 1;
        g.map.insert(
            nonce.clone(),
            Issued {
                task_id: task_id.to_owned(),
                expires_at,
                seq,
            },
        );
        Ok(Challenge {
            nonce,
            aud: self.aud.clone(),
            expires_at,
        })
    }

    /// Returns the audience this listener recorded, so the caller checks the
    /// presentation against a value it issued rather than one the token supplied.
    /// A wrong-task attempt leaves the nonce live for its rightful task.
    pub fn consume(&self, nonce: &str, task_id: &str, now: i64) -> Result<String, CredentialError> {
        let mut g = self.lock()?;
        let entry = g.map.get(nonce).ok_or_else(rejected)?;
        if entry.expires_at <= now {
            g.map.remove(nonce);
            return Err(rejected());
        }
        if entry.task_id != task_id {
            return Err(rejected());
        }
        g.map.remove(nonce);
        Ok(self.aud.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn store() -> NonceStore {
        NonceStore::new("did:example:listener")
    }

    #[test]
    fn single_use() {
        let s = store();
        let c = s.issue("t1", 100).unwrap();
        assert_eq!(c.expires_at, 100 + NONCE_TTL_SECS);
        assert!(s.consume(&c.nonce, "t1", 101).is_ok());
        assert!(s.consume(&c.nonce, "t1", 101).is_err());
    }

    #[test]
    fn wrong_task_fails() {
        let s = store();
        let c = s.issue("t1", 100).unwrap();
        assert!(s.consume(&c.nonce, "t2", 101).is_err());
        assert!(s.consume(&c.nonce, "t1", 101).is_ok());
    }

    #[test]
    fn ttl_boundary() {
        let s = store();
        let a = s.issue("t", 100).unwrap();
        let b = s.issue("t", 100).unwrap();
        assert!(s.consume(&a.nonce, "t", 100 + NONCE_TTL_SECS - 1).is_ok());
        assert!(s.consume(&b.nonce, "t", 100 + NONCE_TTL_SECS).is_err());
    }

    #[test]
    fn returns_recorded_audience() {
        let s = store();
        let c = s.issue("t", 0).unwrap();
        assert_eq!(c.aud, "did:example:listener");
        assert_eq!(s.consume(&c.nonce, "t", 1).unwrap(), "did:example:listener");
    }

    #[test]
    fn unknown_fails_without_echoing_nonce() {
        let err = store().consume("nope-nonce", "t", 0).unwrap_err();
        assert!(!err.to_string().contains("nope-nonce"));
    }

    #[test]
    fn cap_evicts_oldest() {
        let s = store();
        let first = s.issue("t", 0).unwrap();
        let second = s.issue("t", 0).unwrap();
        for _ in 0..MAX_NONCES - 1 {
            s.issue("t", 0).unwrap();
        }
        assert_eq!(s.inner.lock().unwrap().map.len(), MAX_NONCES);
        assert!(s.consume(&first.nonce, "t", 1).is_err());
        assert!(s.consume(&second.nonce, "t", 1).is_ok());
    }

    #[test]
    fn expired_entries_reclaimed_on_issue() {
        let s = store();
        for _ in 0..MAX_NONCES {
            s.issue("t", 0).unwrap();
        }
        let now = NONCE_TTL_SECS + 1;
        let c = s.issue("t", now).unwrap();
        assert_eq!(s.inner.lock().unwrap().map.len(), 1);
        assert!(s.consume(&c.nonce, "t", now).is_ok());
    }

    #[test]
    fn nonces_differ_and_have_expected_shape() {
        let s = store();
        let a = s.issue("t", 0).unwrap();
        let b = s.issue("t", 0).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(a.nonce.len(), 22);
    }

    #[test]
    fn concurrent_consume_admits_one() {
        let s = store();
        let c = s.issue("t", 0).unwrap();
        let wins = AtomicUsize::new(0);
        std::thread::scope(|sc| {
            for _ in 0..16 {
                sc.spawn(|| {
                    if s.consume(&c.nonce, "t", 1).is_ok() {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 1);
    }
}
