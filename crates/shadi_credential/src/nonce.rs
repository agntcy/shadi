// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Single-use challenge nonces for the verifier, bound to the peer they were issued to.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use base64::Engine as _;

use crate::CredentialError;

/// Short enough that a leaked challenge goes stale fast, long enough for one round trip.
pub const NONCE_TTL_SECS: i64 = 60;

/// The longest retry-after a full store hands out: the wait until the earliest
/// live nonce expires, which is never more than a nonce's lifetime. Whatever
/// keeps a busy-parked task around must outlive this wait.
pub const MAX_RETRY_AFTER_SECS: i64 = NONCE_TTL_SECS;

/// Hard bound on parked nonces; the TTL alone is bounded only by inbound rate.
/// When full, a slot comes only from a DID holding a spare or from the caller's
/// own; a new DID is refused until one expires, never handed another's only one.
pub const MAX_NONCES: usize = 4096;

/// Hard bound on nonces live for one DID. Past it a peer's next issue replaces
/// its own oldest, so flooding from one DID never evicts another's.
pub const MAX_NONCES_PER_DID: usize = 2;

/// What the listener puts in the challenge. `expires_at` is advisory for the
/// holder; the store's own record decides.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct Challenge {
    pub nonce: String,
    pub aud: String,
    pub task_id: String,
    pub expires_at: i64,
    pub dcql_query: String,
}

struct Issued {
    task_id: String,
    did: String,
    expires_at: i64,
    seq: u64,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Issued>,
    next_seq: u64,
}

/// Issues and consumes nonces. Share one per listener.
pub struct NonceStore {
    aud: String,
    dcql_query: String,
    inner: Mutex<Inner>,
}

// One message for unknown, expired, wrong-task and wrong-peer: telling them
// apart would let a caller probe which nonces are live or who owns them.
fn rejected() -> CredentialError {
    CredentialError::NonceNotConsumable("challenge nonce is not valid".into())
}

// Names no DID or nonce, for the same reason as `rejected`. The wait is until
// the earliest live nonce expires, the soonest a slot can free on its own.
fn exhausted(map: &HashMap<String, Issued>, now: i64) -> CredentialError {
    let earliest = map.values().map(|v| v.expires_at).min().unwrap_or(now);
    let wait = earliest.saturating_sub(now).clamp(1, MAX_RETRY_AFTER_SECS);
    CredentialError::ChallengeCapacity {
        retry_after_secs: wait.unsigned_abs(),
    }
}

/// The nonce a full store gives up for `did`: the oldest held by a DID that
/// has a newer one, else `did`'s own oldest. `None` means every slot is some
/// other peer's only challenge.
fn backstop_victim(map: &HashMap<String, Issued>, did: &str) -> Option<String> {
    let mut held: HashMap<&str, usize> = HashMap::new();
    for v in map.values() {
        *held.entry(v.did.as_str()).or_default() += 1;
    }
    map.iter()
        .filter(|(_, v)| held[v.did.as_str()] > 1)
        .min_by_key(|(_, v)| v.seq)
        .or_else(|| {
            map.iter()
                .filter(|(_, v)| v.did == did)
                .min_by_key(|(_, v)| v.seq)
        })
        .map(|(k, _)| k.clone())
}

impl NonceStore {
    /// `aud` is this listener's own DID, the only audience it will accept.
    /// Every challenge is stamped with `aud` and `dcql_query`.
    pub fn new(aud: impl Into<String>, dcql_query: impl Into<String>) -> Self {
        Self {
            aud: aud.into(),
            dcql_query: dcql_query.into(),
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, CredentialError> {
        self.inner
            .lock()
            .map_err(|_| CredentialError::Storage("nonce store lock poisoned".into()))
    }

    /// `did` is the peer the challenge is for; only it can consume the nonce.
    /// A full store evicts per [`MAX_NONCES`]; a new DID that would cost another
    /// peer its only challenge gets [`CredentialError::ChallengeCapacity`] and
    /// the store is left as it was.
    pub fn issue(&self, task_id: &str, did: &str, now: i64) -> Result<Challenge, CredentialError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|e| CredentialError::Storage(format!("nonce generation failed: {e}")))?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let expires_at = now.saturating_add(NONCE_TTL_SECS);

        let mut g = self.lock()?;
        g.map.retain(|_, v| v.expires_at > now);

        // Evict this DID's own oldest nonce first, so a flood from one peer
        // never touches another peer's parked challenge.
        let mut mine: Vec<(String, u64)> = g
            .map
            .iter()
            .filter(|(_, v)| v.did == did)
            .map(|(k, v)| (k.clone(), v.seq))
            .collect();
        if mine.len() >= MAX_NONCES_PER_DID {
            mine.sort_by_key(|(_, seq)| *seq);
            for (k, _) in mine.iter().take(mine.len() + 1 - MAX_NONCES_PER_DID) {
                g.map.remove(k);
            }
        }

        // Backstop: the sweep and the per-DID evictions above leave the map at
        // most at the cap, so one eviction makes room.
        if g.map.len() >= MAX_NONCES {
            let victim = backstop_victim(&g.map, did).ok_or_else(|| exhausted(&g.map, now))?;
            g.map.remove(&victim);
        }
        let seq = g.next_seq;
        g.next_seq += 1;
        g.map.insert(
            nonce.clone(),
            Issued {
                task_id: task_id.to_owned(),
                did: did.to_owned(),
                expires_at,
                seq,
            },
        );
        Ok(Challenge {
            nonce,
            aud: self.aud.clone(),
            task_id: task_id.to_owned(),
            expires_at,
            dcql_query: self.dcql_query.clone(),
        })
    }

    /// Returns the audience this listener recorded, so the caller checks the
    /// presentation against a value it issued rather than one the token supplied.
    /// A wrong-task or wrong-peer attempt leaves the nonce live for its rightful holder.
    pub fn consume(
        &self,
        nonce: &str,
        task_id: &str,
        did: &str,
        now: i64,
    ) -> Result<&str, CredentialError> {
        let mut g = self.lock()?;
        let entry = g.map.get(nonce).ok_or_else(rejected)?;
        if entry.expires_at <= now {
            g.map.remove(nonce);
            return Err(rejected());
        }
        if entry.task_id != task_id || entry.did != did {
            return Err(rejected());
        }
        g.map.remove(nonce);
        Ok(&self.aud)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn store() -> NonceStore {
        NonceStore::new("did:example:listener", "{\"fake\":true}")
    }

    #[test]
    fn single_use() {
        let s = store();
        let c = s.issue("t1", "d", 100).unwrap();
        assert_eq!(c.expires_at, 100 + NONCE_TTL_SECS);
        assert!(s.consume(&c.nonce, "t1", "d", 101).is_ok());
        assert!(s.consume(&c.nonce, "t1", "d", 101).is_err());
    }

    #[test]
    fn wrong_task_fails() {
        let s = store();
        let c = s.issue("t1", "d", 100).unwrap();
        assert!(s.consume(&c.nonce, "t2", "d", 101).is_err());
        assert!(s.consume(&c.nonce, "t1", "d", 101).is_ok());
    }

    #[test]
    fn wrong_peer_fails_and_leaves_the_nonce_live() {
        let s = store();
        let c = s.issue("t1", "did:a", 100).unwrap();
        let wrong_peer = s.consume(&c.nonce, "t1", "did:b", 101).unwrap_err();
        let unknown = s.consume("nope", "t1", "did:a", 101).unwrap_err();
        let wrong_task = s.consume(&c.nonce, "t2", "did:a", 101).unwrap_err();
        assert_eq!(wrong_peer.to_string(), unknown.to_string());
        assert_eq!(wrong_peer.to_string(), wrong_task.to_string());
        assert!(s.consume(&c.nonce, "t1", "did:a", 101).is_ok());
    }

    #[test]
    fn ttl_boundary() {
        let s = store();
        let a = s.issue("t", "d", 100).unwrap();
        let b = s.issue("t", "d", 100).unwrap();
        assert!(s
            .consume(&a.nonce, "t", "d", 100 + NONCE_TTL_SECS - 1)
            .is_ok());
        assert!(s.consume(&b.nonce, "t", "d", 100 + NONCE_TTL_SECS).is_err());
    }

    #[test]
    fn returns_recorded_audience() {
        let s = store();
        let c = s.issue("t", "d", 0).unwrap();
        assert_eq!(c.aud, "did:example:listener");
        assert_eq!(
            s.consume(&c.nonce, "t", "d", 1).unwrap(),
            "did:example:listener"
        );
    }

    #[test]
    fn unknown_fails_without_echoing_nonce() {
        let err = store().consume("nope-nonce", "t", "d", 0).unwrap_err();
        assert!(!err.to_string().contains("nope-nonce"));
    }

    /// `n` DIDs `{prefix}0..`, one nonce each.
    fn one_each(s: &NonceStore, prefix: &str, n: usize, now: i64) -> Vec<Challenge> {
        (0..n)
            .map(|i| s.issue("t", &format!("{prefix}{i}"), now).unwrap())
            .collect()
    }

    fn snapshot(s: &NonceStore) -> (Vec<(String, String, u64)>, u64) {
        let g = s.inner.lock().unwrap();
        let mut entries: Vec<_> = g
            .map
            .iter()
            .map(|(k, v)| (k.clone(), v.did.clone(), v.seq))
            .collect();
        entries.sort();
        (entries, g.next_seq)
    }

    #[test]
    fn full_store_refuses_a_new_did_and_keeps_every_peer() {
        let s = store();
        let all = one_each(&s, "d", MAX_NONCES, 0);
        let err = s.issue("t", "newcomer", 0).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialError::ChallengeCapacity {
                    retry_after_secs: 60
                }
            ),
            "{err}"
        );
        assert_eq!(s.inner.lock().unwrap().map.len(), MAX_NONCES);
        assert!(s.consume(&all[0].nonce, "t", "d0", 1).is_ok());
    }

    fn retry_after(err: CredentialError) -> u64 {
        match err {
            CredentialError::ChallengeCapacity { retry_after_secs } => retry_after_secs,
            other => panic!("expected a capacity refusal, got {other}"),
        }
    }

    #[test]
    fn refusal_says_when_the_earliest_slot_frees() {
        let s = store();
        one_each(&s, "d", MAX_NONCES, 0);
        let err = s.issue("t", "newcomer", 10).unwrap_err();
        assert_eq!(
            err.to_string(),
            "challenge capacity exhausted, retry in 50s"
        );
        assert_eq!(retry_after(err), 50);
        let last = NONCE_TTL_SECS - 1;
        assert_eq!(retry_after(s.issue("t", "newcomer", last).unwrap_err()), 1);
    }

    #[test]
    fn refusal_wait_is_clamped_to_the_ttl() {
        let s = store();
        one_each(&s, "d", MAX_NONCES, 1_000);
        let skewed = s.issue("t", "newcomer", 0).unwrap_err();
        assert_eq!(retry_after(skewed), NONCE_TTL_SECS.unsigned_abs());
    }

    #[test]
    fn full_store_evicts_the_oldest_spare_nonce() {
        let s = store();
        let single = s.issue("t", "single", 0).unwrap();
        let m2_old = s.issue("t", "m2", 0).unwrap();
        let m1_old = s.issue("t", "m1", 0).unwrap();
        let m1_new = s.issue("t", "m1", 0).unwrap();
        let m2_new = s.issue("t", "m2", 0).unwrap();
        one_each(&s, "d", MAX_NONCES - 5, 0);

        let c = s.issue("t", "newcomer", 0).unwrap();
        assert_eq!(s.inner.lock().unwrap().map.len(), MAX_NONCES);
        assert!(s.consume(&m2_old.nonce, "t", "m2", 1).is_err());
        for (n, did) in [
            (&m2_new, "m2"),
            (&m1_old, "m1"),
            (&m1_new, "m1"),
            (&single, "single"),
            (&c, "newcomer"),
        ] {
            assert!(s.consume(&n.nonce, "t", did, 1).is_ok(), "{did}");
        }
    }

    #[test]
    fn full_store_lets_a_known_did_replace_its_own_nonce() {
        let s = store();
        let all = one_each(&s, "d", MAX_NONCES, 0);
        let again = s.issue("t", "d7", 0).unwrap();
        assert_eq!(s.inner.lock().unwrap().map.len(), MAX_NONCES);
        assert!(s.consume(&all[7].nonce, "t", "d7", 1).is_err());
        assert!(s.consume(&again.nonce, "t", "d7", 1).is_ok());
        assert!(s.consume(&all[0].nonce, "t", "d0", 1).is_ok());
    }

    #[test]
    fn refusal_leaves_the_store_unchanged_until_a_slot_expires() {
        let s = store();
        s.issue("t", "early", 0).unwrap();
        one_each(&s, "d", MAX_NONCES - 1, 10);
        let before = snapshot(&s);
        let err = s.issue("t", "newcomer", 5).unwrap_err();
        assert_eq!(retry_after(err), 55);
        assert_eq!(snapshot(&s), before);

        let now = NONCE_TTL_SECS + 1;
        let c = s.issue("t", "newcomer", now).unwrap();
        assert_eq!(s.inner.lock().unwrap().map.len(), MAX_NONCES);
        assert!(s.consume(&c.nonce, "t", "newcomer", now).is_ok());
    }

    #[test]
    fn refusal_names_neither_did_nor_nonce() {
        let s = store();
        let all = one_each(&s, "d", MAX_NONCES, 0);
        let msg = s
            .issue("t", "did:key:zNewcomer", 0)
            .unwrap_err()
            .to_string();
        assert!(!msg.contains("zNewcomer"), "{msg}");
        assert!(all.iter().all(|c| !msg.contains(&c.nonce)), "{msg}");
    }

    #[test]
    fn expired_slots_admit_a_new_did() {
        let s = store();
        one_each(&s, "d", MAX_NONCES, 0);
        let now = NONCE_TTL_SECS + 1;
        let c = s.issue("t", "d", now).unwrap();
        assert_eq!(s.inner.lock().unwrap().map.len(), 1);
        assert!(s.consume(&c.nonce, "t", "d", now).is_ok());
    }

    #[test]
    fn per_did_flood_does_not_evict_other_peers() {
        let s = store();
        let victim = s.issue("t", "victim", 0).unwrap();
        // The attacker mints far more nonces than its own cap allows.
        for _ in 0..MAX_NONCES_PER_DID * 10 {
            s.issue("t", "attacker", 0).unwrap();
        }
        assert!(s.consume(&victim.nonce, "t", "victim", 1).is_ok());
        let live_for_attacker = s
            .inner
            .lock()
            .unwrap()
            .map
            .values()
            .filter(|v| v.did == "attacker")
            .count();
        assert_eq!(live_for_attacker, MAX_NONCES_PER_DID);
    }

    #[test]
    fn nonces_differ_and_have_expected_shape() {
        let s = store();
        let a = s.issue("t", "d", 0).unwrap();
        let b = s.issue("t", "d", 0).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(a.nonce.len(), 22);
    }

    #[test]
    fn concurrent_consume_admits_one() {
        let s = store();
        let c = s.issue("t", "d", 0).unwrap();
        let wins = AtomicUsize::new(0);
        std::thread::scope(|sc| {
            for _ in 0..16 {
                sc.spawn(|| {
                    if s.consume(&c.nonce, "t", "d", 1).is_ok() {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn challenge_round_trips_through_json() {
        let c = store().issue("t1", "d", 100).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"task_id\"") && json.contains("\"dcql_query\""));
        assert_eq!(serde_json::from_str::<Challenge>(&json).unwrap(), c);
    }

    #[test]
    fn challenge_carries_task_and_query() {
        let c = store().issue("t1", "d", 100).unwrap();
        assert_eq!(c.task_id, "t1");
        assert_eq!(c.dcql_query, "{\"fake\":true}");
    }
}
