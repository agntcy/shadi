// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Freshness-bound sealing for [`crate::did_proof`] payloads.
//!
//! `wrap_signed_message` alone signs `payload` but carries no nonce, timestamp,
//! or recipient: a captured envelope replays forever to any peer that trusts
//! the sender's DID. [`Sealed`] wraps the payload in a nonce + timestamp +
//! audience before it is signed, and [`ReplayCache`] remembers which nonces a
//! sender has already spent.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::did_proof::{unwrap_signed_message, wrap_signed_message};
use crate::{AgentIdentity, IdentityError};

/// Clock-skew tolerance either side of `iat`, in seconds.
const FRESHNESS_WINDOW_SECS: u64 = 300;

/// How long a replay-cache entry is kept before it is safe to prune: beyond
/// this, the freshness check on `iat` rejects a replay on its own.
const REPLAY_RETENTION_SECS: u64 = FRESHNESS_WINDOW_SECS * 2;

/// Base64 the JSON carries `body` as, so an arbitrary-bytes payload (not just
/// UTF-8 text) still round-trips through `serde_json`.
mod body_b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(body: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(body))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// A payload bound to a one-time nonce, a timestamp, and (optionally) a
/// recipient DID — the bytes to sign, via [`wrap_signed_message`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    jti: String,
    iat: u64,
    aud: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal_hint: Option<String>,
    #[serde(with = "body_b64")]
    body: Vec<u8>,
}

impl Sealed {
    /// Seal `body` for one delivery: a fresh `jti`, the current time, and
    /// `aud` when the destination DID is known.
    ///
    /// `aud: None` does not bind the destination at all — [`Sealed::open`]
    /// waives the audience check entirely for it, same as for a receiver that
    /// does not know its own DID. `coordinate` and `handoff` resolve a peer's
    /// `did:key` when it is a locally registered agent, and `request_invite`
    /// takes the owner's DID as an explicit flag — but none of them can
    /// require one: a remote or unregistered peer, or a caller who simply
    /// doesn't pass `--owner-did`, still has to go through unaddressed rather
    /// than fail outright.
    pub fn seal(
        aud: Option<&str>,
        body: &[u8],
        principal_hint: Option<&str>,
    ) -> Result<Vec<u8>, IdentityError> {
        let sealed = Sealed {
            jti: Uuid::new_v4().to_string(),
            iat: now_unix().map_err(IdentityError::Proof)?,
            aud: aud.unwrap_or_default().to_string(),
            principal_hint: principal_hint.map(str::to_string),
            body: body.to_vec(),
        };
        serde_json::to_vec(&sealed)
            .map_err(|e| IdentityError::Proof(format!("failed to seal payload: {e}")))
    }

    /// Open a sealed payload signed by `sender_did`: checks freshness, the
    /// audience (only when both sides know one), and rejects a replay the
    /// same sender already spent.
    pub fn open(
        payload: &[u8],
        self_did: Option<&str>,
        sender_did: &str,
        replay: &ReplayCache,
    ) -> Result<(Vec<u8>, Option<String>), String> {
        let (sealed, now) = Self::validate(payload, self_did)?;
        if !replay.commit(sender_did, &sealed.jti, now) {
            return Err("sealed payload already delivered (replay)".to_string());
        }
        Ok((sealed.body, sealed.principal_hint))
    }

    /// Like [`Self::open`], but does not spend the replay slot: a caller
    /// that can cheaply refuse most deliveries before they are worth
    /// remembering (e.g. one naming a resource it doesn't hold) calls
    /// [`Opened::confirm`] only once it has decided this one is. A true
    /// replay — a `jti` already committed by an earlier confirm — is still
    /// rejected here, before any of that caller's own work runs.
    pub fn open_deferred(
        payload: &[u8],
        self_did: Option<&str>,
        sender_did: &str,
        replay: &ReplayCache,
    ) -> Result<Opened, String> {
        let (sealed, now) = Self::validate(payload, self_did)?;
        if replay.contains(sender_did, &sealed.jti) {
            return Err("sealed payload already delivered (replay)".to_string());
        }
        Ok(Opened {
            sender_did: sender_did.to_string(),
            jti: sealed.jti,
            now,
            body: sealed.body,
            principal_hint: sealed.principal_hint,
        })
    }

    /// Parse, check freshness, and check the audience — everything [`open`]
    /// and [`open_deferred`] share, short of touching the replay cache.
    fn validate(payload: &[u8], self_did: Option<&str>) -> Result<(Sealed, u64), String> {
        let sealed: Sealed = serde_json::from_slice(payload)
            .map_err(|e| format!("not a sealed payload: {e}"))?;
        let now = now_unix()?;
        if now.abs_diff(sealed.iat) > FRESHNESS_WINDOW_SECS {
            return Err("sealed payload is outside the freshness window".to_string());
        }
        if let Some(self_did) = self_did {
            if !sealed.aud.is_empty() && sealed.aud != self_did {
                return Err(format!(
                    "sealed payload is addressed to {}, not this agent ({self_did})",
                    sealed.aud
                ));
            }
        }
        Ok((sealed, now))
    }
}

/// A sealed payload that passed freshness and audience checks, with its
/// replay slot not yet spent. A caller that decided a delivery is worth
/// acting on calls [`Self::confirm`] to spend that slot; one that refuses
/// the delivery for its own reasons can just drop this, at no cost to the
/// shared [`ReplayCache`].
pub struct Opened {
    sender_did: String,
    jti: String,
    now: u64,
    body: Vec<u8>,
    principal_hint: Option<String>,
}

impl Opened {
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn principal_hint(&self) -> Option<&str> {
        self.principal_hint.as_deref()
    }

    /// Spend this delivery's replay slot. `Err` if it was already spent —
    /// a concurrent delivery of the same envelope won this race, or the
    /// cache has no room left to remember it.
    pub fn confirm(self, replay: &ReplayCache) -> Result<(Vec<u8>, Option<String>), String> {
        if !replay.commit(&self.sender_did, &self.jti, self.now) {
            return Err("sealed payload already delivered (replay)".to_string());
        }
        Ok((self.body, self.principal_hint))
    }
}

/// Remembers, per sender DID, which `jti`s have already been delivered.
///
/// Bounded and fail-closed: a sender whose table is already full of live
/// entries is refused rather than silently evicting one to make room, and
/// the same holds for the number of distinct senders tracked. A plain LRU
/// would instead evict a still-live entry under flood, reopening the replay
/// window it exists to close.
pub struct ReplayCache {
    max_senders: usize,
    per_sender_capacity: usize,
    senders: Mutex<SenderTable>,
}

/// Senders, indexed two ways: by DID for lookup, and by last-seen time so the
/// longest-idle (and therefore only evictable) sender is found in `O(log n)`
/// instead of sweeping every tracked sender's entries to check.
#[derive(Default)]
struct SenderTable {
    by_did: HashMap<String, (u64, HashMap<String, u64>)>,
    by_last_seen: BTreeMap<u64, HashSet<String>>,
}

impl SenderTable {
    fn insert_new(&mut self, sender_did: String, now: u64) {
        self.by_last_seen
            .entry(now)
            .or_default()
            .insert(sender_did.clone());
        self.by_did.insert(sender_did, (now, HashMap::new()));
    }

    /// Records that `sender_did` was just seen at `now`, moving it in the
    /// last-seen index so it is not mistaken for idle.
    fn touch(&mut self, sender_did: &str, now: u64) {
        let old_last_seen = match self.by_did.get(sender_did) {
            Some((ts, _)) => *ts,
            None => return,
        };
        if now <= old_last_seen {
            return;
        }
        self.unindex_last_seen(sender_did, old_last_seen);
        self.by_last_seen
            .entry(now)
            .or_default()
            .insert(sender_did.to_string());
        if let Some(entry) = self.by_did.get_mut(sender_did) {
            entry.0 = now;
        }
    }

    fn remove(&mut self, sender_did: &str) {
        if let Some((last_seen, _)) = self.by_did.remove(sender_did) {
            self.unindex_last_seen(sender_did, last_seen);
        }
    }

    fn unindex_last_seen(&mut self, sender_did: &str, last_seen: u64) {
        if let Some(bucket) = self.by_last_seen.get_mut(&last_seen) {
            bucket.remove(sender_did);
            if bucket.is_empty() {
                self.by_last_seen.remove(&last_seen);
            }
        }
    }

    /// A sender last seen before `cutoff`: every entry it ever recorded is
    /// expired, since none can postdate its own last-seen time.
    fn idle_before(&self, cutoff: u64) -> Option<String> {
        self.by_last_seen
            .range(..cutoff)
            .next()
            .and_then(|(_, bucket)| bucket.iter().next().cloned())
    }
}

impl ReplayCache {
    pub fn new(max_senders: usize, per_sender_capacity: usize) -> Self {
        Self {
            max_senders,
            per_sender_capacity,
            senders: Mutex::new(SenderTable::default()),
        }
    }

    /// True iff `jti` from `sender_did` was already committed. Read-only — it
    /// does not touch the sender/eviction bookkeeping, so a caller can check
    /// before doing expensive work without that check itself costing
    /// anything against the bounded sender table.
    fn contains(&self, sender_did: &str, jti: &str) -> bool {
        let table = self.senders.lock().unwrap_or_else(|e| e.into_inner());
        table
            .by_did
            .get(sender_did)
            .is_some_and(|(_, entries)| entries.contains_key(jti))
    }

    /// True iff `jti` from `sender_did` had not been seen before and there was
    /// room to remember it. `now` is the caller's already-validated clock
    /// reading, so a clock fault is one error at [`Sealed::open`]'s boundary
    /// rather than a second, silent one here.
    fn commit(&self, sender_did: &str, jti: &str, now: u64) -> bool {
        let cutoff = now.saturating_sub(REPLAY_RETENTION_SECS);
        let mut table = self.senders.lock().unwrap_or_else(|e| e.into_inner());

        if table.by_did.contains_key(sender_did) {
            table.touch(sender_did, now);
        } else {
            if table.by_did.len() >= self.max_senders {
                // Only a sender whose entries have all expired is evictable —
                // one that is still live never makes room for another. Found
                // via the last-seen index, not by scanning every sender.
                match table.idle_before(cutoff) {
                    Some(idle) => table.remove(&idle),
                    None => return false,
                }
            }
            table.insert_new(sender_did.to_string(), now);
        }

        let (_, entries) = table.by_did.get_mut(sender_did).expect("just inserted or present");
        entries.retain(|_, seen_at| *seen_at >= cutoff);
        if entries.contains_key(jti) {
            return false;
        }
        if entries.len() >= self.per_sender_capacity {
            return false;
        }
        entries.insert(jti.to_string(), now);
        true
    }
}

/// The current time, or an error — never a fallback timestamp. `0` would
/// make every future `iat` look impossibly old and every cache entry look
/// permanently fresh, so a clock fault must refuse the message, not silently
/// wedge the cache open or closed.
fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock is before the Unix epoch: {e}"))
}

/// Sign `body` for `identity`, sealed with a nonce, timestamp, and (when
/// known) the recipient DID — the only path outbound SHADI envelopes should
/// use from here on.
pub fn seal_and_sign(
    identity: &AgentIdentity,
    aud: Option<&str>,
    body: &[u8],
    hint: Option<&str>,
) -> Result<Vec<u8>, IdentityError> {
    let sealed = Sealed::seal(aud, body, hint)?;
    wrap_signed_message(identity, &sealed)
}

/// Verify a signed envelope and open its sealed body: the DID proof, then
/// freshness, audience, and replay. The only path inbound SHADI envelopes
/// should use from here on.
pub fn verify_and_open(
    envelope: &[u8],
    self_did: Option<&str>,
    replay: &ReplayCache,
) -> Result<(String, Vec<u8>, Option<String>), String> {
    let verified = unwrap_signed_message(envelope).map_err(|e| e.to_string())?;
    let (body, hint) = Sealed::open(&verified.payload, self_did, &verified.did, replay)?;
    Ok((verified.did, body, hint))
}

/// Like [`verify_and_open`], but leaves the replay slot unspent — see
/// [`Sealed::open_deferred`]. Returns the signer's DID alongside the
/// [`Opened`] ticket, since a deferring caller typically still needs it (to
/// check a binding inside the body, for example) before deciding whether to
/// confirm.
pub fn verify_and_open_deferred(
    envelope: &[u8],
    self_did: Option<&str>,
    replay: &ReplayCache,
) -> Result<(String, Opened), String> {
    let verified = unwrap_signed_message(envelope).map_err(|e| e.to_string())?;
    let opened = Sealed::open_deferred(&verified.payload, self_did, &verified.did, replay)?;
    Ok((verified.did, opened))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_sign_round_trips() {
        let id = AgentIdentity::generate().unwrap();
        let replay = ReplayCache::new(16, 16);
        let envelope = seal_and_sign(&id, Some("did:key:zDest"), b"hello", Some("hint")).unwrap();
        let (did, body, hint) = verify_and_open(&envelope, Some("did:key:zDest"), &replay).unwrap();
        assert_eq!(did, id.did());
        assert_eq!(body, b"hello");
        assert_eq!(hint.as_deref(), Some("hint"));
    }

    #[test]
    fn a_replayed_envelope_is_rejected_on_its_second_delivery() {
        let id = AgentIdentity::generate().unwrap();
        let replay = ReplayCache::new(16, 16);
        let envelope = seal_and_sign(&id, None, b"once", None).unwrap();
        verify_and_open(&envelope, None, &replay).expect("first delivery is admitted");
        let err = verify_and_open(&envelope, None, &replay).unwrap_err();
        assert!(err.contains("replay"), "{err}");
    }

    #[test]
    fn an_envelope_addressed_to_someone_else_is_rejected() {
        let id = AgentIdentity::generate().unwrap();
        let replay = ReplayCache::new(16, 16);
        let envelope = seal_and_sign(&id, Some("did:key:zBob"), b"for bob", None).unwrap();
        let err = verify_and_open(&envelope, Some("did:key:zCarol"), &replay).unwrap_err();
        assert!(err.contains("not this agent"), "{err}");
        // The genuine recipient still opens the same envelope fine.
        let replay = ReplayCache::new(16, 16);
        assert!(verify_and_open(&envelope, Some("did:key:zBob"), &replay).is_ok());
    }

    #[test]
    fn no_known_destination_or_self_did_is_not_an_error() {
        let id = AgentIdentity::generate().unwrap();
        let unaddressed = seal_and_sign(&id, None, b"x", None).unwrap();
        let replay = ReplayCache::new(16, 16);
        assert!(verify_and_open(&unaddressed, Some("did:key:zAnyone"), &replay).is_ok());

        let addressed = seal_and_sign(&id, Some("did:key:zBob"), b"x", None).unwrap();
        let replay = ReplayCache::new(16, 16);
        assert!(verify_and_open(&addressed, None, &replay).is_ok());
    }

    #[test]
    fn an_envelope_from_the_future_within_the_window_is_accepted() {
        // Clock skew is symmetric: a sender whose clock runs up to
        // FRESHNESS_WINDOW_SECS ahead is not penalized for it.
        let id = AgentIdentity::generate().unwrap();
        let replay = ReplayCache::new(16, 16);
        let sealed = Sealed {
            jti: Uuid::new_v4().to_string(),
            iat: now_unix().unwrap() + FRESHNESS_WINDOW_SECS,
            aud: String::new(),
            principal_hint: None,
            body: b"x".to_vec(),
        };
        let envelope =
            wrap_signed_message(&id, &serde_json::to_vec(&sealed).unwrap()).unwrap();
        assert!(verify_and_open(&envelope, None, &replay).is_ok());
    }

    #[test]
    fn a_sender_flooding_its_own_capacity_does_not_block_another_sender() {
        let replay = ReplayCache::new(16, 2);
        let now = now_unix().unwrap();
        assert!(replay.commit("alice", "a1", now));
        assert!(replay.commit("alice", "a2", now));
        assert!(
            !replay.commit("alice", "a3", now),
            "alice's table is already full of live entries"
        );
        assert!(
            replay.commit("bob", "b1", now),
            "bob has his own, untouched capacity"
        );
    }

    #[test]
    fn bounded_senders_fail_closed_under_load() {
        let replay = ReplayCache::new(2, 4);
        let now = now_unix().unwrap();
        assert!(replay.commit("alice", "a1", now));
        assert!(replay.commit("bob", "b1", now));
        // Both tracked senders are still live: no room for a third.
        assert!(!replay.commit("carol", "c1", now));
        // And a spent nonce from an existing sender is still a replay, not a
        // second admission that bumps capacity.
        assert!(!replay.commit("alice", "a1", now));
    }

    #[test]
    fn an_idle_sender_is_evicted_to_make_room_for_a_new_one() {
        let replay = ReplayCache::new(1, 4);
        let start = now_unix().unwrap();
        assert!(replay.commit("alice", "a1", start));
        // Carol arrives once alice's entries are old enough to be fully
        // expired: alice is idle, not merely full, so she makes room.
        let later = start + REPLAY_RETENTION_SECS + 1;
        assert!(replay.commit("carol", "c1", later));
    }
}
