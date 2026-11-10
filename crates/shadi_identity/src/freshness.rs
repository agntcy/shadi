// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Freshness-bound sealing for [`crate::did_proof`] payloads.
//!
//! `wrap_signed_message` alone signs `payload` but carries no nonce, timestamp,
//! or recipient: a captured envelope replays forever to any peer that trusts
//! the sender's DID. [`Sealed`] wraps the payload in a nonce + timestamp +
//! audience before it is signed, and [`ReplayCache`] remembers which nonces a
//! sender has already spent.

use std::collections::HashMap;
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
    pub fn seal(
        aud: Option<&str>,
        body: &[u8],
        principal_hint: Option<&str>,
    ) -> Result<Vec<u8>, IdentityError> {
        let sealed = Sealed {
            jti: Uuid::new_v4().to_string(),
            iat: now_unix(),
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
        let sealed: Sealed = serde_json::from_slice(payload)
            .map_err(|e| format!("not a sealed payload: {e}"))?;
        if replay.require_freshness && now_unix().abs_diff(sealed.iat) > FRESHNESS_WINDOW_SECS {
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
        if !replay.admit(sender_did, &sealed.jti) {
            return Err("sealed payload already delivered (replay)".to_string());
        }
        Ok((sealed.body, sealed.principal_hint))
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
    require_freshness: bool,
    senders: Mutex<HashMap<String, HashMap<String, u64>>>,
}

impl ReplayCache {
    pub fn new(max_senders: usize, per_sender_capacity: usize, require_freshness: bool) -> Self {
        Self {
            max_senders,
            per_sender_capacity,
            require_freshness,
            senders: Mutex::new(HashMap::new()),
        }
    }

    /// True iff `jti` from `sender_did` had not been seen before and there was
    /// room to remember it.
    fn admit(&self, sender_did: &str, jti: &str) -> bool {
        let now = now_unix();
        let cutoff = now.saturating_sub(REPLAY_RETENTION_SECS);
        let mut senders = self.senders.lock().unwrap_or_else(|e| e.into_inner());

        if !senders.contains_key(sender_did) {
            if senders.len() >= self.max_senders {
                // Only a sender whose entries have all expired is evictable —
                // one that is still live never makes room for another.
                senders.retain(|_, entries| {
                    entries.retain(|_, seen_at| *seen_at >= cutoff);
                    !entries.is_empty()
                });
                if senders.len() >= self.max_senders {
                    return false;
                }
            }
            senders.insert(sender_did.to_string(), HashMap::new());
        }

        let entries = senders.get_mut(sender_did).expect("just inserted or present");
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_sign_round_trips() {
        let id = AgentIdentity::generate().unwrap();
        let replay = ReplayCache::new(16, 16, true);
        let envelope = seal_and_sign(&id, Some("did:key:zDest"), b"hello", Some("hint")).unwrap();
        let (did, body, hint) = verify_and_open(&envelope, Some("did:key:zDest"), &replay).unwrap();
        assert_eq!(did, id.did());
        assert_eq!(body, b"hello");
        assert_eq!(hint.as_deref(), Some("hint"));
    }

    #[test]
    fn a_replayed_envelope_is_rejected_on_its_second_delivery() {
        let id = AgentIdentity::generate().unwrap();
        let replay = ReplayCache::new(16, 16, true);
        let envelope = seal_and_sign(&id, None, b"once", None).unwrap();
        verify_and_open(&envelope, None, &replay).expect("first delivery is admitted");
        let err = verify_and_open(&envelope, None, &replay).unwrap_err();
        assert!(err.contains("replay"), "{err}");
    }

    #[test]
    fn an_envelope_addressed_to_someone_else_is_rejected() {
        let id = AgentIdentity::generate().unwrap();
        let replay = ReplayCache::new(16, 16, true);
        let envelope = seal_and_sign(&id, Some("did:key:zBob"), b"for bob", None).unwrap();
        let err = verify_and_open(&envelope, Some("did:key:zCarol"), &replay).unwrap_err();
        assert!(err.contains("not this agent"), "{err}");
        // The genuine recipient still opens the same envelope fine.
        let replay = ReplayCache::new(16, 16, true);
        assert!(verify_and_open(&envelope, Some("did:key:zBob"), &replay).is_ok());
    }

    #[test]
    fn no_known_destination_or_self_did_is_not_an_error() {
        let id = AgentIdentity::generate().unwrap();
        let unaddressed = seal_and_sign(&id, None, b"x", None).unwrap();
        let replay = ReplayCache::new(16, 16, true);
        assert!(verify_and_open(&unaddressed, Some("did:key:zAnyone"), &replay).is_ok());

        let addressed = seal_and_sign(&id, Some("did:key:zBob"), b"x", None).unwrap();
        let replay = ReplayCache::new(16, 16, true);
        assert!(verify_and_open(&addressed, None, &replay).is_ok());
    }

    #[test]
    fn a_sender_flooding_its_own_capacity_does_not_block_another_sender() {
        let replay = ReplayCache::new(16, 2, true);
        assert!(replay.admit("alice", "a1"));
        assert!(replay.admit("alice", "a2"));
        assert!(
            !replay.admit("alice", "a3"),
            "alice's table is already full of live entries"
        );
        assert!(
            replay.admit("bob", "b1"),
            "bob has his own, untouched capacity"
        );
    }

    #[test]
    fn bounded_senders_fail_closed_under_load() {
        let replay = ReplayCache::new(2, 4, true);
        assert!(replay.admit("alice", "a1"));
        assert!(replay.admit("bob", "b1"));
        // Both tracked senders are still live: no room for a third.
        assert!(!replay.admit("carol", "c1"));
        // And a spent nonce from an existing sender is still a replay, not a
        // second admission that bumps capacity.
        assert!(!replay.admit("alice", "a1"));
    }
}
