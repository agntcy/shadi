// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Replay and misdelivery protection, carried **inside** the signed payload.
//!
//! `SHADI-DID-PROOF/1` signs `DOMAIN \0 did \0 payload` with no nonce,
//! timestamp or recipient, so on its own a captured envelope is valid forever
//! and replays to any peer that admits the sender's DID.
//!
//! The fix rides in the payload rather than in a new envelope field: the
//! envelope already signs `payload`, so `{jti, iat, aud, principal_hint}`
//! placed there are tamper-proof for free, with no change to `did_proof.rs`
//! and no version negotiation across the transports.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How far `iat` may sit from local time, in either direction. Wide enough to
/// absorb ordinary clock skew between hosts, so no separate skew knob.
pub const FRESHNESS_WINDOW: Duration = Duration::from_secs(300);

/// The application payload plus the fields that make it single-use,
/// time-bounded and addressed to one peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Sealed {
    /// Unique per message; the replay key.
    pub jti: String,
    /// Unix seconds at send.
    pub iat: u64,
    /// The recipient's `did:key`. Binds the message to one peer, so an
    /// envelope captured en route to Bob is rejected by Carol.
    pub aud: String,
    /// Untrusted: selects whose key list a receiver resolves against, and is
    /// believed only once that lookup succeeds. `None` is a normal case, not
    /// an error — the receiver then has no principal to resolve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_hint: Option<String>,
    /// What the adapter will see. A `String` because A2A text parts are.
    pub body: String,
}

impl Sealed {
    /// Wrap `body` for `aud`, carrying `principal_hint`. Seal **before**
    /// signing — freshness fields outside the signature would be trivially
    /// strippable.
    pub fn seal(
        aud: &str,
        body: &str,
        principal_hint: Option<&str>,
    ) -> Result<Vec<u8>, crate::IdentityError> {
        serde_json::to_vec(&Self {
            jti: random_jti(),
            iat: now_secs(),
            aud: aud.to_string(),
            principal_hint: principal_hint.map(str::to_string),
            body: body.to_string(),
        })
        .map_err(|e| crate::IdentityError::Proof(format!("seal: {e}")))
    }

    /// Validate and return `(body, principal_hint)`.
    ///
    /// `payload` must already have been envelope-verified: this checks
    /// freshness, not authenticity, and does not interpret the hint at all —
    /// it only hands it to the caller. `self_did = None` skips the audience
    /// check, for a caller that does not know its own DID. `Err` is a
    /// rejection reason fit for a task status message.
    pub fn open(
        payload: &[u8],
        self_did: Option<&str>,
        replay: &ReplayCache,
    ) -> Result<(Vec<u8>, Option<String>), String> {
        let sealed: Self = match serde_json::from_slice(payload) {
            Ok(sealed) => sealed,
            // A sender that predates sealing, sending a bare body. Accepting is
            // a replay hole; rejecting breaks rolling upgrades. Which one is
            // right is a deployment question, so it is a policy flag — and it
            // must be turned on once every sender seals, or this module is
            // decorative.
            Err(_) if !replay.require_freshness => return Ok((payload.to_vec(), None)),
            Err(e) => return Err(format!("message carries no freshness fields ({e})")),
        };

        if let Some(me) = self_did {
            if sealed.aud != me {
                return Err(format!(
                    "message addressed to {}, not to this agent",
                    sealed.aud
                ));
            }
        }

        let age = sealed.iat.abs_diff(now_secs());
        if age > FRESHNESS_WINDOW.as_secs() {
            return Err(format!(
                "message age {age}s is outside the freshness window"
            ));
        }

        // Last, so a stale or misaddressed message does not consume a jti slot.
        if !replay.insert(&sealed.jti) {
            return Err("replayed message (jti already seen)".to_string());
        }

        Ok((sealed.body.into_bytes(), sealed.principal_hint))
    }
}

/// Seen-`jti` set with time-based eviction.
///
/// A `HashMap` pruned on insert rather than an `lru` dependency: entries are
/// only useful for [`FRESHNESS_WINDOW`], so bounded growth comes for free and
/// no new crate enters the trust path.
///
/// Per-process, so a restart reopens one [`FRESHNESS_WINDOW`] of replay.
pub struct ReplayCache {
    seen: Mutex<HashMap<String, Instant>>,
    capacity: usize,
    /// Reject payloads that carry no freshness fields at all. Off by default
    /// so a receiver can be upgraded before its senders.
    require_freshness: bool,
}

impl ReplayCache {
    pub fn new(capacity: usize, require_freshness: bool) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
            require_freshness,
        }
    }

    /// `true` if this `jti` had not been seen.
    fn insert(&self, jti: &str) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.len() >= self.capacity {
            seen.retain(|_, at| at.elapsed() < FRESHNESS_WINDOW);
        }
        // Still full after pruning: every entry is live, so refuse rather than
        // grow without bound or evict a jti that could then be replayed.
        if seen.len() >= self.capacity && !seen.contains_key(jti) {
            tracing::warn!(
                capacity = self.capacity,
                "replay cache is full of live entries; rejecting"
            );
            return false;
        }
        seen.insert(jti.to_string(), Instant::now()).is_none()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    // A failure here would make every jti identical, which reads as a replay.
    // Fall back to the clock so the message is rejected, never silently unique.
    if getrandom::fill(&mut bytes).is_err() {
        bytes[..8].copy_from_slice(&now_secs().to_be_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "did:key:zBob";

    fn cache() -> ReplayCache {
        ReplayCache::new(64, true)
    }

    fn open(sealed: &Sealed, replay: &ReplayCache) -> Result<Vec<u8>, String> {
        Sealed::open(&serde_json::to_vec(sealed).unwrap(), Some(ME), replay).map(|(body, _)| body)
    }

    fn fresh() -> Sealed {
        Sealed {
            jti: random_jti(),
            iat: now_secs(),
            aud: ME.to_string(),
            principal_hint: None,
            body: "review PR 412".to_string(),
        }
    }

    #[test]
    fn seals_and_opens_round_trip() {
        let replay = cache();
        let payload = Sealed::seal(ME, "review PR 412", Some("alice")).unwrap();
        let (body, hint) = Sealed::open(&payload, Some(ME), &replay).unwrap();
        assert_eq!(body, b"review PR 412");
        assert_eq!(hint.as_deref(), Some("alice"));
    }

    /// sealing before signing puts the freshness fields under
    /// the envelope signature, so flipping one bit anywhere in
    /// the sealed payload must break verification.
    #[test]
    fn a_tampered_seal_fails_envelope_verification() {
        let sender = crate::AgentIdentity::generate().unwrap();
        let sealed = Sealed::seal(ME, "task", Some("alice")).unwrap();
        let envelope = crate::did_proof::wrap_signed_message(&sender, &sealed).unwrap();

        let mut tampered = envelope.clone();
        let payload_start = tampered.len() - sealed.len();
        tampered[payload_start] ^= 0x01;
        assert!(crate::did_proof::unwrap_signed_message(&tampered).is_err());

        // The untouched envelope still verifies, and open() sees exactly what
        // was sealed.
        let verified = crate::did_proof::unwrap_signed_message(&envelope).unwrap();
        let (body, hint) = Sealed::open(&verified.payload, Some(ME), &cache()).unwrap();
        assert_eq!(body, b"task");
        assert_eq!(hint.as_deref(), Some("alice"));
    }

    /// A missing hint is a normal case, not an error: the receiver simply has
    /// no principal to resolve.
    #[test]
    fn a_payload_without_a_principal_hint_still_opens() {
        let replay = cache();
        let legacy = serde_json::json!({
            "jti": random_jti(), "iat": now_secs(), "aud": ME, "body": "task"
        });
        let (body, hint) =
            Sealed::open(&serde_json::to_vec(&legacy).unwrap(), Some(ME), &replay).unwrap();
        assert_eq!(body, b"task");
        assert!(hint.is_none());
        // And the field is omitted on the way out, not serialised as null.
        let sealed = Sealed::seal(ME, "task", None).unwrap();
        assert!(!String::from_utf8(sealed)
            .unwrap()
            .contains("principal_hint"));
    }

    #[test]
    fn verbatim_replay_is_rejected_on_second_delivery() {
        let replay = cache();
        let payload = Sealed::seal(ME, "task", None).unwrap();
        assert!(Sealed::open(&payload, Some(ME), &replay).is_ok());
        let err = Sealed::open(&payload, Some(ME), &replay).unwrap_err();
        assert!(err.contains("replayed"), "{err}");
    }

    /// Same body, fresh `jti`: a legitimate retry, not a replay.
    #[test]
    fn a_distinct_jti_with_the_same_body_is_accepted() {
        let replay = cache();
        let seal = || Sealed::seal(ME, "task", None).unwrap();
        assert!(Sealed::open(&seal(), Some(ME), &replay).is_ok());
        assert!(Sealed::open(&seal(), Some(ME), &replay).is_ok());
    }

    #[test]
    fn a_message_for_another_peer_is_rejected() {
        let replay = cache();
        let sealed = Sealed {
            aud: "did:key:zCarol".to_string(),
            ..fresh()
        };
        let err = open(&sealed, &replay).unwrap_err();
        assert!(err.contains("addressed to did:key:zCarol"), "{err}");
    }

    #[test]
    fn stale_and_future_dated_messages_are_rejected() {
        let replay = cache();
        let window = FRESHNESS_WINDOW.as_secs();
        for iat in [now_secs() - window - 1, now_secs() + window + 1] {
            let err = open(&Sealed { iat, ..fresh() }, &replay).unwrap_err();
            assert!(err.contains("freshness window"), "{err}");
        }
        // The boundary itself is inside the window.
        assert!(open(
            &Sealed {
                iat: now_secs() - window,
                ..fresh()
            },
            &replay
        )
        .is_ok());
    }

    /// A rejected message must not burn its jti, or an attacker could
    /// pre-poison the cache with jtis a legitimate sender will later use.
    #[test]
    fn a_rejected_message_does_not_consume_its_jti() {
        let replay = cache();
        let misaddressed = Sealed {
            aud: "did:key:zCarol".to_string(),
            ..fresh()
        };
        assert!(open(&misaddressed, &replay).is_err());
        let redirected = Sealed {
            aud: ME.to_string(),
            ..misaddressed
        };
        assert!(open(&redirected, &replay).is_ok(), "jti was consumed");
    }

    #[test]
    fn unsealed_payloads_follow_the_require_freshness_flag() {
        let lenient = ReplayCache::new(8, false);
        assert_eq!(
            Sealed::open(b"bare legacy body", Some(ME), &lenient).unwrap(),
            (b"bare legacy body".to_vec(), None)
        );
        let strict = cache();
        assert!(Sealed::open(b"bare legacy body", Some(ME), &strict).is_err());
    }

    #[test]
    fn audience_check_is_skipped_when_the_caller_has_no_did() {
        let replay = cache();
        let payload = serde_json::to_vec(&fresh()).unwrap();
        assert!(Sealed::open(&payload, None, &replay).is_ok());
    }

    #[test]
    fn a_full_cache_of_live_entries_rejects_rather_than_evicting() {
        let replay = ReplayCache::new(2, true);
        assert!(replay.insert("a"));
        assert!(replay.insert("b"));
        assert!(!replay.insert("c"), "must not evict a live jti");
        assert!(!replay.insert("a"), "known jti stays known");
    }
}
