// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Who a signing key belongs to, according to an authority outside the message.
//!
//! A binding certificate proves some human key vouched for an agent DID; it does
//! not say whose key that is. An anchor answers that, and the two together are
//! what let a receiver name the person behind a peer.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;

use crate::ssh::all_ed25519_in_authorized_keys;
use crate::{parse_did_key, IdentityError};

/// Whether an authority vouches for a key under a principal.
pub trait TrustAnchor {
    /// `Ok(false)` is an answer: not vouched for. `Err` means the authority
    /// could not be reached, which a caller must read as "cannot say" and never
    /// as "no" — otherwise an outage silently becomes a denial.
    fn vouches_for(&self, principal: &str, key: &VerifyingKey) -> Result<bool, IdentityError>;

    fn authority(&self) -> &str;
}

/// Fetches an `authorized_keys`-style listing from a URL.
///
/// `Ok("")` means the account publishes no usable key, a 404 included — an
/// answer, not an outage. `Err` is an outage.
pub type KeyListFetcher = Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// An authority that certifies by publishing its members' keys.
pub struct PublishedKeysAnchor {
    authority: String,
    keys_url_template: String,
    /// Principals worth fetching for. Gating on this before any request is what
    /// stops invented principals turning into outbound traffic, and it bounds
    /// the cache below, which therefore needs no eviction policy of its own.
    allowed: Vec<String>,
    fetch: KeyListFetcher,
    cache: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

/// A cached lookup: the keys, or why the authority could not be reached.
type CacheEntry = (Result<Vec<VerifyingKey>, String>, Instant);

/// How long an unreachable authority is remembered. Short enough that recovery
/// is quick, long enough that an outage costs one fetch per principal per
/// window rather than one per message, each blocking on the network.
const FETCH_FAILURE_TTL: Duration = Duration::from_secs(30);

impl PublishedKeysAnchor {
    pub fn new(
        authority: impl Into<String>,
        keys_url_template: impl Into<String>,
        allowed: Vec<String>,
        ttl: Duration,
        fetch: KeyListFetcher,
    ) -> Self {
        Self {
            authority: authority.into(),
            keys_url_template: keys_url_template.into(),
            allowed,
            fetch,
            cache: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    fn keys_for(&self, principal: &str) -> Result<Vec<VerifyingKey>, IdentityError> {
        let fresh = self.cache().get(principal).and_then(|(cached, at)| {
            let ttl = if cached.is_ok() {
                self.ttl
            } else {
                FETCH_FAILURE_TTL
            };
            (at.elapsed() < ttl).then(|| cached.clone())
        });
        if let Some(cached) = fresh {
            return cached.map_err(IdentityError::Config);
        }

        let url = self.keys_url_template.replace("{}", principal);
        let fetched = (self.fetch)(&url).map(|listing| all_ed25519_in_authorized_keys(&listing));
        self.cache()
            .insert(principal.to_string(), (fetched.clone(), Instant::now()));
        fetched.map_err(IdentityError::Config)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, CacheEntry>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl TrustAnchor for PublishedKeysAnchor {
    fn vouches_for(&self, principal: &str, key: &VerifyingKey) -> Result<bool, IdentityError> {
        if !self.allowed.iter().any(|p| p == principal) {
            return Ok(false);
        }
        Ok(self.keys_for(principal)?.contains(key))
    }

    fn authority(&self) -> &str {
        &self.authority
    }
}

/// An authority whose keys the operator names directly, with no network and no
/// external issuer. Covers peers holding no account anywhere, and deployments
/// that must work offline.
pub struct DeclaredKeysAnchor {
    authority: String,
    keys: HashMap<String, Vec<VerifyingKey>>,
}

impl DeclaredKeysAnchor {
    /// `declared` maps each principal to the `did:key` identifiers vouched for
    /// it. Parsing here means a malformed entry fails while the operator is
    /// still looking at the configuration.
    pub fn new(
        authority: impl Into<String>,
        declared: HashMap<String, Vec<String>>,
    ) -> Result<Self, IdentityError> {
        let mut keys = HashMap::with_capacity(declared.len());
        for (principal, dids) in declared {
            let parsed = dids
                .iter()
                .map(|did| parse_did_key(did))
                .collect::<Result<Vec<_>, _>>()?;
            keys.insert(principal, parsed);
        }
        Ok(Self {
            authority: authority.into(),
            keys,
        })
    }
}

impl TrustAnchor for DeclaredKeysAnchor {
    fn vouches_for(&self, principal: &str, key: &VerifyingKey) -> Result<bool, IdentityError> {
        Ok(self
            .keys
            .get(principal)
            .is_some_and(|keys| keys.contains(key)))
    }

    fn authority(&self) -> &str {
        &self.authority
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentIdentity;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const TTL: Duration = Duration::from_secs(900);

    fn key() -> VerifyingKey {
        AgentIdentity::generate().unwrap().verifying_key()
    }

    fn listing(keys: &[&VerifyingKey]) -> String {
        keys.iter()
            .map(|k| {
                let mut blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 ".to_vec();
                blob.extend_from_slice(k.as_bytes());
                format!(
                    "ssh-ed25519 {}",
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn published(body: Result<String, String>, allowed: &[&str]) -> PublishedKeysAnchor {
        PublishedKeysAnchor::new(
            "github.com",
            "https://github.com/{}.keys",
            allowed.iter().map(|s| s.to_string()).collect(),
            TTL,
            Box::new(move |_| body.clone()),
        )
    }

    /// A fetcher that counts its own calls. Shared across tests that assert a
    /// call count, whether zero (never reached) or one (served from cache).
    fn counting_fetcher(
        calls: &Arc<AtomicUsize>,
        result: Result<String, String>,
    ) -> KeyListFetcher {
        let seen = Arc::clone(calls);
        Box::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            result.clone()
        })
    }

    #[test]
    fn a_published_key_is_vouched_for_and_an_absent_one_is_not() {
        let mine = key();
        let anchor = published(Ok(listing(&[&mine])), &["alice"]);
        assert!(anchor.vouches_for("alice", &mine).unwrap());
        assert!(!anchor.vouches_for("alice", &key()).unwrap());
        assert_eq!(anchor.authority(), "github.com");
    }

    #[test]
    fn an_unreachable_authority_is_an_error_not_a_no() {
        let anchor = published(Err("connection refused".to_string()), &["alice"]);
        assert!(anchor.vouches_for("alice", &key()).is_err());
    }

    /// A remembered failure is reused within `FETCH_FAILURE_TTL`, so an
    /// outage costs one fetch per principal rather than one per message.
    #[test]
    fn a_cached_failure_is_reused_without_refetching() {
        let calls = Arc::new(AtomicUsize::new(0));
        let anchor = PublishedKeysAnchor::new(
            "github.com",
            "https://github.com/{}.keys",
            vec!["alice".to_string()],
            TTL,
            counting_fetcher(&calls, Err("connection refused".to_string())),
        );
        assert!(anchor.vouches_for("alice", &key()).is_err());
        assert!(anchor.vouches_for("alice", &key()).is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a cached failure must not be refetched"
        );
    }

    /// An empty listing is a negative answer, so a 404 must not fail closed.
    #[test]
    fn an_empty_listing_answers_no() {
        let anchor = published(Ok(String::new()), &["alice"]);
        assert!(!anchor.vouches_for("alice", &key()).unwrap());
    }

    #[test]
    fn a_principal_outside_the_allow_list_costs_no_request() {
        let calls = Arc::new(AtomicUsize::new(0));
        let anchor = PublishedKeysAnchor::new(
            "github.com",
            "https://github.com/{}.keys",
            vec!["alice".to_string()],
            TTL,
            counting_fetcher(&calls, Ok(String::new())),
        );
        assert!(!anchor.vouches_for("mallory", &key()).unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "fetched for an unlisted principal"
        );
    }

    #[test]
    fn a_second_lookup_is_served_from_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mine = key();
        let anchor = PublishedKeysAnchor::new(
            "github.com",
            "https://github.com/{}.keys",
            vec!["alice".to_string()],
            TTL,
            counting_fetcher(&calls, Ok(listing(&[&mine]))),
        );
        assert!(anchor.vouches_for("alice", &mine).unwrap());
        assert!(anchor.vouches_for("alice", &mine).unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_url_template_names_the_principal() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let urls = Arc::clone(&seen);
        let anchor = PublishedKeysAnchor::new(
            "github.com",
            "https://github.com/{}.keys",
            vec!["alice".to_string()],
            TTL,
            Box::new(move |url| {
                urls.lock().unwrap().push(url.to_string());
                Ok(String::new())
            }),
        );
        anchor.vouches_for("alice", &key()).unwrap();
        assert_eq!(seen.lock().unwrap()[0], "https://github.com/alice.keys");
    }

    #[test]
    fn a_declared_key_is_vouched_for_without_any_fetch() {
        let id = AgentIdentity::generate().unwrap();
        let anchor = DeclaredKeysAnchor::new(
            "local",
            HashMap::from([("alice".to_string(), vec![id.did()])]),
        )
        .unwrap();
        assert!(anchor.vouches_for("alice", &id.verifying_key()).unwrap());
        assert!(!anchor.vouches_for("alice", &key()).unwrap());
        assert!(!anchor.vouches_for("bob", &id.verifying_key()).unwrap());
        assert_eq!(anchor.authority(), "local");
    }

    #[test]
    fn a_malformed_declared_key_is_rejected_at_construction() {
        let err = DeclaredKeysAnchor::new(
            "local",
            HashMap::from([("alice".to_string(), vec!["not-a-did".to_string()])]),
        );
        assert!(err.is_err());
    }

    /// Both sources answer the same question, so a caller can hold either.
    #[test]
    fn either_source_satisfies_the_trait() {
        let id = AgentIdentity::generate().unwrap();
        let anchors: Vec<Box<dyn TrustAnchor>> = vec![
            Box::new(published(Ok(listing(&[&id.verifying_key()])), &["alice"])),
            Box::new(
                DeclaredKeysAnchor::new(
                    "local",
                    HashMap::from([("alice".to_string(), vec![id.did()])]),
                )
                .unwrap(),
            ),
        ];
        for anchor in anchors {
            let authority = anchor.authority();
            assert!(
                anchor.vouches_for("alice", &id.verifying_key()).unwrap(),
                "{authority} did not vouch"
            );
        }
    }

    /// A key stops being trusted once its cache entry expires, not just when
    /// it's removed from the listing - a zero TTL makes every lookup stale
    #[test]
    fn expired_entry_is_refetched() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mine = key();
        let anchor = PublishedKeysAnchor::new(
            "github.com",
            "https://github.com/{}.keys",
            vec!["alice".to_string()],
            Duration::ZERO,
            counting_fetcher(&calls, Ok(listing(&[&mine]))),
        );
        assert!(anchor.vouches_for("alice", &mine).unwrap());
        assert!(anchor.vouches_for("alice", &mine).unwrap());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "expired cache entry must be refetched"
        );
    }
}
