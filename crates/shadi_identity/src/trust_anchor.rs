// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Who owns a `did:key`, according to an authority outside the message.
//!
//! This is the out-of-band half of the design. `SHADI-DID-PROOF/1` proves the
//! sender holds the private key for some DID; it says nothing about whose key
//! that is. An anchor answers that second question from a source the sender
//! does not control, which is what lets the OIDC credential stay off the wire
//! entirely (see [`crate::oidc`]).
//!
//! No SHADI-defined signed object is introduced here. [`GithubAnchor`] reads a
//! key GitHub publishes and [`LocalAnchor`] reads a file the operator wrote —
//! existing attestations, consumed. There is no home-made certificate format
//! in the trust path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::IdentityError;

/// How long a resolved attestation may be reused.
///
/// Deliberately *not* the 3600 s JWKS lifetime: IdP signing keys rotate
/// monthly, but DID ownership changes when someone leaves the company.
/// Inheriting the JWKS number would be a category error, and this is the
/// window a revoked key stays admissible for — the deny-list, checked before
/// the cache, is what makes revocation immediate.
pub const ATTESTATION_TTL: Duration = Duration::from_secs(300);

/// How long a *miss* is remembered. Short enough that a freshly enrolled agent
/// is not visibly broken, long enough to blunt DID enumeration.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// Who an attestation names, and who vouched for it.
///
/// Identity is the `(authority, principal)` pair. Never `principal` alone:
/// two issuers can both mint `sub = alice`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub did: String,
    /// A stable id: an OIDC `sub`, a GitHub login, a workload ref. Never an
    /// email — an address is reassignable, so the next hire called `alice`
    /// would silently inherit access.
    pub principal: String,
    /// The attesting authority: an OIDC issuer URL, or `github.com`.
    pub authority: String,
    /// For domain policy only, and only honoured when `email_verified`.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    /// Extra claims for policy — groups, `repository`, `repository_owner`.
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

pub trait TrustAnchor: Send + Sync {
    /// Resolve `did` to the principal that owns it.
    ///
    /// `hint` is an **unauthenticated** lookup key (it rides in A2A metadata,
    /// outside the envelope signature). It selects *whose* attestation to
    /// fetch and is never believed: a wrong hint can only fail to match `did`.
    ///
    /// `Ok(None)` means "this anchor cannot answer" — no usable hint, or no
    /// such binding — and lets several anchors be tried in order without an
    /// abstention looking like a failure. `Err` means the authority should
    /// have known but could not be reached, which admission must fail closed
    /// on rather than treat as "unknown peer".
    fn resolve(&self, did: &str, hint: Option<&str>)
        -> Result<Option<Attestation>, IdentityError>;

    fn authority(&self) -> &str;
}

/// Operator-pinned `principal -> did` pairs, read from the policy file.
///
/// Always available, explicit, and does not scale — the escape hatch and the
/// test fixture. This is the old hand-edited DID allow-list, promoted to a
/// first-class anchor so it goes through the same policy evaluation as the
/// resolvable ones.
pub struct LocalAnchor {
    authority: String,
    entries: Vec<Attestation>,
}

impl LocalAnchor {
    pub fn new(authority: impl Into<String>, entries: Vec<Attestation>) -> Self {
        Self {
            authority: authority.into(),
            entries,
        }
    }
}

impl TrustAnchor for LocalAnchor {
    fn resolve(
        &self,
        did: &str,
        _hint: Option<&str>,
    ) -> Result<Option<Attestation>, IdentityError> {
        Ok(self.entries.iter().find(|a| a.did == did).cloned())
    }

    fn authority(&self) -> &str {
        &self.authority
    }
}

/// Resolves a DID via the Ed25519 keys a user published on GitHub.
///
/// GitHub has **no reverse key lookup** — you can ask "what keys does alice
/// publish", never "who published this key". So a `hint` of the form
/// `github:<login>` is required to pick whose keys to fetch; the DID is then
/// checked against them. That is safe because a wrong hint cannot produce a
/// match: hinting `github:alice` for Eve's DID fails when Alice's published
/// keys do not contain it, and hinting Alice's DID fails at the envelope
/// signature because Eve cannot sign for it.
pub struct GithubAnchor {
    token: Option<String>,
    /// Keyed by `login|did`, so a hint change cannot serve another user's
    /// cached answer. Holds misses too, at [`NEGATIVE_TTL`].
    cache: Mutex<HashMap<String, (Option<Attestation>, Instant)>>,
}

pub const GITHUB_AUTHORITY: &str = "github.com";

impl GithubAnchor {
    /// Always pass a token when one is available: unauthenticated GitHub is
    /// 60 requests/hour, authenticated is 5,000, and exhausting the limit
    /// breaks admission for every peer.
    pub fn new(token: Option<String>) -> Self {
        Self {
            token,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn login_from_hint(hint: Option<&str>) -> Option<&str> {
        hint?.strip_prefix("github:")
    }
}

impl TrustAnchor for GithubAnchor {
    fn resolve(&self, did: &str, hint: Option<&str>) -> Result<Option<Attestation>, IdentityError> {
        let Some(login) = Self::login_from_hint(hint) else {
            // No usable hint: this anchor cannot answer. Not an error — another
            // anchor may be able to.
            return Ok(None);
        };

        let cache_key = format!("{login}|{did}");
        if let Some((hit, at)) = self.cache.lock().unwrap().get(&cache_key) {
            let ttl = if hit.is_some() {
                ATTESTATION_TTL
            } else {
                NEGATIVE_TTL
            };
            if at.elapsed() < ttl {
                return Ok(hit.clone());
            }
        }

        let dids = crate::github::published_dids(login, self.token.as_deref())?;
        let found = dids.iter().any(|d| d == did).then(|| Attestation {
            did: did.to_string(),
            principal: login.to_string(),
            authority: GITHUB_AUTHORITY.to_string(),
            // GitHub's key listing carries no address, and an unverified one
            // must never reach the domain check.
            email: None,
            email_verified: false,
            claims: serde_json::Map::new(),
        });

        self.cache
            .lock()
            .unwrap()
            .insert(cache_key, (found.clone(), Instant::now()));
        Ok(found)
    }

    fn authority(&self) -> &str {
        GITHUB_AUTHORITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::test_seam::TestKeys;

    fn attestation(did: &str, principal: &str) -> Attestation {
        Attestation {
            did: did.to_string(),
            principal: principal.to_string(),
            authority: "https://issuer.example".to_string(),
            email: Some(format!("{principal}@corp.com")),
            email_verified: true,
            claims: serde_json::Map::new(),
        }
    }

    #[test]
    fn local_anchor_round_trips_a_pinned_pair() {
        let anchor = LocalAnchor::new(
            "https://issuer.example",
            vec![attestation("did:key:zAlice", "alice")],
        );
        let found = anchor.resolve("did:key:zAlice", None).unwrap().unwrap();
        assert_eq!(found.principal, "alice");
        assert_eq!(anchor.authority(), "https://issuer.example");
        assert!(anchor.resolve("did:key:zBob", None).unwrap().is_none());
    }

    #[test]
    fn github_anchor_abstains_without_a_usable_hint() {
        let anchor = GithubAnchor::new(None);
        assert!(anchor.resolve("did:key:zAlice", None).unwrap().is_none());
        assert!(anchor
            .resolve("did:key:zAlice", Some("oidc:https://issuer.example#alice"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn github_anchor_resolves_a_published_key() {
        let alice = crate::AgentIdentity::generate().unwrap();
        let _keys = TestKeys::set(&TestKeys::ssh_line(&alice));
        let anchor = GithubAnchor::new(None);
        let found = anchor
            .resolve(&alice.did(), Some("github:alice"))
            .unwrap()
            .unwrap();
        assert_eq!(found.principal, "alice");
        assert_eq!(found.authority, GITHUB_AUTHORITY);
        assert!(!found.email_verified, "GitHub keys carry no verified email");
    }

    /// The hint names a real user who does not own this DID. Eve gains
    /// nothing by claiming to be Alice, because the hint is only a lookup key
    /// and the answer is checked against the DID.
    #[test]
    fn github_anchor_rejects_a_hint_that_does_not_own_the_did() {
        let alice = crate::AgentIdentity::generate().unwrap();
        let eve = crate::AgentIdentity::generate().unwrap();
        let _keys = TestKeys::set(&TestKeys::ssh_line(&alice));
        let anchor = GithubAnchor::new(None);
        assert!(anchor
            .resolve(&eve.did(), Some("github:alice"))
            .unwrap()
            .is_none());
    }
}
