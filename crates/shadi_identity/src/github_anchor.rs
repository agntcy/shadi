// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! A [`TrustAnchor`] backed by an account's published SSH keys.
//!
//! The two links: a forge publishes a key only after its account holder
//! uploaded it while authenticated, and that key signs an attestation naming
//! the agent's DID. A receiver follows both with one GET and one signature
//! check, and holds no credential of its own.
//!
//! The fetch is injected rather than done here, so this crate keeps no HTTP
//! or TLS stack and the anchor is testable without a server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::freshness::now_secs;
use crate::ssh::all_ed25519_in_authorized_keys;
use crate::trust_anchor::{peek_principal, verify_attestation, Attestation, TrustAnchor};
use crate::IdentityError;

/// Fetches an `authorized_keys`-style listing for one principal.
///
/// `Ok("")` means the account publishes no usable key — a 404 included, which
/// is an answer rather than an outage. `Err` means the authority could not be
/// reached, and admission fails closed on it.
pub type KeyListFetcher = Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

pub struct GithubKeysAnchor {
    authority: String,
    /// Principals worth fetching for. An unknown sender is refused before any
    /// outbound request, which is what stops a flood of invented principals
    /// turning into a flood of GETs.
    allowed: Vec<String>,
    keys_url_template: String,
    fetch: KeyListFetcher,
    /// Keyed by principal, so it is bounded by `allowed` and needs no cap of
    /// its own. Holds failures as well as answers — an empty listing is a
    /// negative answer, an `Err` is an unreachable authority.
    cache: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    clock_skew: Duration,
}

/// One cached lookup: the keys, or why the authority could not be reached.
type CacheEntry = (Result<Vec<ed25519_dalek::VerifyingKey>, String>, Instant);

/// How long an unreachable authority is remembered. Short, so recovery is
/// quick, but enough that an outage costs one fetch per principal per window
/// instead of one per message — each of which blocks on the network.
const FETCH_FAILURE_TTL: Duration = Duration::from_secs(30);

impl GithubKeysAnchor {
    pub fn new(
        authority: impl Into<String>,
        keys_url_template: impl Into<String>,
        allowed: Vec<String>,
        ttl: Duration,
        clock_skew: Duration,
        fetch: KeyListFetcher,
    ) -> Self {
        Self {
            authority: authority.into(),
            allowed,
            keys_url_template: keys_url_template.into(),
            fetch,
            cache: Mutex::new(HashMap::new()),
            ttl,
            clock_skew,
        }
    }

    fn keys_for(&self, principal: &str) -> Result<Vec<ed25519_dalek::VerifyingKey>, IdentityError> {
        if let Some((cached, at)) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(principal)
        {
            let ttl = if cached.is_ok() {
                self.ttl
            } else {
                FETCH_FAILURE_TTL
            };
            if at.elapsed() < ttl {
                return cached.clone().map_err(IdentityError::Config);
            }
        }

        let url = self.keys_url_template.replace("{}", principal);
        let fetched = (self.fetch)(&url).map(|listing| all_ed25519_in_authorized_keys(&listing));
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(principal.to_string(), (fetched.clone(), Instant::now()));
        fetched.map_err(IdentityError::Config)
    }
}

impl TrustAnchor for GithubKeysAnchor {
    fn resolve(&self, did: &str, hint: Option<&str>) -> Result<Option<Attestation>, IdentityError> {
        let Some(jws) = hint else {
            return Ok(None);
        };
        // Unverified, and used only to pick whose keys to fetch. Nothing from
        // it is trusted until the signature check below succeeds.
        let Some(claimed) = peek_principal(jws) else {
            return Ok(None);
        };
        if !self.allowed.iter().any(|p| p == &claimed) {
            return Ok(None);
        }

        let keys = self.keys_for(&claimed)?;
        let now = now_secs();
        let Some(claims) = keys
            .iter()
            .find_map(|key| verify_attestation(jws, key, now, self.clock_skew))
        else {
            return Ok(None);
        };

        // The binding the scheme rests on: the attestation must name the DID
        // that actually signed the envelope.
        if claims.did != did {
            tracing::warn!(
                %did,
                principal = %claimed,
                attested_did = %claims.did,
                "attestation verified but names a different DID"
            );
            return Ok(None);
        }
        // Minting hardcodes github.com while the anchor's name comes from
        // policy, so a mismatch here is almost always an issuer string that is
        // not exactly "github.com".
        if claims.authority != self.authority {
            tracing::warn!(
                %did,
                expected = %self.authority,
                attested = %claims.authority,
                "attestation names a different authority"
            );
            return Ok(None);
        }
        // Invariant, not a defence: the fetch was keyed on `claimed`, which
        // came from this same payload, so these agree unless peeking and
        // verifying ever stop reading the same field.
        debug_assert_eq!(claims.principal, claimed);

        Ok(Some(Attestation {
            did: claims.did,
            principal: claims.principal,
            authority: self.authority.clone(),
            email: None,
            email_verified: false,
            claims: [("tool".to_string(), claims.tool.into())]
                .into_iter()
                .collect(),
        }))
    }

    fn authority(&self) -> &str {
        &self.authority
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_anchor::{mint_attestation, AttestationClaims};
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const AUTHORITY: &str = "github.com";
    const TEMPLATE: &str = "https://github.com/{}.keys";
    const DID: &str = "did:key:zAlice";

    fn ssh_key(seed: [u8; 32]) -> (SigningKey, String) {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let line = ssh_key::PrivateKey::from(keypair)
            .public_key()
            .to_openssh()
            .unwrap();
        (SigningKey::from_bytes(&seed), line)
    }

    fn claims(did: &str, principal: &str, tool: &str) -> AttestationClaims {
        AttestationClaims {
            authority: AUTHORITY.to_string(),
            principal: principal.to_string(),
            did: did.to_string(),
            tool: tool.to_string(),
            iat: now_secs() - 60,
            exp: now_secs() + 3600,
        }
    }

    fn anchor(listing: String, allowed: &[&str]) -> GithubKeysAnchor {
        GithubKeysAnchor::new(
            AUTHORITY,
            TEMPLATE,
            allowed.iter().map(|p| p.to_string()).collect(),
            Duration::from_secs(900),
            Duration::from_secs(60),
            Box::new(move |_| Ok(listing.clone())),
        )
    }

    #[test]
    fn resolves_a_did_attested_by_a_published_key() {
        let (signer, line) = ssh_key([1u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "amarton", "claude-code")).unwrap();
        let att = anchor(line, &["amarton"])
            .resolve(DID, Some(&jws))
            .unwrap()
            .expect("should resolve");

        assert_eq!(att.principal, "amarton");
        assert_eq!(att.authority, AUTHORITY);
        assert_eq!(att.claims.get("tool").unwrap(), "claude-code");
    }

    /// The signing key is not one the account publishes.
    #[test]
    fn an_unpublished_key_does_not_resolve() {
        let (_, published) = ssh_key([1u8; 32]);
        let (other, _) = ssh_key([2u8; 32]);
        let jws = mint_attestation(&other, &claims(DID, "amarton", "claude-code")).unwrap();
        assert!(anchor(published, &["amarton"])
            .resolve(DID, Some(&jws))
            .unwrap()
            .is_none());
    }

    /// A captured attestation re-attached to an envelope signed by another key.
    #[test]
    fn an_attestation_for_another_did_does_not_resolve() {
        let (signer, line) = ssh_key([1u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "amarton", "claude-code")).unwrap();
        assert!(anchor(line, &["amarton"])
            .resolve("did:key:zEve", Some(&jws))
            .unwrap()
            .is_none());
    }

    /// Claiming someone else's login: their keys are what the JWS must verify
    /// against, and it does not.
    #[test]
    fn claiming_another_principal_does_not_resolve() {
        let (signer, _) = ssh_key([1u8; 32]);
        let (_, victim_keys) = ssh_key([2u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "jdoe", "claude-code")).unwrap();
        assert!(anchor(victim_keys, &["jdoe"])
            .resolve(DID, Some(&jws))
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_message_without_an_attestation_abstains() {
        let (_, line) = ssh_key([1u8; 32]);
        assert!(anchor(line, &["amarton"])
            .resolve(DID, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn an_unreachable_authority_errors_rather_than_abstaining() {
        let (signer, _) = ssh_key([1u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "amarton", "claude-code")).unwrap();
        let anchor = GithubKeysAnchor::new(
            AUTHORITY,
            TEMPLATE,
            vec!["amarton".to_string()],
            Duration::from_secs(900),
            Duration::from_secs(60),
            Box::new(|_| Err("connection refused".to_string())),
        );
        // Err, not Ok(None): an outage must not read as "unknown peer".
        assert!(anchor.resolve(DID, Some(&jws)).is_err());
    }

    /// Every message from an allow-listed principal would otherwise block on
    /// the network for the whole of an outage.
    #[test]
    fn an_unreachable_authority_is_not_refetched_per_message() {
        let (signer, _) = ssh_key([1u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "amarton", "claude-code")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let anchor = GithubKeysAnchor::new(
            AUTHORITY,
            TEMPLATE,
            vec!["amarton".to_string()],
            Duration::from_secs(900),
            Duration::from_secs(60),
            Box::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Err("connection refused".to_string())
            }),
        );

        for _ in 0..5 {
            // Still Err each time — the verdict is cached, not softened.
            assert!(anchor.resolve(DID, Some(&jws)).is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_unknown_principal_is_refused_without_fetching() {
        let (signer, _) = ssh_key([1u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "stranger", "claude-code")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let anchor = GithubKeysAnchor::new(
            AUTHORITY,
            TEMPLATE,
            vec!["amarton".to_string()],
            Duration::from_secs(900),
            Duration::from_secs(60),
            Box::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(String::new())
            }),
        );

        assert!(anchor.resolve(DID, Some(&jws)).unwrap().is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "must not touch the network"
        );
    }

    #[test]
    fn the_key_list_is_fetched_once_per_principal_within_the_ttl() {
        let (signer, line) = ssh_key([1u8; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let anchor = GithubKeysAnchor::new(
            AUTHORITY,
            TEMPLATE,
            vec!["amarton".to_string()],
            Duration::from_secs(900),
            Duration::from_secs(60),
            Box::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(line.clone())
            }),
        );

        // Distinct DIDs, same principal: the whole point of caching per
        // principal, since an attacker can invent DIDs freely.
        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            let jws = mint_attestation(&signer, &claims(did, "amarton", "claude-code")).unwrap();
            assert!(anchor.resolve(did, Some(&jws)).unwrap().is_some());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A 404 is an answer, and caching it stops a re-ask per message.
    #[test]
    fn an_account_with_no_keys_is_cached_negatively() {
        let (signer, _) = ssh_key([1u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "amarton", "claude-code")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let anchor = GithubKeysAnchor::new(
            AUTHORITY,
            TEMPLATE,
            vec!["amarton".to_string()],
            Duration::from_secs(900),
            Duration::from_secs(60),
            Box::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(String::new())
            }),
        );

        assert!(anchor.resolve(DID, Some(&jws)).unwrap().is_none());
        assert!(anchor.resolve(DID, Some(&jws)).unwrap().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_url_template_is_filled_with_the_principal() {
        let (signer, line) = ssh_key([1u8; 32]);
        let jws = mint_attestation(&signer, &claims(DID, "amarton", "claude-code")).unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        let recorder = Arc::clone(&seen);
        let anchor = GithubKeysAnchor::new(
            AUTHORITY,
            TEMPLATE,
            vec!["amarton".to_string()],
            Duration::from_secs(900),
            Duration::from_secs(60),
            Box::new(move |url| {
                *recorder.lock().unwrap() = url.to_string();
                Ok(line.clone())
            }),
        );

        anchor.resolve(DID, Some(&jws)).unwrap();
        assert_eq!(
            seen.lock().unwrap().as_str(),
            "https://github.com/amarton.keys"
        );
    }

    #[test]
    fn an_expired_attestation_does_not_resolve() {
        let (signer, line) = ssh_key([1u8; 32]);
        let mut expired = claims(DID, "amarton", "claude-code");
        expired.iat = now_secs() - 7200;
        expired.exp = now_secs() - 3600;
        let jws = mint_attestation(&signer, &expired).unwrap();
        assert!(anchor(line, &["amarton"])
            .resolve(DID, Some(&jws))
            .unwrap()
            .is_none());
    }
}
