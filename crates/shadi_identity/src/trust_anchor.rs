// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Who owns a `did:key`, according to an authority outside the message.
//!
//! The envelope proves possession of a key; an anchor says whose key it is,
//! from a source the sender does not control.

use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::IdentityError;

/// How long a resolved attestation may be reused. This is the window a revoked
/// key stays admissible for; the deny-list is checked before the cache so
/// revocation does not wait for it.
pub const ATTESTATION_TTL: Duration = Duration::from_secs(300);

/// Who an attestation names, and who vouched for it.
///
/// Identity is the `(authority, principal)` pair. Never `principal` alone:
/// two issuers can both mint `sub = alice`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub did: String,
    /// A stable id, e.g. an OIDC `sub`. Never an email: an address is
    /// reassignable, so the next hire called `alice` would inherit access.
    pub principal: String,
    /// Who vouched for it, e.g. an OIDC issuer URL.
    pub authority: String,
    /// For domain policy only, and only honoured when `email_verified`.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    /// Extra claims for policy, e.g. groups.
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// What a sender signs to claim a DID — the wire form of an attestation.
///
/// Distinct from [`Attestation`], which is what an anchor returns once one has
/// been verified. `iat`/`exp` are consumed at verification and do not survive
/// into that type.
///
/// **`tool` is self-asserted.** The sender signs this with its own key, so a
/// principal can mint claims naming whichever tool it likes. Being inside the
/// signature stops a *relay* from rewriting it, and nothing more: policy's
/// `permitted_tools` therefore constrains an honest principal's
/// misconfiguration, not a dishonest one's choices. What the signature does
/// establish is the `principal → did` binding, because only keys the authority
/// publishes can produce it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationClaims {
    pub authority: String,
    pub principal: String,
    pub did: String,
    pub tool: String,
    pub iat: u64,
    pub exp: u64,
}

/// Longest compact JWS accepted. The claims above encode to ~250 bytes.
pub const ATTESTATION_JWS_MAX_BYTES: usize = 1024;

const JWS_HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Sign `claims` as a compact JWS.
pub fn mint_attestation(
    key: &SigningKey,
    claims: &AttestationClaims,
) -> Result<String, IdentityError> {
    let payload = serde_json::to_vec(claims)
        .map_err(|e| IdentityError::Proof(format!("encode attestation: {e}")))?;
    let signing_input = format!("{}.{}", b64().encode(JWS_HEADER), b64().encode(&payload));
    let sig = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64().encode(sig.to_bytes())))
}

/// The `principal` a JWS claims, without verifying it.
///
/// Only selects whose keys to fetch. Nothing it returns is trusted until
/// [`verify_attestation`] succeeds against one of those keys.
pub fn peek_principal(jws: &str) -> Option<String> {
    Some(decode_claims(jws)?.principal)
}

/// Verify a compact JWS against `key` and return its claims.
///
/// `alg` is never read from the header: Ed25519 is the algorithm by
/// construction, and the header is covered by the signature, so a swapped
/// `alg` — `none` included — just fails verification.
///
/// `None` for every failure, because each one means the same thing to a
/// caller: this key does not vouch for this JWS.
pub fn verify_attestation(
    jws: &str,
    key: &VerifyingKey,
    now: u64,
    clock_skew: Duration,
) -> Option<AttestationClaims> {
    if jws.len() > ATTESTATION_JWS_MAX_BYTES {
        return None;
    }
    let (signing_input, sig_b64) = jws.rsplit_once('.')?;
    let sig = Signature::from_slice(&b64().decode(sig_b64).ok()?).ok()?;
    key.verify(signing_input.as_bytes(), &sig).ok()?;

    let claims = decode_claims(jws)?;
    let skew = clock_skew.as_secs();
    (claims.iat <= now.saturating_add(skew) && now <= claims.exp.saturating_add(skew))
        .then_some(claims)
}

fn decode_claims(jws: &str) -> Option<AttestationClaims> {
    if jws.len() > ATTESTATION_JWS_MAX_BYTES {
        return None;
    }
    let mut parts = jws.split('.');
    let (_header, payload) = (parts.next()?, parts.next()?);
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&b64().decode(payload).ok()?).ok()
}

pub trait TrustAnchor: Send + Sync {
    /// Resolve `did` to the principal that owns it.
    ///
    /// `hint` is an unauthenticated lookup key for anchors that have no
    /// reverse index; it is never believed. `LocalAnchor` ignores it.
    ///
    /// `Ok(None)` means this anchor cannot answer, so the next one is tried.
    /// `Err` means the authority could not be reached — admission fails closed
    /// on that rather than treating it as an unknown peer.
    fn resolve(&self, did: &str, hint: Option<&str>) -> Result<Option<Attestation>, IdentityError>;

    fn authority(&self) -> &str;
}

/// Operator-pinned attestations, read from the policy file.
///
/// Explicit and does not scale, but it goes through the same policy evaluation
/// a resolvable anchor would.
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

#[cfg(test)]
mod tests {
    use super::*;

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

    const NOW: u64 = 1_789_459_200;
    const SKEW: Duration = Duration::from_secs(60);

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn claims() -> AttestationClaims {
        AttestationClaims {
            authority: "github.com".to_string(),
            principal: "amarton".to_string(),
            did: "did:key:zAlice".to_string(),
            tool: "claude-code".to_string(),
            iat: NOW - 60,
            exp: NOW + 2_592_000,
        }
    }

    #[test]
    fn attestation_round_trips_and_peeks_without_verifying() {
        let key = signer();
        let jws = mint_attestation(&key, &claims()).expect("mint");
        assert_eq!(peek_principal(&jws).as_deref(), Some("amarton"));
        assert_eq!(
            verify_attestation(&jws, &key.verifying_key(), NOW, SKEW),
            Some(claims())
        );
    }

    #[test]
    fn another_key_does_not_vouch_for_it() {
        let jws = mint_attestation(&signer(), &claims()).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(verify_attestation(&jws, &other, NOW, SKEW).is_none());
    }

    /// Re-pointing a captured attestation at another DID must not verify —
    /// this is the binding the whole scheme rests on.
    #[test]
    fn repointing_the_did_breaks_the_signature() {
        let key = signer();
        let jws = mint_attestation(&key, &claims()).unwrap();
        let mut forged = claims();
        forged.did = "did:key:zEve".to_string();
        let payload = b64().encode(serde_json::to_vec(&forged).unwrap());

        let mut parts = jws.split('.');
        let spliced = format!(
            "{}.{payload}.{}",
            parts.next().unwrap(),
            parts.nth(1).unwrap()
        );
        assert!(verify_attestation(&spliced, &key.verifying_key(), NOW, SKEW).is_none());
    }

    /// `alg: none` with an empty signature is the classic JWT bypass.
    #[test]
    fn a_stripped_algorithm_header_is_refused() {
        let payload = b64().encode(serde_json::to_vec(&claims()).unwrap());
        let unsigned = format!("{}.{payload}.", b64().encode(r#"{"alg":"none"}"#));
        assert!(verify_attestation(&unsigned, &signer().verifying_key(), NOW, SKEW).is_none());
    }

    #[test]
    fn expiry_and_future_issuance_are_refused_outside_the_skew() {
        let key = signer();
        let vk = key.verifying_key();
        let jws = mint_attestation(&key, &claims()).unwrap();

        assert!(verify_attestation(&jws, &vk, claims().exp + 61, SKEW).is_none());
        assert!(verify_attestation(&jws, &vk, claims().exp + 30, SKEW).is_some());
        assert!(verify_attestation(&jws, &vk, claims().iat - 61, SKEW).is_none());
    }

    #[test]
    fn malformed_and_oversized_input_is_refused() {
        let vk = signer().verifying_key();
        for jws in ["", ".", "a.b", "a.b.c.d", "not base64.at all.here"] {
            assert!(verify_attestation(jws, &vk, NOW, SKEW).is_none(), "{jws}");
            assert!(peek_principal(jws).is_none(), "{jws}");
        }
        let huge = "a".repeat(ATTESTATION_JWS_MAX_BYTES + 1);
        assert!(peek_principal(&huge).is_none());
        assert!(verify_attestation(&huge, &vk, NOW, SKEW).is_none());
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
}
