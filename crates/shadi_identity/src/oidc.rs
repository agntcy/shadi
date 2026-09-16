// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Standard OIDC ID-token verification — discovery, JWKS, signature, claims.
//!
//! # Invariant
//!
//! **No token verified here may be put on the wire.** This module runs once,
//! at enrollment, to learn *who the human is*; the answer is recorded as an
//! [`crate::trust_anchor::Attestation`] and the token is discarded. The
//! security argument for the whole design rests on an OIDC credential never
//! being visible to a peer: possession of *a* key is not evidence that the
//! token's owner chose *that* key, so a visible token reduces admission to
//! self-assertion. The wire may carry an unauthenticated principal *hint*
//! (a lookup key, verified against an authority — see
//! [`crate::freshness::A2A_PRINCIPAL_HINT_METADATA_KEY`]); it must never carry
//! an identity *claim* that is believed.
//!
//! If you find yourself wanting to send one of these tokens, that invariant is
//! the thing you are about to break.

use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;

use crate::IdentityError;

/// Bounds how long an anchor or enrollment fetch can stall the caller.
/// `reqwest` has no default timeout, and `TrustAnchor::resolve` is synchronous.
pub(crate) const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

fn oidc(msg: impl Into<String>) -> IdentityError {
    IdentityError::Oidc(msg.into())
}

/// The claims taken from a verified ID token.
///
/// Identity is the `(iss, sub)` pair, never `sub` alone — two issuers can both
/// mint `sub = alice`. `email` is policy input only, and only when
/// `email_verified`: an address is reassignable, so it is not an identifier.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    pub iss: String,
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    /// Every claim in the token, for policy that needs groups, `repository`, …
    pub raw: serde_json::Map<String, serde_json::Value>,
}

/// Verifies OIDC ID tokens against their issuer's published JWKS.
pub struct OidcVerifier {
    http: reqwest::blocking::Client,
    /// Issuers we will fetch from. Consulted *before* any network call, so a
    /// forged `iss` cannot steer this at an arbitrary URL (SSRF).
    trusted_issuers: Vec<String>,
    /// Our own OIDC client_id. Every accepted token must name it in `aud`.
    expected_audience: String,
}

impl OidcVerifier {
    pub fn new(trusted_issuers: Vec<String>, expected_audience: String) -> Self {
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()
                .unwrap_or_default(),
            trusted_issuers,
            expected_audience,
        }
    }

    /// Verify an ID token and return its claims.
    ///
    /// No JWKS cache: enrollment verifies exactly one token per invocation.
    /// A long-lived caller wants one, at the 3600 s JWKS lifetime — which is
    /// *not* the attestation lifetime, see
    /// [`crate::trust_anchor::ATTESTATION_TTL`].
    pub fn verify_token(&self, jwt: &str) -> Result<OidcClaims, IdentityError> {
        // Unverified, and used for exactly one thing: choosing whose keys to
        // fetch. The signature check below re-tests `iss` against the same
        // value, so a lie here cannot survive.
        let iss = peek_issuer(jwt)?;
        if !self.trusted_issuers.iter().any(|i| i == &iss) {
            return Err(oidc(format!("issuer {iss} is not trusted")));
        }
        let jwks = self.jwks_for_issuer(&iss)?;
        verify_claims_with_jwks(jwt, &jwks, &iss, &self.expected_audience)
    }

    fn jwks_for_issuer(&self, iss: &str) -> Result<JwkSet, IdentityError> {
        if !iss.starts_with("https://") {
            return Err(oidc(format!("issuer {iss} is not https")));
        }
        let discovery = format!(
            "{}/.well-known/openid-configuration",
            iss.trim_end_matches('/')
        );
        let doc: serde_json::Value = self
            .http
            .get(&discovery)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|e| oidc(format!("OIDC discovery at {discovery} failed: {e}")))?;

        // OIDC Discovery 1.0 §4.3: the document's `issuer` must equal the
        // issuer it was retrieved for, exactly. Without this a redirect could
        // hand us another IdP's key set.
        if doc.get("issuer").and_then(|v| v.as_str()) != Some(iss) {
            return Err(oidc(format!(
                "discovery document at {discovery} does not claim issuer {iss}"
            )));
        }
        let jwks_uri = doc
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| oidc(format!("discovery document at {discovery} has no jwks_uri")))?;
        if !jwks_uri.starts_with("https://") {
            return Err(oidc(format!("jwks_uri {jwks_uri} is not https")));
        }

        self.http
            .get(jwks_uri)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|e| oidc(format!("JWKS fetch from {jwks_uri} failed: {e}")))
    }
}

/// The `iss` claim, read without verifying anything. Safe only as a lookup key.
fn peek_issuer(jwt: &str) -> Result<String, IdentityError> {
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| oidc("malformed JWT: no payload segment"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| oidc(format!("malformed JWT payload: {e}")))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| oidc(format!("malformed JWT claims: {e}")))?;
    claims
        .get("iss")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| oidc("JWT carries no iss claim"))
}

fn verify_claims_with_jwks(
    jwt: &str,
    jwks: &JwkSet,
    iss: &str,
    expected_aud: &str,
) -> Result<OidcClaims, IdentityError> {
    let header =
        jsonwebtoken::decode_header(jwt).map_err(|e| oidc(format!("malformed JWT header: {e}")))?;
    let jwk = match &header.kid {
        Some(kid) => jwks
            .find(kid)
            .ok_or_else(|| oidc(format!("no JWKS key for kid {kid}")))?,
        None => jwks
            .keys
            .first()
            .ok_or_else(|| oidc(format!("issuer {iss} published an empty JWKS")))?,
    };
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|e| oidc(format!("unusable JWKS key: {e}")))?;

    // The algorithm family comes from the JWK's own key type, never from the
    // token header, so a forged header cannot downgrade an RSA key into HMAC.
    let mut validation = jsonwebtoken::Validation::new_for_family(key.family());
    validation.set_issuer(&[iss]);
    // MUST be set. jsonwebtoken 10.4 defaults `validate_aud = true` with
    // `aud = None`, and rejects outright any token that carries an `aud` when
    // none is expected. OIDC Core makes `aud` mandatory in ID tokens, so
    // omitting this rejects every real token — while passing any test whose
    // fixture omits `aud`. Hence `claims_with_aud` in the tests below.
    validation.set_audience(&[expected_aud]);

    let data = jsonwebtoken::decode::<serde_json::Value>(jwt, &key, &validation)
        .map_err(|e| oidc(format!("OIDC token verification failed: {e}")))?;
    let raw = data
        .claims
        .as_object()
        .ok_or_else(|| oidc("OIDC claims are not a JSON object"))?
        .clone();
    let sub = raw
        .get("sub")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| oidc("verified token carries no sub claim"))?
        .to_string();

    Ok(OidcClaims {
        iss: iss.to_string(),
        sub,
        email: raw
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        email_verified: raw
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    const TEST_ISS: &str = "https://issuer.example";
    const TEST_AUD: &str = "shadi-agentbridge";

    /// A matching (signing key, JWKS) pair for an Ed25519 JWK — the same key
    /// family SHADI's own `did:key`s use, so no live IdP and no HTTP mock is
    /// needed to test everything but the fetch.
    fn eddsa_key_and_jwks(kid: &str) -> (EncodingKey, JwkSet) {
        let id = crate::AgentIdentity::generate().unwrap();
        let key = EncodingKey::from_ed_pem(id.to_pkcs8_pem().unwrap().as_bytes()).unwrap();
        let mut jwk = id.public_jwk();
        jwk["kid"] = serde_json::json!(kid);
        let jwks = serde_json::json!({ "keys": [jwk] });
        (key, serde_json::from_value(jwks).unwrap())
    }

    fn sign(key: &EncodingKey, claims: &serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(&header, claims, key).unwrap()
    }

    fn claims_with_aud(aud: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": TEST_ISS,
            "sub": "alice-sub",
            "aud": aud,
            "email": "alice@corp.com",
            "email_verified": true,
            "exp": jsonwebtoken::get_current_timestamp() + 3600,
        })
    }

    #[test]
    fn round_trips_with_expected_audience() {
        let (key, jwks) = eddsa_key_and_jwks("kid-1");
        let jwt = sign(&key, &claims_with_aud(TEST_AUD), "kid-1");
        let verified = verify_claims_with_jwks(&jwt, &jwks, TEST_ISS, TEST_AUD).unwrap();
        assert_eq!(verified.sub, "alice-sub");
        assert_eq!(verified.iss, TEST_ISS);
        assert_eq!(verified.email.as_deref(), Some("alice@corp.com"));
        assert!(verified.email_verified);
    }

    /// A token minted for another relying party of the *same* IdP must not be
    /// usable here, though its signature and issuer are both valid. Otherwise
    /// a token issued for an internal wiki replays straight into SHADI.
    #[test]
    fn rejects_foreign_audience() {
        let (key, jwks) = eddsa_key_and_jwks("kid-1");
        let jwt = sign(&key, &claims_with_aud("some-other-app"), "kid-1");
        assert!(verify_claims_with_jwks(&jwt, &jwks, TEST_ISS, TEST_AUD).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let (key, jwks) = eddsa_key_and_jwks("kid-1");
        let mut claims = claims_with_aud(TEST_AUD);
        claims["exp"] = serde_json::json!(jsonwebtoken::get_current_timestamp() - 3600);
        let jwt = sign(&key, &claims, "kid-1");
        assert!(verify_claims_with_jwks(&jwt, &jwks, TEST_ISS, TEST_AUD).is_err());
    }

    #[test]
    fn rejects_mismatched_issuer() {
        let (key, jwks) = eddsa_key_and_jwks("kid-1");
        let jwt = sign(&key, &claims_with_aud(TEST_AUD), "kid-1");
        assert!(verify_claims_with_jwks(&jwt, &jwks, "https://other.example", TEST_AUD).is_err());
    }

    #[test]
    fn rejects_unknown_kid_and_foreign_signer() {
        let (key, jwks) = eddsa_key_and_jwks("kid-1");
        let jwt = sign(&key, &claims_with_aud(TEST_AUD), "kid-unknown");
        assert!(verify_claims_with_jwks(&jwt, &jwks, TEST_ISS, TEST_AUD).is_err());

        // Right kid, wrong key: the JWKS entry belongs to somebody else.
        let (_, other_jwks) = eddsa_key_and_jwks("kid-1");
        let jwt = sign(&key, &claims_with_aud(TEST_AUD), "kid-1");
        assert!(verify_claims_with_jwks(&jwt, &other_jwks, TEST_ISS, TEST_AUD).is_err());
    }

    #[test]
    fn rejects_malformed_jwt() {
        let (_, jwks) = eddsa_key_and_jwks("kid-1");
        assert!(verify_claims_with_jwks("not-a-jwt", &jwks, TEST_ISS, TEST_AUD).is_err());
        assert!(peek_issuer("not-a-jwt").is_err());
        assert!(peek_issuer("a.@@@.c").is_err());
        assert!(peek_issuer("a.e30.c").is_err()); // `{}` — no iss
    }

    /// The allow-list is consulted before any network call, so an untrusted
    /// issuer cannot make us fetch a URL it chose.
    #[test]
    fn untrusted_issuer_is_rejected_without_a_fetch() {
        let (key, _) = eddsa_key_and_jwks("kid-1");
        let jwt = sign(&key, &claims_with_aud(TEST_AUD), "kid-1");
        let verifier = OidcVerifier::new(vec!["https://elsewhere".into()], TEST_AUD.into());
        let err = verifier.verify_token(&jwt).unwrap_err();
        assert!(err.to_string().contains("is not trusted"), "{err}");
    }

    #[test]
    fn non_https_issuer_is_refused() {
        let verifier = OidcVerifier::new(vec!["http://insecure".into()], TEST_AUD.into());
        assert!(verifier.jwks_for_issuer("http://insecure").is_err());
    }
}
