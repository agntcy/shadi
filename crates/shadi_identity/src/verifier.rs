// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! [`DidKeyVerifier`]: SLIM's [`Verifier`] for self-issued `did:key` DID-JWTs.
//!
//! A token is accepted only when it is an `EdDSA` JWT whose `sub` and `iss` are the
//! same Ed25519 `did:key`, whose signature verifies against the key inside that DID,
//! whose times fall within the lifetime bound, and whose `aud` is exactly
//! [`DID_JWT_AUDIENCE`]. The key comes from the DID itself, so verification
//! needs no JWKS and no network.
//!
//! `aud` is one fixed shadi-wide constant, not a per-verifier setting. The issuing
//! side must set the same value, and every verifier checks it exactly.
//!
//! SLIM learns only that the peer holds the key for its DID. Which DIDs may connect
//! is decided by the verifier's policy: any `did:key`, or an explicit allow-list.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde_json::Value;
use slim_auth::errors::AuthError;
use slim_auth::traits::Verifier;

use crate::config::DEFAULT_TOKEN_TTL;
use crate::{parse_did_key, IdentityError};

/// The fixed `aud` of every shadi SLIM DID-JWT.
///
/// The provider must set `aud` to exactly this value, and every [`DidKeyVerifier`]
/// requires it. It is a domain-separation tag, not a recipient binding: SLIM's
/// `TokenProvider::get_token` takes no recipient, so one token minted per local app
/// is presented to every peer. A DID-JWT minted for anything else is not accepted as
/// a shadi SLIM credential. Bump the `/v1` suffix if the token format changes
/// incompatibly.
pub const DID_JWT_AUDIENCE: &str = "shadi-slim-did-jwt/v1";

/// Clock skew tolerated on `exp`, `iat` and `nbf`, in seconds.
const CLOCK_SKEW_SECS: u64 = 30;

/// Longest accepted `exp - iat`: the default DID-JWT TTL plus the clock skew.
const MAX_TOKEN_LIFETIME_SECS: u64 = DEFAULT_TOKEN_TTL.as_secs() + CLOCK_SKEW_SECS;

/// Which DIDs the verifier admits. Every admitted DID must still prove its key.
#[derive(Debug, Clone)]
enum Policy {
    /// Any `did:key` whose token verifies against the key in that DID.
    AnyDidKey,
    /// Only these DIDs.
    AllowList(BTreeSet<String>),
}

/// SLIM [`Verifier`] that admits `did:key` holders by checking their DID-JWT signature.
///
/// Build it with [`DidKeyVerifier::any_did_key`] or [`DidKeyVerifier::allow_list`].
/// Both return a `Result`, because construction validates the audience, and both
/// require `aud` to equal [`DID_JWT_AUDIENCE`].
#[derive(Debug, Clone)]
pub struct DidKeyVerifier {
    policy: Policy,
    /// Exact value the token's `aud` claim must equal.
    audience: String,
}

/// A token that passed every check, with what the trait methods read from it.
struct Verified {
    sub: String,
    pubkey: Vec<u8>,
    claims: Value,
}

impl DidKeyVerifier {
    /// Admit any `did:key` holder whose token verifies against its own DID and whose
    /// `aud` is [`DID_JWT_AUDIENCE`].
    ///
    /// Returns `Err` if construction rejects the audience. [`DID_JWT_AUDIENCE`] is
    /// non-empty, so this does not happen in practice.
    pub fn any_did_key() -> Result<Self, IdentityError> {
        Self::new(Policy::AnyDidKey, DID_JWT_AUDIENCE)
    }

    /// Admit only the given DIDs. Each must be a valid Ed25519 `did:key`, so a bad
    /// entry fails here instead of silently admitting nobody. Tokens must also carry
    /// `aud` equal to [`DID_JWT_AUDIENCE`].
    pub fn allow_list<'a, I>(dids: I) -> Result<Self, IdentityError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut allowed = BTreeSet::new();
        for did in dids {
            parse_did_key(did)?;
            allowed.insert(did.to_string());
        }
        Self::new(Policy::AllowList(allowed), DID_JWT_AUDIENCE)
    }

    /// The public key carried by a token that passes every check. Synchronous for the
    /// custom-identity adapter in `auth.rs`, whose callbacks cannot await; the trait
    /// method [`Verifier::get_public_key`] delegates here.
    pub(crate) fn public_key_of(&self, token: &str) -> Result<Vec<u8>, AuthError> {
        Ok(self.check(token)?.pubkey)
    }

    /// A verifier that requires `aud` to equal `audience`. The public constructors
    /// pass [`DID_JWT_AUDIENCE`]; tests pass other values to show a mismatch is rejected.
    /// An empty or whitespace-only audience is rejected as a misconfiguration.
    fn new(policy: Policy, audience: impl Into<String>) -> Result<Self, IdentityError> {
        let audience = audience.into();
        if audience.trim().is_empty() {
            return Err(IdentityError::Config(
                "verifier audience cannot be empty".to_string(),
            ));
        }
        Ok(Self { policy, audience })
    }

    /// Verify a DID-JWT and return its parts. Every rejection goes through here, so
    /// no trait method can return claims from a token that failed a check.
    fn check(&self, token: &str) -> Result<Verified, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        let [header_b64, payload_b64, signature_b64] = parts[..] else {
            return Err(reject("token is not a three-part JWS"));
        };

        let header: Value = serde_json::from_slice(&decode_part(header_b64, "header")?)
            .map_err(|e| reject(format!("bad JWT header: {e}")))?;
        if header["alg"].as_str() != Some("EdDSA") {
            return Err(reject(format!(
                "unsupported alg {}, only EdDSA is accepted",
                header["alg"]
            )));
        }

        let claims: Value = serde_json::from_slice(&decode_part(payload_b64, "payload")?)
            .map_err(|e| reject(format!("bad JWT payload: {e}")))?;
        let sub = claims["sub"]
            .as_str()
            .ok_or_else(|| reject("missing sub"))?;
        let iss = claims["iss"]
            .as_str()
            .ok_or_else(|| reject("missing iss"))?;
        if iss != sub {
            return Err(reject(format!("iss ({iss}) differs from sub ({sub})")));
        }
        let key: VerifyingKey = parse_did_key(sub)
            .map_err(|e| reject(format!("sub is not an Ed25519 did:key: {e}")))?;
        if let Policy::AllowList(allowed) = &self.policy {
            if !allowed.contains(sub) {
                return Err(reject(format!("{sub} is not on the allow-list")));
            }
        }

        // The claim checks run before the signature check. They are cheap, so a
        // token that fails them costs no Ed25519 verification, and none of them
        // reveals anything the sender did not already put in the token.

        // `aud` comes first, so a token from the other admission mode fails on
        // its audience, whatever its lifetime. `aud` must be a JSON string exactly
        // equal to the verifier's audience (`DID_JWT_AUDIENCE` from the public
        // constructors). A missing, non-string (including an array) or different
        // value is rejected.
        match claims.get("aud") {
            None => return Err(reject("missing aud")),
            Some(Value::String(aud)) if *aud == self.audience => {}
            Some(Value::String(_)) => {
                return Err(reject("aud does not match the expected audience"))
            }
            Some(_) => return Err(reject("aud must be a string")),
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let exp = claims["exp"]
            .as_u64()
            .ok_or_else(|| reject("missing or invalid exp"))?;
        let iat = claims["iat"]
            .as_u64()
            .ok_or_else(|| reject("missing or invalid iat"))?;
        if now > exp.saturating_add(CLOCK_SKEW_SECS) {
            return Err(reject("token expired"));
        }
        if iat > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(reject("iat is in the future"));
        }
        if let Some(nbf) = claims.get("nbf") {
            let nbf = nbf.as_u64().ok_or_else(|| reject("invalid nbf"))?;
            if nbf > now.saturating_add(CLOCK_SKEW_SECS) {
                return Err(reject("token is not valid yet"));
            }
        }
        let lifetime = exp
            .checked_sub(iat)
            .ok_or_else(|| reject("exp is before iat"))?;
        if lifetime > MAX_TOKEN_LIFETIME_SECS {
            return Err(reject(format!(
                "token lifetime {lifetime}s exceeds the {MAX_TOKEN_LIFETIME_SECS}s bound"
            )));
        }

        // The key comes from the DID, so a valid signature proves the holder has it.
        // The signing input is the header and payload exactly as received.
        let signature = Signature::from_slice(&decode_part(signature_b64, "signature")?)
            .map_err(|e| reject(format!("bad signature encoding: {e}")))?;
        key.verify_strict(format!("{header_b64}.{payload_b64}").as_bytes(), &signature)
            .map_err(|_| reject("signature does not verify against the key in the DID"))?;

        let pubkey_b64 = claims["pubkey"]
            .as_str()
            .ok_or_else(|| reject("missing pubkey claim"))?;
        let pubkey = STANDARD
            .decode(pubkey_b64)
            .map_err(|e| reject(format!("bad base64 in pubkey claim: {e}")))?;
        if pubkey.is_empty() {
            return Err(reject("empty pubkey claim"));
        }

        Ok(Verified {
            sub: sub.to_string(),
            pubkey,
            claims,
        })
    }
}

/// Decode one base64url segment of a JWT.
fn decode_part(part: &str, what: &str) -> Result<Vec<u8>, AuthError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| reject(format!("bad base64url in {what}: {e}")))
}

/// A rejected token, as SLIM's auth error carrying the reason.
fn reject(reason: impl AsRef<str>) -> AuthError {
    AuthError::Custom(format!("DID-JWT rejected: {}", reason.as_ref()))
}

impl Verifier for DidKeyVerifier {
    async fn initialize(&mut self) -> Result<(), AuthError> {
        // Keys come from the DIDs in each token, so there is nothing to fetch.
        Ok(())
    }

    fn verify(&self, token: impl AsRef<str>) -> Result<(), AuthError> {
        self.check(token.as_ref()).map(|_| ())
    }

    fn get_claims<Claims>(&self, token: impl AsRef<str>) -> Result<Claims, AuthError>
    where
        Claims: DeserializeOwned + Send,
    {
        let verified = self.check(token.as_ref())?;
        Ok(serde_json::from_value(verified.claims)?)
    }

    fn get_subject(&self, token: impl AsRef<str>) -> Result<String, AuthError> {
        Ok(self.check(token.as_ref())?.sub)
    }

    fn verify_key_binding(
        &self,
        token: impl AsRef<str>,
        public_key: &[u8],
    ) -> Result<(), AuthError> {
        let verified = self.check(token.as_ref())?;
        if verified.pubkey == public_key {
            return Ok(());
        }
        Err(AuthError::PublicKeyMismatch {
            subject: verified.sub,
            expected: STANDARD.encode(public_key),
            found: STANDARD.encode(&verified.pubkey),
        })
    }

    async fn get_public_key(&self, token: impl AsRef<str> + Send) -> Result<Vec<u8>, AuthError> {
        self.public_key_of(token.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentIdentity;
    use serde_json::json;

    /// A verifier that admits any `did:key` whose `aud` is [`DID_JWT_AUDIENCE`].
    fn any_verifier() -> DidKeyVerifier {
        DidKeyVerifier::any_did_key().unwrap()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Sign `header.payload` with `signer`, the way a DID-JWT provider does.
    fn mint_with(signer: &AgentIdentity, header: Value, claims: Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(header.to_string());
        let p = URL_SAFE_NO_PAD.encode(claims.to_string());
        let sig = signer.sign_bytes(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn eddsa_header() -> Value {
        json!({ "alg": "EdDSA", "typ": "JWT" })
    }

    /// Claims for a token `did` issues about itself, valid from `iat` to `exp`,
    /// with `aud` set to [`DID_JWT_AUDIENCE`].
    fn claims_for(did: &str, iat: u64, exp: u64) -> Value {
        json!({
            "iss": did,
            "sub": did,
            "aud": DID_JWT_AUDIENCE,
            "iat": iat,
            "nbf": iat,
            "exp": exp,
            "pubkey": STANDARD.encode([7u8; 32]),
        })
    }

    /// A token `id` signs about itself, issued now for the default TTL.
    fn valid_token(id: &AgentIdentity) -> String {
        let t = now();
        mint_with(
            id,
            eddsa_header(),
            claims_for(&id.did(), t, t + DEFAULT_TOKEN_TTL.as_secs()),
        )
    }

    /// The rejection reason, panicking if the token was accepted.
    fn reason<T>(result: Result<T, AuthError>) -> String {
        match result {
            Ok(_) => panic!("token was accepted"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn accepts_valid_token_and_reports_its_subject() {
        let id = AgentIdentity::generate().unwrap();
        let v = any_verifier();
        let token = valid_token(&id);
        assert!(v.verify(&token).is_ok());
        assert_eq!(v.get_subject(&token).unwrap(), id.did());
    }

    #[test]
    fn rejects_token_signed_by_another_key() {
        let id = AgentIdentity::generate().unwrap();
        let other = AgentIdentity::generate().unwrap();
        let t = now();
        // Claims name `id`, but only `other`'s key signed them.
        let token = mint_with(
            &other,
            eddsa_header(),
            claims_for(&id.did(), t, t + DEFAULT_TOKEN_TTL.as_secs()),
        );
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("signature"), "{msg}");
    }

    #[test]
    fn rejects_tampered_payload() {
        let id = AgentIdentity::generate().unwrap();
        let token = valid_token(&id);
        let t = now();
        let mut forged = claims_for(&id.did(), t, t + DEFAULT_TOKEN_TTL.as_secs());
        forged["pubkey"] = json!(STANDARD.encode([9u8; 32]));
        let forged_payload = URL_SAFE_NO_PAD.encode(forged.to_string());
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = forged_payload.as_str();
        let tampered = parts.join(".");
        let msg = reason(any_verifier().verify(&tampered));
        assert!(msg.contains("signature"), "{msg}");
    }

    #[test]
    fn rejects_expired_token() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        // Within the TTL, but expired well beyond the clock skew.
        let token = mint_with(&id, eddsa_header(), claims_for(&id.did(), t - 400, t - 100));
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("expired"), "{msg}");
    }

    #[test]
    fn accepts_times_within_clock_skew() {
        let id = AgentIdentity::generate().unwrap();
        let v = any_verifier();
        let t = now();
        // Issued 20 s in the future: inside the 30 s skew.
        let future = mint_with(&id, eddsa_header(), claims_for(&id.did(), t + 20, t + 320));
        assert!(v.verify(&future).is_ok());
        // Expired 10 s ago: inside the 30 s skew.
        let just_expired = mint_with(&id, eddsa_header(), claims_for(&id.did(), t - 310, t - 10));
        assert!(v.verify(&just_expired).is_ok());
    }

    #[test]
    fn rejects_token_lifetime_beyond_ttl_plus_skew() {
        let id = AgentIdentity::generate().unwrap();
        let v = any_verifier();
        let t = now();
        let ttl = DEFAULT_TOKEN_TTL.as_secs();
        // Exactly TTL + 30 s is the longest accepted lifetime.
        let at_bound = mint_with(&id, eddsa_header(), claims_for(&id.did(), t, t + ttl + 30));
        assert!(v.verify(&at_bound).is_ok());
        // One second more is rejected.
        let beyond = mint_with(&id, eddsa_header(), claims_for(&id.did(), t, t + ttl + 31));
        let msg = reason(v.verify(&beyond));
        assert!(msg.contains("lifetime"), "{msg}");
    }

    #[test]
    fn rejects_iat_or_nbf_beyond_clock_skew() {
        let id = AgentIdentity::generate().unwrap();
        let v = any_verifier();
        let t = now();
        let iat_future = mint_with(&id, eddsa_header(), claims_for(&id.did(), t + 60, t + 360));
        let msg = reason(v.verify(&iat_future));
        assert!(msg.contains("iat"), "{msg}");

        let mut claims = claims_for(&id.did(), t, t + 300);
        claims["nbf"] = json!(t + 60);
        let nbf_future = mint_with(&id, eddsa_header(), claims);
        let msg = reason(v.verify(&nbf_future));
        assert!(msg.contains("not valid yet"), "{msg}");
    }

    #[test]
    fn rejects_non_did_key_subject() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        let mut claims = claims_for(&id.did(), t, t + 300);
        claims["sub"] = json!("did:web:example.com");
        claims["iss"] = json!("did:web:example.com");
        let token = mint_with(&id, eddsa_header(), claims);
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("did:key"), "{msg}");
    }

    #[test]
    fn rejects_non_eddsa_algorithms() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        let claims = claims_for(&id.did(), t, t + 300);
        let v = any_verifier();
        for alg in ["HS256", "ES256", "eddsa"] {
            let token = mint_with(&id, json!({ "alg": alg }), claims.clone());
            let msg = reason(v.verify(&token));
            assert!(msg.contains("unsupported alg"), "{alg}: {msg}");
        }
        // `alg=none` with no signature at all must never pass.
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(json!({ "alg": "none" }).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        let msg = reason(v.verify(&unsigned));
        assert!(msg.contains("unsupported alg"), "none: {msg}");
    }

    #[test]
    fn rejects_malformed_tokens() {
        let v = any_verifier();
        for token in ["", "a.b", "a.b.c.d", "!.!.!"] {
            assert!(v.verify(token).is_err(), "accepted {token:?}");
        }
    }

    #[test]
    fn rejects_missing_or_invalid_claims() {
        let id = AgentIdentity::generate().unwrap();
        let did = id.did();
        let t = now();
        let v = any_verifier();
        for field in ["sub", "iss", "aud", "iat", "exp", "pubkey"] {
            let mut claims = claims_for(&did, t, t + 300);
            claims.as_object_mut().unwrap().remove(field);
            let token = mint_with(&id, eddsa_header(), claims);
            assert!(
                v.verify(&token).is_err(),
                "accepted a token without {field}"
            );
        }
        let mut claims = claims_for(&did, t, t + 300);
        claims["pubkey"] = json!("");
        let token = mint_with(&id, eddsa_header(), claims);
        assert!(v.verify(&token).is_err(), "accepted an empty pubkey");
        let mut claims = claims_for(&did, t, t + 300);
        claims["aud"] = json!("wrong-audience");
        let token = mint_with(&id, eddsa_header(), claims);
        assert!(v.verify(&token).is_err(), "accepted a wrong aud");
    }

    #[test]
    fn allow_list_admits_only_listed_dids() {
        let a = AgentIdentity::generate().unwrap();
        let b = AgentIdentity::generate().unwrap();
        let v = DidKeyVerifier::allow_list([a.did().as_str()]).unwrap();
        assert!(v.verify(valid_token(&a)).is_ok());
        let msg = reason(v.verify(valid_token(&b)));
        assert!(msg.contains("allow-list"), "{msg}");
    }

    #[test]
    fn allow_list_rejects_malformed_did() {
        assert!(DidKeyVerifier::allow_list(["did:web:nope"]).is_err());
    }

    #[test]
    fn public_constructors_accept_did_jwt_audience() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        let token = mint_with(&id, eddsa_header(), claims_for(&id.did(), t, t + 300));
        assert!(any_verifier().verify(&token).is_ok());
        let v = DidKeyVerifier::allow_list([id.did().as_str()]).unwrap();
        assert!(v.verify(&token).is_ok());
    }

    #[test]
    fn public_constructors_reject_other_audience() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        let mut claims = claims_for(&id.did(), t, t + 300);
        claims["aud"] = json!("some-other-audience");
        let token = mint_with(&id, eddsa_header(), claims);
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("does not match"), "{msg}");
        let v = DidKeyVerifier::allow_list([id.did().as_str()]).unwrap();
        let msg = reason(v.verify(&token));
        assert!(msg.contains("does not match"), "{msg}");
    }

    #[test]
    fn verifier_for_another_audience_rejects_did_jwt_audience() {
        let id = AgentIdentity::generate().unwrap();
        let v = DidKeyVerifier::new(Policy::AnyDidKey, "shadi-test-audience").unwrap();
        let msg = reason(v.verify(valid_token(&id)));
        assert!(msg.contains("does not match"), "{msg}");
    }

    #[test]
    fn rejects_empty_or_blank_audience() {
        for aud in ["", "   "] {
            match DidKeyVerifier::new(Policy::AnyDidKey, aud) {
                Err(IdentityError::Config(msg)) => {
                    assert_eq!(msg, "verifier audience cannot be empty", "{aud:?}");
                }
                other => panic!("accepted audience {aud:?}: {other:?}"),
            }
        }
        // The public path uses a non-empty constant, so it must still construct.
        assert!(DidKeyVerifier::any_did_key().is_ok());
    }

    #[test]
    fn did_jwt_audience_is_the_versioned_constant() {
        // A silent change would break every peer's tokens, so it must be deliberate.
        assert_eq!(DID_JWT_AUDIENCE, "shadi-slim-did-jwt/v1");
    }

    #[test]
    fn rejects_missing_aud() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        let mut claims = claims_for(&id.did(), t, t + 300);
        claims.as_object_mut().unwrap().remove("aud");
        let token = mint_with(&id, eddsa_header(), claims);
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("missing aud"), "{msg}");
    }

    #[test]
    fn rejects_different_aud() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        let mut claims = claims_for(&id.did(), t, t + 300);
        claims["aud"] = json!("some-other-audience");
        let token = mint_with(&id, eddsa_header(), claims);
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("does not match"), "{msg}");
        // Exact match only: a prefix, another version, a different case or trailing
        // whitespace is a different audience.
        for aud in [
            "shadi-slim-did-jwt",
            "shadi-slim-did-jwt/v2",
            "SHADI-SLIM-DID-JWT/V1",
            "shadi-slim-did-jwt/v1 ",
        ] {
            let mut claims = claims_for(&id.did(), t, t + 300);
            claims["aud"] = json!(aud);
            let token = mint_with(&id, eddsa_header(), claims);
            let msg = reason(any_verifier().verify(&token));
            assert!(msg.contains("does not match"), "{aud:?}: {msg}");
        }
    }

    #[test]
    fn rejects_non_string_aud() {
        let id = AgentIdentity::generate().unwrap();
        let t = now();
        for aud in [
            json!([DID_JWT_AUDIENCE]),
            json!(["other", DID_JWT_AUDIENCE]),
            json!(null),
            json!(42),
        ] {
            let mut claims = claims_for(&id.did(), t, t + 300);
            claims["aud"] = aud.clone();
            let token = mint_with(&id, eddsa_header(), claims);
            let msg = reason(any_verifier().verify(&token));
            assert!(msg.contains("aud must be a string"), "{aud}: {msg}");
        }
    }

    #[test]
    fn claim_checks_run_before_the_signature_check() {
        let id = AgentIdentity::generate().unwrap();
        let other = AgentIdentity::generate().unwrap();
        let t = now();

        // A closed-mode (stock signer) token: no `aud`, and a lifetime past the
        // bound. It must fail on `aud`, not on its lifetime or its signature.
        let mut claims = claims_for(&id.did(), t, t + 3600);
        claims.as_object_mut().unwrap().remove("aud");
        let token = mint_with(&other, eddsa_header(), claims);
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("missing aud"), "{msg}");

        // An expired token with a bad signature fails on the time check.
        let token = mint_with(
            &other,
            eddsa_header(),
            claims_for(&id.did(), t - 400, t - 100),
        );
        let msg = reason(any_verifier().verify(&token));
        assert!(msg.contains("expired"), "{msg}");
    }

    #[test]
    fn verify_key_binding_checks_pubkey_claim() {
        let id = AgentIdentity::generate().unwrap();
        let v = any_verifier();
        let token = valid_token(&id);
        // `claims_for` embeds the 32-byte key [7; 32].
        assert!(v.verify_key_binding(&token, &[7u8; 32]).is_ok());
        assert!(matches!(
            v.verify_key_binding(&token, &[8u8; 32]),
            Err(AuthError::PublicKeyMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn get_public_key_and_claims_come_from_the_verified_token() {
        let id = AgentIdentity::generate().unwrap();
        let v = any_verifier();
        let token = valid_token(&id);
        assert_eq!(v.get_public_key(&token).await.unwrap(), vec![7u8; 32]);
        let claims: Value = v.get_claims(&token).unwrap();
        assert_eq!(claims["sub"], id.did());
        assert_eq!(claims["iss"], id.did());
    }
}
