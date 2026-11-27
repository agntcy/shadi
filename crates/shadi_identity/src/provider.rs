// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! [`DidKeyProvider`]: SLIM's [`TokenProvider`] for a local `did:key` identity.
//!
//! Every token is a DID-JWT that [`DidKeyVerifier`](crate::DidKeyVerifier) accepts:
//! an `EdDSA` JWT whose `iss` and `sub` are the identity's `did:key`, signed by that
//! DID's Ed25519 key, with `aud` set to [`DID_JWT_AUDIENCE`]. Tokens are minted fresh
//! on each call and are never cached.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::json;
use slim_auth::errors::AuthError;
use slim_auth::traits::TokenProvider;
use slim_auth::utils::generate_mls_signature_keys;

use crate::config::DEFAULT_TOKEN_TTL;
use crate::verifier::DID_JWT_AUDIENCE;
use crate::{AgentIdentity, IdentityError};

/// SLIM [`TokenProvider`] that proves a local `did:key` identity by signing DID-JWTs.
///
/// The DID-JWT is signed with the identity's Ed25519 key, which the `did:key` names.
/// The `pubkey` claim carries the MLS signature public key from
/// [`TokenProvider::get_signature_keys`], not the DID key. SLIM checks control
/// messages with the key in `pubkey`, and MLS signs with the MLS key. The DID-JWT
/// signature, made with the DID key, binds that MLS key to the DID. This is the same
/// layout SLIM's stock JWT signer emits.
pub struct DidKeyProvider {
    identity: AgentIdentity,
    /// MLS signature key pair `(secret, public)`. The public half goes in `pubkey`.
    signature_keys: (Vec<u8>, Vec<u8>),
}

impl DidKeyProvider {
    /// Build a provider for `identity`, generating its MLS signature key pair.
    ///
    /// The MLS keys come from SLIM's generator for the active MLS ciphersuite, so they
    /// are installed from the start, as SLIM's stock signer does. MLS may replace them
    /// later through [`TokenProvider::set_signature_keys`].
    pub fn new(identity: AgentIdentity) -> Result<Self, IdentityError> {
        let signature_keys =
            generate_mls_signature_keys().map_err(|e| IdentityError::KeyGen(e.to_string()))?;
        Ok(Self {
            identity,
            signature_keys,
        })
    }

    /// Install the MLS signature key pair, as [`TokenProvider::set_signature_keys`]
    /// does. Synchronous for the custom-identity adapter in `auth.rs`, whose
    /// callbacks cannot await; the trait method delegates here.
    pub(crate) fn install_signature_keys(&mut self, private_key: Vec<u8>, public_key: Vec<u8>) {
        self.signature_keys = (private_key, public_key);
    }

    /// Mint a DID-JWT whose `iat` and `nbf` are `now` (seconds since the Unix epoch).
    fn mint_at(&self, now: u64) -> String {
        let did = self.identity.did();
        let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": did });
        let claims = json!({
            "iss": did,
            "sub": did,
            "aud": DID_JWT_AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + DEFAULT_TOKEN_TTL.as_secs(),
            "pubkey": STANDARD.encode(&self.signature_keys.1),
        });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        let signature = self.identity.sign_bytes(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

impl Clone for DidKeyProvider {
    /// Clones copy the identity's key and the MLS key pair. Each clone then holds its
    /// own MLS keys, as with SLIM's stock signer.
    fn clone(&self) -> Self {
        Self {
            identity: AgentIdentity::from_signing_key_bytes(&self.identity.signing_key_bytes()),
            signature_keys: self.signature_keys.clone(),
        }
    }
}

impl TokenProvider for DidKeyProvider {
    async fn initialize(&mut self) -> Result<(), AuthError> {
        // Nothing to set up: the key pair is local and the tokens are self-signed.
        Ok(())
    }

    fn get_token(&self) -> Result<String, AuthError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(self.mint_at(now))
    }

    fn get_id(&self) -> Result<String, AuthError> {
        Ok(self.identity.did())
    }

    fn get_signature_keys(&self) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        Ok(self.signature_keys.clone())
    }

    fn mls_signature_keys_installed(&self) -> Result<bool, AuthError> {
        // Same rule as SLIM's stock signer: the keys are present from construction,
        // and an empty secret means none are installed.
        Ok(!self.signature_keys.0.is_empty())
    }

    async fn set_signature_keys(
        &mut self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), AuthError> {
        self.install_signature_keys(private_key, public_key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks_from_dids;
    use crate::verifier::DidKeyVerifier;
    use ed25519_dalek::{Signature, VerifyingKey};
    use serde_json::Value;
    use slim_auth::traits::Verifier;
    use std::collections::BTreeSet;
    use std::time::Duration;

    fn provider() -> DidKeyProvider {
        DidKeyProvider::new(AgentIdentity::generate().unwrap()).unwrap()
    }

    fn any_verifier() -> DidKeyVerifier {
        DidKeyVerifier::any_did_key().unwrap()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn split_token(token: &str) -> [&str; 3] {
        let parts: Vec<&str> = token.split('.').collect();
        parts.try_into().expect("a JWT has three segments")
    }

    fn decode_segment(segment: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    fn payload_of(token: &str) -> Value {
        decode_segment(split_token(token)[1])
    }

    fn keys_of(value: &Value) -> BTreeSet<&str> {
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn get_id_is_the_did_key_and_clones_match() {
        let id = AgentIdentity::generate().unwrap();
        let did = id.did();
        let p = DidKeyProvider::new(id).unwrap();
        assert_eq!(p.get_id().unwrap(), did);
        let q = p.clone();
        assert_eq!(q.get_id().unwrap(), did);
        assert_eq!(
            q.get_signature_keys().unwrap(),
            p.get_signature_keys().unwrap()
        );
    }

    #[tokio::test]
    async fn initialize_is_a_noop_and_mls_keys_are_installed() {
        let mut p = provider();
        assert!(p.initialize().await.is_ok());
        assert!(p.mls_signature_keys_installed().unwrap());
        let (secret, public) = p.get_signature_keys().unwrap();
        assert!(!secret.is_empty() && !public.is_empty());
    }

    #[test]
    fn get_token_reads_the_clock_and_re_signs() {
        let p = provider();
        let before = now();
        let token = p.get_token().unwrap();
        let after = now();
        let iat = payload_of(&token)["iat"].as_u64().unwrap();
        assert!(
            before <= iat && iat <= after,
            "iat {iat} outside {before}..={after}"
        );

        // Signing is deterministic, so a token changes exactly when its claims do.
        assert_ne!(p.mint_at(iat), p.mint_at(iat + 1));
        assert_eq!(p.mint_at(iat), p.mint_at(iat));
    }

    #[test]
    fn consecutive_tokens_differ_once_the_clock_moves() {
        // `iat` has one-second resolution, so wait past a tick before the second call.
        let p = provider();
        let first = p.get_token().unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let second = p.get_token().unwrap();
        assert_ne!(first, second);
        assert!(
            payload_of(&second)["iat"].as_u64().unwrap()
                > payload_of(&first)["iat"].as_u64().unwrap()
        );
    }

    #[test]
    fn token_carries_exactly_the_documented_claims() {
        let id = AgentIdentity::generate().unwrap();
        let did = id.did();
        let p = DidKeyProvider::new(id).unwrap();
        let token = p.get_token().unwrap();
        let [header_b64, claims_b64, _] = split_token(&token);
        let header = decode_segment(header_b64);
        let claims = decode_segment(claims_b64);

        assert_eq!(keys_of(&header), BTreeSet::from(["alg", "typ", "kid"]));
        assert_eq!(
            keys_of(&claims),
            BTreeSet::from(["iss", "sub", "aud", "iat", "nbf", "exp", "pubkey"])
        );

        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], did);
        assert_eq!(claims["iss"], did);
        assert_eq!(claims["sub"], did);
        assert_eq!(claims["aud"], DID_JWT_AUDIENCE);
        assert_eq!(claims["iat"], claims["nbf"]);
        let iat = claims["iat"].as_u64().unwrap();
        assert_eq!(
            claims["exp"].as_u64().unwrap() - iat,
            DEFAULT_TOKEN_TTL.as_secs()
        );
        assert_eq!(
            claims["pubkey"].as_str().unwrap(),
            STANDARD.encode(p.get_signature_keys().unwrap().1)
        );
    }

    #[tokio::test]
    async fn any_did_key_verifier_accepts_the_token() {
        let p = provider();
        let token = p.get_token().unwrap();
        let v = any_verifier();
        assert!(v.verify(&token).is_ok());
        assert_eq!(v.get_subject(&token).unwrap(), p.get_id().unwrap());
        assert_eq!(
            v.get_public_key(&token).await.unwrap(),
            p.get_signature_keys().unwrap().1
        );
    }

    #[test]
    fn allow_list_with_its_own_did_accepts_the_token() {
        let id = AgentIdentity::generate().unwrap();
        let did = id.did();
        let p = DidKeyProvider::new(id).unwrap();
        let token = p.get_token().unwrap();
        let v = DidKeyVerifier::allow_list([did.as_str()]).unwrap();
        assert!(v.verify(&token).is_ok());
    }

    #[test]
    fn allow_list_excluding_its_did_rejects_the_token() {
        let p = provider();
        let token = p.get_token().unwrap();
        let other = AgentIdentity::generate().unwrap().did();
        let v = DidKeyVerifier::allow_list([other.as_str()]).unwrap();
        let err = v.verify(&token).unwrap_err().to_string();
        assert!(err.contains("allow-list"), "{err}");
    }

    #[tokio::test]
    async fn verify_key_binding_accepts_only_the_mls_key() {
        let p = provider();
        let token = p.get_token().unwrap();
        let mls_public = p.get_signature_keys().unwrap().1;
        let v = any_verifier();
        assert!(v.verify_key_binding(&token, &mls_public).is_ok());
        assert!(matches!(
            v.verify_key_binding(&token, &[0u8; 32]),
            Err(AuthError::PublicKeyMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn set_signature_keys_changes_the_pubkey_claim_on_the_next_token() {
        let mut p = provider();
        let (new_secret, new_public) = (vec![1u8; 32], vec![2u8; 32]);
        p.set_signature_keys(new_secret.clone(), new_public.clone())
            .await
            .unwrap();
        assert_eq!(
            p.get_signature_keys().unwrap(),
            (new_secret, new_public.clone())
        );
        assert!(p.mls_signature_keys_installed().unwrap());

        // No token is cached: the next one already names the new key.
        let token = p.get_token().unwrap();
        assert_eq!(payload_of(&token)["pubkey"], STANDARD.encode(&new_public));
        assert_eq!(
            any_verifier().get_public_key(&token).await.unwrap(),
            new_public
        );
    }

    #[test]
    fn stock_jwks_style_verifier_accepts_the_token() {
        // Stand-in for a stock JWKS verifier: it has only the JWKS of trusted DIDs,
        // picks the key by `kid`, checks the signature, then the registered claims.
        // This uses ed25519-dalek directly; jsonwebtoken is not a direct dependency.
        let p = provider();
        let did = p.get_id().unwrap();
        let token = p.get_token().unwrap();
        let [header_b64, claims_b64, signature_b64] = split_token(&token);
        let header = decode_segment(header_b64);

        let jwks: Value = serde_json::from_str(&jwks_from_dids([did.as_str()]).unwrap()).unwrap();
        let jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == header["kid"])
            .expect("no JWKS entry for the token's kid");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(header["alg"], jwk["alg"]);

        let x: [u8; 32] = URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let key = VerifyingKey::from_bytes(&x).unwrap();
        let sig: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .unwrap()
            .try_into()
            .unwrap();
        key.verify_strict(
            format!("{header_b64}.{claims_b64}").as_bytes(),
            &Signature::from_bytes(&sig),
        )
        .expect("signature must verify against the JWKS key");

        let claims = decode_segment(claims_b64);
        let now = now();
        assert_eq!(claims["iss"], did);
        assert_eq!(claims["sub"], did);
        assert_eq!(claims["aud"], DID_JWT_AUDIENCE);
        assert!(claims["iat"].as_u64().unwrap() <= now);
        assert!(claims["nbf"].as_u64().unwrap() <= now);
        assert!(claims["exp"].as_u64().unwrap() > now);
    }
}
