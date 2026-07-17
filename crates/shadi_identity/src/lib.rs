// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SHADI DID identity primitives.
//!
//! Ed25519 agent identities expressed as `did:key`, with the key material and
//! encodings SLIM's JWT identity layer needs:
//! - PKCS#8 PEM private key (signer / `Encoding` key),
//! - JWK / JWKS public keys (verifier / `Decoding` key set = the DID allow-list).
//!
//! Only `did:key` with Ed25519 is supported (per the DID design note).

use std::fmt;

use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::LineEnding;

pub mod config;

/// Multicodec prefix for an Ed25519 public key (`0xed` varint-encoded).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

#[derive(Debug)]
pub enum IdentityError {
    KeyGen(String),
    Pkcs8(String),
    InvalidDid(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::KeyGen(e) => write!(f, "key generation failed: {e}"),
            IdentityError::Pkcs8(e) => write!(f, "PKCS#8 error: {e}"),
            IdentityError::InvalidDid(e) => write!(f, "invalid did:key: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// An Ed25519 agent identity: the signing key plus its `did:key`.
pub struct AgentIdentity {
    signing_key: SigningKey,
}

impl AgentIdentity {
    /// Generate a fresh Ed25519 identity.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| IdentityError::KeyGen(e.to_string()))?;
        let id = Self {
            signing_key: SigningKey::from_bytes(&seed),
        };
        seed.iter_mut().for_each(|b| *b = 0);
        Ok(id)
    }

    /// Load an identity from a PKCS#8 PEM private key (as stored in the secret store).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, IdentityError> {
        let signing_key =
            SigningKey::from_pkcs8_pem(pem).map_err(|e| IdentityError::Pkcs8(e.to_string()))?;
        Ok(Self { signing_key })
    }

    /// Serialize the private key as PKCS#8 PEM (for storage in the secret store).
    pub fn to_pkcs8_pem(&self) -> Result<String, IdentityError> {
        self.signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// This identity's `did:key`.
    pub fn did(&self) -> String {
        encode_did_key(&self.verifying_key())
    }

    /// This identity's public key as a JWK (`kid` = its did:key).
    pub fn public_jwk(&self) -> serde_json::Value {
        verifying_key_to_jwk(&self.verifying_key(), &self.did())
    }

    /// SLIM identity **provider** config that proves this agent's DID on `channel`
    /// by signing a DID-JWT with its Ed25519 key.
    pub fn provider_config(
        &self,
        channel: &str,
    ) -> Result<slim_bindings::IdentityProviderConfig, IdentityError> {
        Ok(config::did_provider_config(
            &self.to_pkcs8_pem()?,
            &self.did(),
            channel,
        ))
    }
}

/// SLIM identity **verifier** config for `channel` whose trusted-key set is the
/// given member DIDs — the cryptographic allow-list.
pub fn verifier_config_from_dids<'a, I>(
    dids: I,
    channel: &str,
) -> Result<slim_bindings::IdentityVerifierConfig, IdentityError>
where
    I: IntoIterator<Item = &'a str>,
{
    Ok(config::did_verifier_config(&jwks_from_dids(dids)?, channel))
}

/// Encode an Ed25519 public key as a `did:key` (`did:key:z<base58btc(0xed01 || pubkey)>`).
pub fn encode_did_key(vk: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(2 + 32);
    bytes.extend_from_slice(&ED25519_MULTICODEC);
    bytes.extend_from_slice(vk.as_bytes());
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

/// Parse an Ed25519 `did:key` back into its public key.
pub fn parse_did_key(did: &str) -> Result<VerifyingKey, IdentityError> {
    let mb = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| IdentityError::InvalidDid(format!("not a did:key: {did}")))?;
    let decoded = bs58::decode(mb)
        .into_vec()
        .map_err(|e| IdentityError::InvalidDid(format!("base58: {e}")))?;
    if decoded.len() != 2 + 32 || decoded[0..2] != ED25519_MULTICODEC {
        return Err(IdentityError::InvalidDid(
            "not an Ed25519 did:key (bad multicodec or length)".to_string(),
        ));
    }
    let key_bytes: [u8; 32] = decoded[2..]
        .try_into()
        .map_err(|_| IdentityError::InvalidDid("bad key length".to_string()))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| IdentityError::InvalidDid(format!("bad Ed25519 key: {e}")))
}

fn verifying_key_to_jwk(vk: &VerifyingKey, kid: &str) -> serde_json::Value {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.as_bytes());
    serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "kid": kid,
        "x": x,
    })
}

/// Build a JWKS (`{"keys":[...]}`) from a set of `did:key` DIDs — the verifier's
/// trusted-key set, i.e. the cryptographic allow-list. A JWT signed by a DID not
/// in this set has no matching key and fails verification.
pub fn jwks_from_dids<'a, I>(dids: I) -> Result<String, IdentityError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut keys = Vec::new();
    for did in dids {
        let vk = parse_did_key(did)?;
        keys.push(verifying_key_to_jwk(&vk, did));
    }
    Ok(serde_json::json!({ "keys": keys }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_round_trips_through_parse() {
        let id = AgentIdentity::generate().unwrap();
        let did = id.did();
        assert!(did.starts_with("did:key:z"));
        let parsed = parse_did_key(&did).unwrap();
        assert_eq!(parsed.as_bytes(), id.verifying_key().as_bytes());
    }

    #[test]
    fn pkcs8_pem_round_trips() {
        let id = AgentIdentity::generate().unwrap();
        let pem = id.to_pkcs8_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let loaded = AgentIdentity::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(loaded.did(), id.did());
    }

    #[test]
    fn parse_did_key_rejects_non_did_key() {
        assert!(parse_did_key("did:web:example.com").is_err());
        assert!(parse_did_key("did:key:zNOTvalidbase58!!").is_err());
        assert!(parse_did_key("garbage").is_err());
    }

    #[test]
    fn public_jwk_is_okp_ed25519() {
        let id = AgentIdentity::generate().unwrap();
        let jwk = id.public_jwk();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["kid"], id.did());
        assert!(jwk["x"].as_str().unwrap().len() >= 43); // 32 bytes base64url-nopad
    }

    #[test]
    fn jwks_from_dids_collects_member_keys() {
        let a = AgentIdentity::generate().unwrap();
        let b = AgentIdentity::generate().unwrap();
        let jwks: serde_json::Value =
            serde_json::from_str(&jwks_from_dids([a.did().as_str(), b.did().as_str()]).unwrap())
                .unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0]["kid"], a.did());
        assert_eq!(keys[1]["kid"], b.did());
    }

    #[test]
    fn jwks_from_dids_rejects_bad_did() {
        assert!(jwks_from_dids(["did:web:nope"]).is_err());
    }
}
