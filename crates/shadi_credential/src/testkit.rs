// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SD-JWT fixtures shared by the crate's tests.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shadi_identity::AgentIdentity;

#[cfg(test)]
use crate::sd_jwt::{import, parse_sd_jwt};
#[cfg(test)]
use crate::vault::tests::sqlcipher_vault;
#[cfg(test)]
use crate::Selection;

pub const ISS: &str = "https://idp.example/realms/eng";
pub const NOW: i64 = 1_700_000_000;

pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

pub fn disclosure(name: &str, value: impl Into<Value>) -> String {
    let value: Value = value.into();
    b64(json!(["c2FsdA", name, value]).to_string())
}

pub fn base_header() -> Value {
    json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": "k1"})
}

pub fn base_claims(holder: &AgentIdentity, discs: &[String]) -> Value {
    let sd: Vec<String> = discs
        .iter()
        .map(|d| b64(Sha256::digest(d.as_bytes())))
        .collect();
    json!({
        "iss": ISS,
        "vct": "urn:shadi:agent-admission:1",
        "exp": NOW + 3_600,
        "cnf": { "jwk": holder.public_jwk() },
        "_sd_alg": "sha-256",
        "_sd": sd,
    })
}

/// A signed credential: issuer JWT, `discs`, trailing tilde.
pub fn credential(key: &SigningKey, header: &Value, claims: &Value, discs: &[String]) -> String {
    let input = format!("{}.{}", b64(header.to_string()), b64(claims.to_string()));
    let mut raw = format!("{input}.{}", b64(key.sign(input.as_bytes()).to_bytes()));
    for d in discs {
        raw.push('~');
        raw.push_str(d);
    }
    raw.push('~');
    raw
}

/// `cred` imported, with its first `take` disclosures chosen.
#[cfg(test)]
pub(crate) fn selection(cred: &str, take: usize) -> Selection {
    Selection {
        record: import(&sqlcipher_vault(), cred, 1_000).unwrap(),
        disclosures: parse_sd_jwt(cred).unwrap().disclosures[..take].to_vec(),
    }
}

/// The holder answers with the first `take` disclosures, via the real builder.
#[cfg(test)]
pub(crate) fn present_n(
    holder: &AgentIdentity,
    cred: &str,
    take: usize,
    nonce: &str,
    aud: &str,
    iat: i64,
) -> String {
    crate::presentation::build(holder, &selection(cred, take), nonce, aud, iat).unwrap()
}
