// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Application-layer DID proof for agentbridge SLIM messages.
//!
//! Node auth (mesh join) is not enough: a member can present another agent's
//! DID unless the payload is bound to the sender's `did:key` by an Ed25519
//! signature. This module is that binding. It does not invent a new identity
//! system — it signs with the existing [`AgentIdentity`] Ed25519 key.

use crate::{parse_did_key, AgentIdentity, IdentityError, SlimAuth};
use base64::Engine as _;
use ed25519_dalek::Signature;

const MAGIC: &[u8] = b"SHADI-DID-PROOF/1";
const DOMAIN: &[u8] = b"SHADI-DID-PROOF/1";

/// Payload plus the `did:key` that signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayload {
    pub did: String,
    pub payload: Vec<u8>,
}

/// True when `bytes` start with the DID-proof envelope header.
pub fn looks_like_did_proof(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC) && bytes.get(MAGIC.len()) == Some(&b'\n')
}

/// Wrap `payload` in a DID-proof envelope signed by `identity`.
pub fn wrap_signed_message(
    identity: &AgentIdentity,
    payload: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let did = identity.did();
    let sig = identity.sign_bytes(&canonical(&did, payload));
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
    let mut out = Vec::with_capacity(MAGIC.len() + did.len() + sig_b64.len() + payload.len() + 4);
    out.extend_from_slice(MAGIC);
    out.push(b'\n');
    out.extend_from_slice(did.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(sig_b64.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    Ok(out)
}

/// Verify a DID-proof envelope and return the bound DID plus the inner payload.
///
/// A mesh member that copies another agent's DID into the header but signs
/// with its own key fails here — the public key is taken from the claimed
/// `did:key`, not from the caller.
pub fn unwrap_signed_message(envelope: &[u8]) -> Result<VerifiedPayload, IdentityError> {
    if !looks_like_did_proof(envelope) {
        return Err(IdentityError::Proof(
            "message is not a DID-proof envelope".to_string(),
        ));
    }
    let (did, sig_b64, payload) = split_envelope(envelope)?;
    if !did.starts_with("did:key:") {
        return Err(IdentityError::Proof(format!(
            "claimed DID is not did:key: {did}"
        )));
    }
    let vk = parse_did_key(&did)?;
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|_| IdentityError::Proof("invalid signature encoding".to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| IdentityError::Proof("signature must be 64 bytes".to_string()))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(&canonical(&did, payload), &sig)
        .map_err(|_| {
            IdentityError::Proof(
                "forged DID: signature does not match the claimed did:key".to_string(),
            )
        })?;
    Ok(VerifiedPayload {
        did,
        payload: payload.to_vec(),
    })
}

/// Sign `payload` with the agent DID derived from the process environment.
///
/// Uses the same `SHADI_SLIM_AUTH=did` / `SLIM_HUMAN_SEED` contract as mesh
/// join. Shared-secret node auth cannot produce an application-layer proof.
pub fn sign_message_from_env(agent_id: &str, payload: &[u8]) -> Result<Vec<u8>, IdentityError> {
    sign_message_with_auth(crate::require_did_auth_from_env(agent_id)?, payload)
}

fn sign_message_with_auth(auth: SlimAuth, payload: &[u8]) -> Result<Vec<u8>, IdentityError> {
    match auth {
        SlimAuth::Did { signing_pem, did, .. } => {
            let identity = AgentIdentity::from_pkcs8_pem(&signing_pem)?;
            if identity.did() != did {
                return Err(IdentityError::Proof(
                    "env-derived identity DID does not match SlimAuth DID".to_string(),
                ));
            }
            wrap_signed_message(&identity, payload)
        }
        SlimAuth::SharedSecret(_) => Err(IdentityError::Config(
            "DID proof requires SHADI_SLIM_AUTH=did; shared-secret node auth is not application auth"
                .to_string(),
        )),
    }
}

fn canonical(did: &str, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + did.len() + payload.len() + 2);
    msg.extend_from_slice(DOMAIN);
    msg.push(0);
    msg.extend_from_slice(did.as_bytes());
    msg.push(0);
    msg.extend_from_slice(payload);
    msg
}

fn split_envelope(bytes: &[u8]) -> Result<(String, String, &[u8]), IdentityError> {
    let mut start = 0;
    let mut headers = Vec::with_capacity(3);
    for _ in 0..3 {
        let rel = bytes[start..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| IdentityError::Proof("truncated DID-proof envelope".to_string()))?;
        headers.push(&bytes[start..start + rel]);
        start += rel + 1;
    }
    let magic = headers[0];
    if magic != MAGIC {
        return Err(IdentityError::Proof("bad DID-proof magic".to_string()));
    }
    let did = std::str::from_utf8(headers[1])
        .map_err(|_| IdentityError::Proof("DID is not UTF-8".to_string()))?
        .to_string();
    let sig = std::str::from_utf8(headers[2])
        .map_err(|_| IdentityError::Proof("signature is not UTF-8".to_string()))?
        .to_string();
    if did.is_empty() || sig.is_empty() {
        return Err(IdentityError::Proof(
            "DID-proof envelope missing DID or signature".to_string(),
        ));
    }
    Ok((did, sig, &bytes[start..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_unwrap_round_trips() {
        let id = AgentIdentity::generate().unwrap();
        let envelope = wrap_signed_message(&id, b"handoff body").unwrap();
        assert!(looks_like_did_proof(&envelope));
        let verified = unwrap_signed_message(&envelope).unwrap();
        assert_eq!(verified.did, id.did());
        assert_eq!(verified.payload, b"handoff body");
    }

    #[test]
    fn forged_did_is_rejected() {
        let honest = AgentIdentity::generate().unwrap();
        let impostor = AgentIdentity::generate().unwrap();
        let envelope = wrap_signed_message(&honest, b"task").unwrap();
        // Swap the claimed DID for the impostor's while keeping the honest signature.
        let parts = split_envelope(&envelope).unwrap();
        let forged = {
            let mut out = Vec::new();
            out.extend_from_slice(MAGIC);
            out.push(b'\n');
            out.extend_from_slice(impostor.did().as_bytes());
            out.push(b'\n');
            out.extend_from_slice(parts.1.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(parts.2);
            out
        };
        let err = unwrap_signed_message(&forged).unwrap_err();
        match err {
            IdentityError::Proof(msg) => assert!(msg.contains("forged DID"), "{msg}"),
            other => panic!("expected Proof, got {other}"),
        }
        let _ = parts.0;
    }

    #[test]
    fn unsigned_bytes_are_not_a_proof() {
        assert!(!looks_like_did_proof(b"hello"));
        let err = unwrap_signed_message(b"hello").unwrap_err();
        assert!(matches!(err, IdentityError::Proof(_)));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let id = AgentIdentity::generate().unwrap();
        let mut envelope = wrap_signed_message(&id, b"original").unwrap();
        envelope.extend_from_slice(b"-tampered");
        assert!(unwrap_signed_message(&envelope).is_err());
    }

    fn raw_envelope(did: &[u8], sig: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(b'\n');
        out.extend_from_slice(did);
        out.push(b'\n');
        out.extend_from_slice(sig);
        out.push(b'\n');
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn unwrap_rejects_malformed_envelopes() {
        assert!(unwrap_signed_message(b"SHADI-DID-PROOF/1\nonly-one-line").is_err());
        assert!(split_envelope(b"NOPE\ndid:key:z\nsig\n").is_err());
        assert!(unwrap_signed_message(&raw_envelope(b"did:web:example.com", b"c2ln", b"x")).is_err());
        assert!(unwrap_signed_message(&raw_envelope(b"did:key:zabc", b"@@@", b"x")).is_err());
        assert!(unwrap_signed_message(&raw_envelope(b"did:key:zabc", b"YQ", b"x")).is_err());
        assert!(unwrap_signed_message(&raw_envelope(b"", b"c2ln", b"x")).is_err());
        assert!(unwrap_signed_message(&raw_envelope(b"did:key:zabc", b"", b"x")).is_err());
        assert!(unwrap_signed_message(&raw_envelope(b"did:key:\xff", b"c2ln", b"x")).is_err());
        assert!(unwrap_signed_message(&raw_envelope(b"did:key:zabc", b"sig\xff", b"x")).is_err());
    }

    #[test]
    fn sign_from_env_round_trips_did_mode() {
        let _guard = crate::auth::lock_slim_auth_env();
        let identity = AgentIdentity::derive(b"human", "avatar").unwrap();
        std::env::set_var("SHADI_SLIM_AUTH", "did");
        std::env::set_var("SLIM_HUMAN_SEED", "human");
        std::env::set_var("SLIM_MEMBER_DIDS", identity.did());
        let envelope = sign_message_from_env("avatar", b"from-env").unwrap();
        let verified = unwrap_signed_message(&envelope).unwrap();
        assert_eq!(verified.did, identity.did());
        assert_eq!(verified.payload, b"from-env");

        std::env::remove_var("SHADI_SLIM_AUTH");
        let err = sign_message_from_env("avatar", b"x").unwrap_err();
        assert!(matches!(err, IdentityError::Config(_)));
        std::env::remove_var("SLIM_HUMAN_SEED");
        std::env::remove_var("SLIM_MEMBER_DIDS");
    }

    #[test]
    fn sign_with_auth_rejects_shared_secret_and_mismatched_did() {
        let err = sign_message_with_auth(SlimAuth::SharedSecret(String::new()), b"x").unwrap_err();
        assert!(matches!(err, IdentityError::Config(_)));

        let signer = AgentIdentity::generate().unwrap();
        let other = AgentIdentity::generate().unwrap();
        let mismatched = SlimAuth::Did {
            signing_pem: signer.to_pkcs8_pem().unwrap(),
            did: other.did(),
            member_jwks: String::new(),
        };
        let err = sign_message_with_auth(mismatched, b"x").unwrap_err();
        match err {
            IdentityError::Proof(msg) => assert!(msg.contains("does not match"), "{msg}"),
            other => panic!("expected Proof, got {other}"),
        }
    }
}
