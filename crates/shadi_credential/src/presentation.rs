// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Building a key-bound presentation: the credential, the chosen disclosures,
//! and a key-binding JWT signed with the agent key.
//!
//! The agent key is the same one that signs the outer DID proof, which is
//! what lets a verifier join `cnf.jwk` to the DID that signed the envelope.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use shadi_identity::AgentIdentity;

use crate::dcql::{self, DcqlQuery, ReleasePolicy, Selection};
use crate::vault::CredentialVault;
use crate::CredentialError;

/// Upper bound on the challenge nonce; the protocol issues 16 random bytes.
const MAX_NONCE_BYTES: usize = 128;

/// Answer a challenge: validate its audience, pick what to disclose, and sign.
///
/// `peer_did` is the agent we actually dialled. A challenge naming anyone else
/// as its audience is refused before anything is selected or signed.
#[allow(clippy::too_many_arguments)]
pub fn answer_challenge(
    vault: &dyn CredentialVault,
    identity: &AgentIdentity,
    policy: &ReleasePolicy,
    peer_did: &str,
    aud: &str,
    nonce: &str,
    query: &DcqlQuery,
    now: i64,
) -> Result<String, CredentialError> {
    if aud != peer_did {
        return Err(CredentialError::Refused(
            "the challenge audience is not the agent we are talking to".into(),
        ));
    }
    if nonce.is_empty() || nonce.len() > MAX_NONCE_BYTES {
        return Err(CredentialError::Refused(format!(
            "the challenge nonce must be 1 to {MAX_NONCE_BYTES} bytes"
        )));
    }
    let selection = dcql::select(vault, &identity.did(), query, policy, peer_did, now)?;
    build(identity, &selection, nonce, aud, now)
}

/// Serialise `selection` and bind it to `nonce` and `audience`.
pub(crate) fn build(
    identity: &AgentIdentity,
    selection: &Selection,
    nonce: &str,
    audience: &str,
    now: i64,
) -> Result<String, CredentialError> {
    if selection.record.agent_did != identity.did() {
        return Err(CredentialError::Refused(
            "the credential is bound to a different agent key".into(),
        ));
    }
    let (issuer_jwt, _) = selection
        .record
        .raw
        .split_once('~')
        .ok_or_else(|| CredentialError::Malformed("credential has no `~`".into()))?;

    // `sd_hash` covers exactly these bytes, through the last `~`.
    let mut prefix = format!("{issuer_jwt}~");
    for d in &selection.disclosures {
        prefix.push_str(&d.raw);
        prefix.push('~');
    }

    let header = json!({ "alg": "EdDSA", "typ": "kb+jwt" });
    let payload = json!({
        "iat": now,
        "aud": audience,
        "nonce": nonce,
        "sd_hash": URL_SAFE_NO_PAD.encode(Sha256::digest(prefix.as_bytes())),
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let sig = identity.sign_bytes(input.as_bytes());
    Ok(format!("{prefix}{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sd_jwt::{decode_json, import};
    use crate::vault::tests::sqlcipher_vault;
    use ed25519_dalek::{Signature, Verifier};

    const NOW: i64 = 1_700_000_000;

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    fn disclosure(name: &str, value: &str) -> String {
        // Whitespace after the commas: a re-encode would not reproduce this.
        b64(&format!("[ \"c2FsdA\", \"{name}\", \"{value}\" ]"))
    }

    fn selection_for(id: &AgentIdentity, take: usize) -> Selection {
        let payload = json!({
            "iss": "https://idp.example",
            "vct": "urn:shadi:agent-admission:1",
            "cnf": { "jwk": id.public_jwk() },
        });
        let raw = format!(
            "{}.{}.c2ln~{}~{}~",
            b64(r#"{"alg":"EdDSA","typ":"dc+sd-jwt"}"#),
            b64(&payload.to_string()),
            disclosure("groups", "admins"),
            disclosure("email", "a@example.test"),
        );
        let vault = sqlcipher_vault();
        let record = import(&vault, &raw, 1_000).unwrap();
        let disclosures = crate::parse_sd_jwt(&raw).unwrap().disclosures[..take].to_vec();
        Selection {
            record,
            disclosures,
        }
    }

    /// Verify the KB-JWT signature and `sd_hash` of `pres`.
    fn verifies(id: &AgentIdentity, pres: &str) -> bool {
        let Some((prefix, kb)) = pres.rsplit_once('~') else {
            return false;
        };
        let parts: Vec<&str> = kb.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        let Ok(sig) = URL_SAFE_NO_PAD.decode(parts[2]) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&sig) else {
            return false;
        };
        let signed = format!("{}.{}", parts[0], parts[1]);
        if id.verifying_key().verify(signed.as_bytes(), &sig).is_err() {
            return false;
        }
        let Ok(payload) = decode_json(parts[1], "payload") else {
            return false;
        };
        let mut h = Sha256::new();
        h.update(prefix.as_bytes());
        h.update(b"~");
        payload["sd_hash"] == URL_SAFE_NO_PAD.encode(h.finalize())
    }

    #[test]
    fn round_trip_shape() {
        let id = AgentIdentity::generate().unwrap();
        let sel = selection_for(&id, 1);
        let pres = build(&id, &sel, "n-1", "did:key:verifier", NOW).unwrap();
        let parts: Vec<&str> = pres.split('~').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], sel.record.raw.split('~').next().unwrap());
        assert_eq!(parts[1], sel.disclosures[0].raw);
        assert_eq!(parts[2].split('.').count(), 3);
        assert!(verifies(&id, &pres));
    }

    #[test]
    fn no_disclosures_still_ends_with_kb_jwt() {
        let id = AgentIdentity::generate().unwrap();
        let sel = selection_for(&id, 0);
        let pres = build(&id, &sel, "n", "aud", NOW).unwrap();
        assert_eq!(pres.split('~').count(), 2);
        assert!(verifies(&id, &pres));
    }

    #[test]
    fn kb_jwt_carries_nonce_aud_and_typ() {
        let id = AgentIdentity::generate().unwrap();
        let pres = build(&id, &selection_for(&id, 2), "n-42", "did:key:v", NOW).unwrap();
        let kb: Vec<&str> = pres.rsplit('~').next().unwrap().split('.').collect();
        let header = decode_json(kb[0], "header").unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "kb+jwt");
        let payload = decode_json(kb[1], "payload").unwrap();
        assert_eq!(payload["nonce"], "n-42");
        assert_eq!(payload["aud"], "did:key:v");
        assert_eq!(payload["iat"], NOW);
    }

    #[test]
    fn sd_hash_matches_an_independent_digest() {
        let id = AgentIdentity::generate().unwrap();
        let sel = selection_for(&id, 1);
        let pres = build(&id, &sel, "n", "aud", NOW).unwrap();
        // Rebuild the prefix from the stored parts rather than from `pres`,
        // and hash it incrementally.
        let mut h = Sha256::new();
        h.update(sel.record.raw.split('~').next().unwrap().as_bytes());
        for d in &sel.disclosures {
            h.update(b"~");
            h.update(d.raw.as_bytes());
        }
        h.update(b"~");
        let expected = URL_SAFE_NO_PAD.encode(h.finalize());
        let kb = pres.rsplit('~').next().unwrap();
        let payload = decode_json(kb.split('.').nth(1).unwrap(), "payload").unwrap();
        assert_eq!(payload["sd_hash"], expected);
    }

    #[test]
    fn disclosures_are_emitted_verbatim() {
        let id = AgentIdentity::generate().unwrap();
        let sel = selection_for(&id, 2);
        let pres = build(&id, &sel, "n", "aud", NOW).unwrap();
        let parts: Vec<&str> = pres.split('~').collect();
        assert_eq!(parts[1], sel.disclosures[0].raw);
        assert_eq!(parts[2], sel.disclosures[1].raw);
    }

    #[test]
    fn signature_does_not_verify_under_another_key() {
        let id = AgentIdentity::generate().unwrap();
        let other = AgentIdentity::generate().unwrap();
        let pres = build(&id, &selection_for(&id, 1), "n", "aud", NOW).unwrap();
        assert!(!verifies(&other, &pres));
    }

    #[test]
    fn a_one_byte_mutation_anywhere_breaks_verification() {
        let id = AgentIdentity::generate().unwrap();
        let pres = build(&id, &selection_for(&id, 2), "n", "aud", NOW).unwrap();
        assert!(verifies(&id, &pres));
        let tildes: Vec<usize> = pres.match_indices('~').map(|(i, _)| i).collect();
        let kb_payload = tildes[2] + 1 + pres[tildes[2] + 1..].find('.').unwrap() + 1;
        // Inside the issuer JWT, a disclosure, and the KB-JWT payload.
        for at in [5, tildes[0] + 3, kb_payload + 5] {
            let mut bytes = pres.clone().into_bytes();
            bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
            let mutated = String::from_utf8(bytes).unwrap();
            assert!(!verifies(&id, &mutated), "byte {at}");
        }
    }

    #[test]
    fn refuses_a_credential_bound_to_another_agent() {
        let id = AgentIdentity::generate().unwrap();
        let other = AgentIdentity::generate().unwrap();
        let sel = selection_for(&other, 1);
        let err = build(&id, &sel, "n", "aud", NOW).unwrap_err();
        assert!(matches!(err, CredentialError::Refused(_)), "{err}");
    }

    #[test]
    fn answer_challenge_refuses_a_foreign_audience_first() {
        let id = AgentIdentity::generate().unwrap();
        let vault = sqlcipher_vault();
        let query = DcqlQuery {
            credentials: vec![],
        };
        // Would hit `select` (and its empty vault) if the audience check ran later.
        let err = answer_challenge(
            &vault,
            &id,
            &ReleasePolicy::default(),
            "did:key:dialled",
            "did:key:someone-else",
            "n",
            &query,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, CredentialError::Refused(_)), "{err}");
    }

    #[test]
    fn answer_challenge_refuses_an_empty_or_oversized_nonce() {
        let id = AgentIdentity::generate().unwrap();
        let vault = sqlcipher_vault();
        let query = DcqlQuery {
            credentials: vec![],
        };
        for nonce in [String::new(), "n".repeat(MAX_NONCE_BYTES + 1)] {
            let err = answer_challenge(
                &vault,
                &id,
                &ReleasePolicy::default(),
                "did:key:p",
                "did:key:p",
                &nonce,
                &query,
                NOW,
            )
            .unwrap_err();
            assert!(err.to_string().contains("nonce"), "{err}");
        }
    }
}
