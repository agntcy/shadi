// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The `did:key` document for an Ed25519 public key, as `shadictl
//! did-from-gpg` and the Desktop write it.

use serde_json::{json, Value};

use crate::{IdentityError, ED25519_MULTICODEC};

/// The DID, its verification method id, and its document for `key`: 32 raw
/// bytes, or 33 with OpenPGP's `0x40` native-point prefix.
pub fn ed25519_did_document(key: &[u8]) -> Result<(String, String, Value), IdentityError> {
    let key = match key {
        [0x40, rest @ ..] if rest.len() == 32 => rest,
        _ if key.len() == 32 => key,
        _ => {
            return Err(IdentityError::InvalidDid(format!(
                "unexpected Ed25519 key material length: {}",
                key.len()
            )))
        }
    };

    let mut multicodec = Vec::with_capacity(ED25519_MULTICODEC.len() + key.len());
    multicodec.extend_from_slice(&ED25519_MULTICODEC);
    multicodec.extend_from_slice(key);
    let fingerprint = format!("z{}", bs58::encode(multicodec).into_string());

    let did = format!("did:key:{fingerprint}");
    let vm_id = format!("{did}#{fingerprint}");

    let doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": fingerprint
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
        "capabilityDelegation": [vm_id],
        "capabilityInvocation": [vm_id]
    });

    Ok((did, vm_id, doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentIdentity;

    #[test]
    fn the_document_names_the_same_did_as_the_identity() {
        let identity = AgentIdentity::generate().unwrap();
        let (did, vm_id, doc) = ed25519_did_document(&identity.verifying_key_bytes()).unwrap();
        assert_eq!(did, identity.did());
        assert_eq!(doc["authentication"][0], vm_id.as_str());

        let mut prefixed = vec![0x40];
        prefixed.extend_from_slice(&identity.verifying_key_bytes());
        assert_eq!(ed25519_did_document(&prefixed).unwrap().0, did);
        assert!(ed25519_did_document(&[0x01; 31]).is_err());
    }
}
