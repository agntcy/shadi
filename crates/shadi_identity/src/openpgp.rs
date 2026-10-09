// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The Ed25519 key in an OpenPGP certificate, for `did-from-gpg`.

use sequoia_openpgp::crypto::mpi::PublicKey as MpiPublicKey;
use sequoia_openpgp::crypto::Curve;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;

use crate::IdentityError;

/// The first alive, unrevoked Ed25519 key in `certificate`, as the
/// certificate encodes it (see [`crate::did_document::ed25519_did_document`]).
pub fn ed25519_public_key(certificate: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let cert = Cert::from_reader(certificate).map_err(|err| {
        IdentityError::InvalidDid(format!("failed to parse OpenPGP certificate: {err}"))
    })?;
    let policy = &StandardPolicy::new();

    for key in cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
    {
        match key.key().mpis() {
            MpiPublicKey::Ed25519 { a } => return Ok(a.to_vec()),
            MpiPublicKey::EdDSA { curve, q } if *curve == Curve::Ed25519 => {
                return Ok(q.value().to_vec());
            }
            _ => {}
        }
    }

    Err(IdentityError::InvalidDid(
        "no Ed25519 public key found in OpenPGP certificate".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_document::ed25519_did_document;
    use sequoia_openpgp::cert::prelude::*;
    use sequoia_openpgp::serialize::Serialize;
    use sequoia_openpgp::Profile;

    fn exported(cert: &Cert) -> Vec<u8> {
        let mut out = Vec::new();
        cert.armored().export(&mut out).unwrap();
        out
    }

    #[test]
    fn a_legacy_and_an_rfc9580_ed25519_key_both_give_a_did() {
        for profile in [Profile::RFC4880, Profile::RFC9580] {
            let (cert, _) = CertBuilder::general_purpose(Some("alice@example.org"))
                .set_profile(profile)
                .unwrap()
                .generate()
                .unwrap();
            let key = ed25519_public_key(&exported(&cert)).unwrap();
            let (did, _, _) = ed25519_did_document(&key).unwrap();
            assert!(did.starts_with("did:key:z6Mk"), "{profile:?}: {did}");
        }
    }

    #[test]
    fn a_certificate_without_an_ed25519_key_and_garbage_are_refused() {
        let (cert, _) = CertBuilder::general_purpose(Some("bob@example.org"))
            .set_cipher_suite(CipherSuite::P256)
            .generate()
            .unwrap();
        let err = ed25519_public_key(&exported(&cert)).unwrap_err();
        assert!(err.to_string().contains("no Ed25519"), "{err}");
        assert!(ed25519_public_key(b"not a certificate").is_err());
    }
}
