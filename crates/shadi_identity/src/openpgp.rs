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
