// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SSH Ed25519 keys as a SHADI identity root (agntcy/shadi#140).
//!
//! An SSH Ed25519 key encodes the same primitive as `did:key`: the public half
//! gives a human DID, the private half roots agent derivation. See
//! `docs/content/security.md` for how the sources compare.

use ed25519_dalek::VerifyingKey;
use ssh_key::{PrivateKey, PublicKey};

use crate::IdentityError;

pub const SSH_ED25519: &str = "ssh-ed25519";

fn invalid(msg: impl Into<String>) -> IdentityError {
    IdentityError::Config(msg.into())
}

/// The key's 32-byte seed, used as the agent-derivation root.
///
/// The seed rather than the file's bytes: re-encrypting with a new passphrase
/// rewrites the file while the key is unchanged, so hashing the file would
/// silently change every derived agent DID.
pub fn seed_from_openssh_private_key(
    key_bytes: &[u8],
    passphrase: Option<&str>,
) -> Result<[u8; 32], IdentityError> {
    let text = std::str::from_utf8(key_bytes)
        .map_err(|_| invalid("SSH private key is not valid UTF-8 (expected OpenSSH PEM)"))?;
    let key = PrivateKey::from_openssh(text.trim()).map_err(|err| {
        invalid(format!(
            "failed to parse OpenSSH private key: {err}. Expected an unencrypted or \
             passphrase-protected OpenSSH key (BEGIN OPENSSH PRIVATE KEY)"
        ))
    })?;

    let key = if key.is_encrypted() {
        let passphrase = passphrase.filter(|p| !p.is_empty()).ok_or_else(|| {
            invalid("SSH private key is encrypted; a passphrase is required to derive from it")
        })?;
        key.decrypt(passphrase)
            .map_err(|_| invalid("failed to decrypt SSH private key: wrong passphrase"))?
    } else {
        key
    };

    let keypair = key.key_data().ed25519().ok_or_else(|| {
        invalid(format!(
            "SSH key algorithm is {}, but only {SSH_ED25519} can root a SHADI identity. \
             Hardware-backed sk-ssh-ed25519 keys expose no private key and cannot be used; \
             generate one with: ssh-keygen -t ed25519",
            key.algorithm()
        ))
    })?;

    Ok(keypair.private.to_bytes())
}

/// The Ed25519 key behind an `ssh-ed25519 AAAA... comment` line.
pub fn verifying_key_from_openssh_public_key(line: &str) -> Result<VerifyingKey, IdentityError> {
    let key = PublicKey::from_openssh(line.trim()).map_err(|err| {
        invalid(format!(
            "failed to parse OpenSSH public key: {err}. Expected a line like \
             '{SSH_ED25519} AAAA...'"
        ))
    })?;
    let public = key.key_data().ed25519().ok_or_else(|| {
        invalid(format!(
            "SSH key algorithm is {}, but only {SSH_ED25519} maps to an Ed25519 did:key",
            key.algorithm()
        ))
    })?;
    VerifyingKey::from_bytes(&public.0)
        .map_err(|err| invalid(format!("SSH public key is not a valid Ed25519 point: {err}")))
}

/// First `ssh-ed25519` key in an `authorized_keys`-style listing, e.g.
/// `github.com/<user>.keys`. Selects by algorithm because accounts commonly
/// publish several keys of mixed types.
pub fn first_ed25519_in_authorized_keys(listing: &str) -> Result<VerifyingKey, IdentityError> {
    let mut algorithms = Vec::new();
    for line in listing.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(SSH_ED25519) {
            return verifying_key_from_openssh_public_key(line);
        }
        if let Some(algorithm) = line.split_whitespace().next() {
            algorithms.push(algorithm.to_string());
        }
    }
    algorithms.sort();
    algorithms.dedup();
    let found = if algorithms.is_empty() {
        "none".to_string()
    } else {
        algorithms.join(", ")
    };
    Err(invalid(format!(
        "no {SSH_ED25519} key published (found: {found}). SHADI's did:key is Ed25519-only"
    )))
}

/// Public key of an OpenSSH private key, so a human DID needs no `.pub` file.
pub fn verifying_key_from_openssh_private_key(
    key_bytes: &[u8],
    passphrase: Option<&str>,
) -> Result<VerifyingKey, IdentityError> {
    let seed = seed_from_openssh_private_key(key_bytes, passphrase)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(signing.verifying_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_did_key;

    /// Fixed seed, encoded by the library itself so the fixture is a real key.
    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn plain_key() -> String {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&TEST_SEED);
        PrivateKey::from(keypair)
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encode openssh")
            .to_string()
    }

    fn plain_public_line() -> String {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&TEST_SEED);
        PrivateKey::from(keypair)
            .public_key()
            .to_openssh()
            .expect("encode public")
    }

    fn encrypted_key(passphrase: &str) -> String {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&TEST_SEED);
        PrivateKey::from(keypair)
            .encrypt(&mut rand_core_stub(), passphrase)
            .expect("encrypt")
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encode encrypted")
            .to_string()
    }

    /// Only used for the encryption salt.
    fn rand_core_stub() -> impl ssh_key::rand_core::CryptoRng + ssh_key::rand_core::RngCore {
        ssh_key::rand_core::OsRng
    }

    #[test]
    fn seed_is_32_bytes_and_stable() {
        let a = seed_from_openssh_private_key(plain_key().as_bytes(), None).expect("parse");
        let b = seed_from_openssh_private_key(plain_key().as_bytes(), None).expect("parse");
        assert_eq!(a.len(), 32);
        assert_eq!(a, b, "derivation root must be deterministic");
        assert_ne!(a, [0u8; 32]);
    }

    /// One key, one human DID — whichever half it is read from.
    #[test]
    fn public_and_private_halves_agree() {
        let from_private =
            verifying_key_from_openssh_private_key(plain_key().as_bytes(), None).expect("private");
        let from_public =
            verifying_key_from_openssh_public_key(&plain_public_line()).expect("public");
        assert_eq!(from_private.as_bytes(), from_public.as_bytes());
        assert!(encode_did_key(&from_private).starts_with("did:key:z"));
    }

    #[test]
    fn agents_derived_from_the_ssh_seed_are_distinct_and_stable() {
        let seed = seed_from_openssh_private_key(plain_key().as_bytes(), None).unwrap();
        let a1 = crate::AgentIdentity::derive(&seed, "claude-code").unwrap();
        let a2 = crate::AgentIdentity::derive(&seed, "claude-code").unwrap();
        let b = crate::AgentIdentity::derive(&seed, "codex").unwrap();
        assert_eq!(a1.did(), a2.did(), "same name must re-derive the same DID");
        assert_ne!(a1.did(), b.did(), "different agents must differ");
    }

    #[test]
    fn algorithm_selection_skips_non_ed25519_keys() {
        let listing = format!(
            "ssh-rsa AAAAB3NzaC1yc2EAAAA notreal\n# a comment\n{}\n",
            plain_public_line()
        );
        let vk = first_ed25519_in_authorized_keys(&listing).expect("should find the ed25519 key");
        let expected =
            verifying_key_from_openssh_private_key(plain_key().as_bytes(), None).unwrap();
        assert_eq!(vk.as_bytes(), expected.as_bytes());
    }

    /// Naming the algorithm that *is* published is what makes the refusal
    /// diagnosable — "1 published key" left the reason invisible.
    #[test]
    fn listing_without_an_ed25519_key_names_what_was_found() {
        let err = first_ed25519_in_authorized_keys("ssh-rsa AAAAB3NzaC1yc2EAAAA nope\n")
            .expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("no ssh-ed25519 key published"), "{msg}");
        assert!(msg.contains("found: ssh-rsa"), "must name the algorithm: {msg}");
    }

    /// Adding a passphrase must not change the derivation root.
    #[test]
    fn encrypted_key_yields_the_same_seed_as_plaintext() {
        let encrypted = encrypted_key("correct horse");
        let from_encrypted =
            seed_from_openssh_private_key(encrypted.as_bytes(), Some("correct horse"))
                .expect("decrypt with the right passphrase");
        let from_plain = seed_from_openssh_private_key(plain_key().as_bytes(), None).unwrap();
        assert_eq!(
            from_encrypted, from_plain,
            "a passphrase must not change the derivation root"
        );
    }

    #[test]
    fn encrypted_key_without_or_with_a_wrong_passphrase_is_refused() {
        let encrypted = encrypted_key("correct horse");

        let missing = seed_from_openssh_private_key(encrypted.as_bytes(), None)
            .expect_err("must not silently succeed");
        assert!(missing.to_string().contains("passphrase is required"), "{missing}");

        // An empty passphrase is treated as absent rather than tried.
        assert!(seed_from_openssh_private_key(encrypted.as_bytes(), Some("")).is_err());

        let wrong = seed_from_openssh_private_key(encrypted.as_bytes(), Some("nope"))
            .expect_err("wrong passphrase must fail");
        assert!(wrong.to_string().contains("wrong passphrase"), "{wrong}");
    }

    #[test]
    fn garbage_input_is_rejected() {
        assert!(seed_from_openssh_private_key(b"not a key", None).is_err());
        assert!(verifying_key_from_openssh_public_key("nonsense").is_err());
        assert!(first_ed25519_in_authorized_keys("").is_err());
    }
}
