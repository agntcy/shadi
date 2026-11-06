// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Verifiable credential handling for SHADI: a local vault, and the SD-JWT VC
//! format that currently fills it.
//!
//! The two are deliberately separate. [`vault`] and [`store`] know nothing
//! about SD-JWT — they keep opaque credential bytes under columns they can
//! query — while [`sd_jwt`] owns everything tilde-separated. A second
//! credential format lands as a sibling of `sd_jwt`, not as a change to the
//! storage.

pub mod dcql;
pub mod jwks;
pub mod nonce;
pub mod oid4vci;
pub mod policy;
pub mod presentation;
pub mod sd_jwt;
pub mod store;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod vault;
pub mod verify;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// The credential could not be read. Never embeds the credential itself —
    /// raw bytes stay inside the vault.
    #[error("malformed credential: {0}")]
    Malformed(String),
    #[error("vault storage error: {0}")]
    Storage(String),
    /// Well-formed input that failed a check — an issuance response, a
    /// challenge, or a key lookup.
    #[error("refused: {0}")]
    Refused(String),
    /// A challenge nonce that could not be consumed. Renders exactly as
    /// [`Self::Refused`]; only the type tells a caller to re-challenge.
    #[error("refused: {0}")]
    NonceNotConsumable(String),
}

/// `s` made safe to put in an error: control characters dropped, cut to 64
/// characters. Errors reach log lines, so token text must never pass raw.
pub(crate) fn printable(s: &str) -> String {
    let mut chars = s.chars().filter(|c| !c.is_control());
    let mut out: String = chars.by_ref().take(64).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod printable_tests {
    use super::printable;

    #[test]
    fn cuts_to_64_characters_and_marks_it() {
        assert_eq!(printable(&"a".repeat(64)), "a".repeat(64));
        assert_eq!(printable(&"a".repeat(65)), format!("{}…", "a".repeat(64)));
    }

    #[test]
    fn drops_control_characters() {
        assert_eq!(printable("a\nb\tc\r\x1b[31md\0"), "abc[31md");
    }

    #[test]
    fn cuts_on_a_character_boundary() {
        // 63 ASCII bytes then a 3-byte char straddling byte 64.
        let s = format!("{}€€", "a".repeat(63));
        assert_eq!(printable(&s), format!("{}€…", "a".repeat(63)));
    }

    #[test]
    fn counts_characters_after_dropping_controls() {
        let s = format!("{}x", "\n".repeat(100));
        assert_eq!(printable(&s), "x");
    }
}

pub use dcql::{select, ClaimQuery, CredentialQuery, DcqlQuery, ReleasePolicy, Selection};
pub use jwks::JwksStore;
pub use nonce::{Challenge, NonceStore};
pub use oid4vci::{check_id_token, proof_jwt, IdTokenClaims, IdpOrigin};
pub use policy::{AdmissionPolicy, Decision, IssuerPolicy};
pub use presentation::answer_challenge;
pub use sd_jwt::{
    import, parse_presentation, parse_sd_jwt, Disclosure, Jwt, ParsedCredential,
    ParsedPresentation, SD_JWT_FORMAT,
};
pub use store::{CredentialRecord, SqlCipherVault};
pub use vault::{
    default_backend, default_vault, pin_issuer, CredentialVault, KeychainVault, VaultBackend,
    CREDENTIAL_KEY_PREFIX,
};
pub use verify::{verify, VerifiedPresentation};
