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

pub mod oid4vci;
pub mod sd_jwt;
pub mod store;
pub mod vault;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    /// The credential could not be read. Never embeds the credential itself —
    /// raw bytes stay inside the vault.
    #[error("malformed credential: {0}")]
    Malformed(String),
    #[error("vault storage error: {0}")]
    Storage(String),
    /// A response parsed fine but failed a check.
    #[error("issuance refused: {0}")]
    Refused(String),
}

pub use oid4vci::{check_id_token, proof_jwt, IdTokenClaims, IdpOrigin};
pub use sd_jwt::{import, parse_sd_jwt, Disclosure, ParsedCredential, SD_JWT_FORMAT};
pub use store::{CredentialRecord, SqlCipherVault};
pub use vault::{
    default_backend, default_vault, pin_issuer, CredentialVault, KeychainVault, VaultBackend,
    CREDENTIAL_KEY_PREFIX,
};
