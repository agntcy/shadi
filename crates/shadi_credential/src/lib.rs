// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Verifiable credential handling for SHADI: a local vault, and the SD-JWT VC
//! format that currently fills it.
//!
//! The two are deliberately separate modules. [`vault`] knows nothing about
//! SD-JWT — it stores opaque credential bytes under columns it can query —
//! while [`sd_jwt`] owns everything tilde-separated. A second credential
//! format lands as a sibling of `sd_jwt`, not as a change to `vault`.

pub mod sd_jwt;
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
}

pub use sd_jwt::{import, parse_sd_jwt, Disclosure, ParsedCredential};
pub use shadi_memory::CredentialRecord;
pub use vault::{
    default_backend, default_vault, CredentialVault, KeychainVault, SqlCipherVault, VaultBackend,
    CREDENTIAL_KEY_PREFIX,
};
