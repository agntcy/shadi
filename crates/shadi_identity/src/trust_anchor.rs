// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Who owns a `did:key`, according to an authority outside the message.
//!
//! The envelope proves possession of a key; an anchor says whose key it is,
//! from a source the sender does not control.

use std::time::Duration;

use crate::IdentityError;

/// How long a resolved attestation may be reused. This is the window a revoked
/// key stays admissible for; the deny-list is checked before the cache so
/// revocation does not wait for it.
pub const ATTESTATION_TTL: Duration = Duration::from_secs(300);

/// Who an attestation names, and who vouched for it.
///
/// Identity is the `(authority, principal)` pair. Never `principal` alone:
/// two issuers can both mint `sub = alice`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub did: String,
    /// A stable id, e.g. an OIDC `sub`. Never an email: an address is
    /// reassignable, so the next hire called `alice` would inherit access.
    pub principal: String,
    /// Who vouched for it, e.g. an OIDC issuer URL.
    pub authority: String,
    /// For domain policy only, and only honoured when `email_verified`.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    /// Extra claims for policy, e.g. groups.
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

pub trait TrustAnchor: Send + Sync {
    /// Resolve `did` to the principal that owns it.
    ///
    /// `hint` is an unauthenticated lookup key for anchors that have no
    /// reverse index; it is never believed. `LocalAnchor` ignores it.
    ///
    /// `Ok(None)` means this anchor cannot answer, so the next one is tried.
    /// `Err` means the authority could not be reached — admission fails closed
    /// on that rather than treating it as an unknown peer.
    fn resolve(&self, did: &str, hint: Option<&str>) -> Result<Option<Attestation>, IdentityError>;

    fn authority(&self) -> &str;
}

/// Operator-pinned attestations, read from the policy file.
///
/// Explicit and does not scale, but it goes through the same policy evaluation
/// a resolvable anchor would.
pub struct LocalAnchor {
    authority: String,
    entries: Vec<Attestation>,
}

impl LocalAnchor {
    pub fn new(authority: impl Into<String>, entries: Vec<Attestation>) -> Self {
        Self {
            authority: authority.into(),
            entries,
        }
    }
}

impl TrustAnchor for LocalAnchor {
    fn resolve(
        &self,
        did: &str,
        _hint: Option<&str>,
    ) -> Result<Option<Attestation>, IdentityError> {
        Ok(self.entries.iter().find(|a| a.did == did).cloned())
    }

    fn authority(&self) -> &str {
        &self.authority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation(did: &str, principal: &str) -> Attestation {
        Attestation {
            did: did.to_string(),
            principal: principal.to_string(),
            authority: "https://issuer.example".to_string(),
            email: Some(format!("{principal}@corp.com")),
            email_verified: true,
            claims: serde_json::Map::new(),
        }
    }

    #[test]
    fn local_anchor_round_trips_a_pinned_pair() {
        let anchor = LocalAnchor::new(
            "https://issuer.example",
            vec![attestation("did:key:zAlice", "alice")],
        );
        let found = anchor.resolve("did:key:zAlice", None).unwrap().unwrap();
        assert_eq!(found.principal, "alice");
        assert_eq!(anchor.authority(), "https://issuer.example");
        assert!(anchor.resolve("did:key:zBob", None).unwrap().is_none());
    }
}
