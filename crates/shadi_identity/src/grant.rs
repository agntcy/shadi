// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Channel grants: the owner's signature letting one participant into, or out
//! of, one channel.
//!
//! The format is the SLIM channel manager's default grant (agntcy/slim#2180),
//! so a stock channel manager accepts what an owner's SHADI signs. Until a
//! channel manager acts on them, the owner's own moderator checks them. The
//! nonce lets whoever acts on a grant refuse a replay. See agntcy/shadi#420.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier};
use serde_json::{json, Map, Value};

use crate::{parse_did_key, AgentIdentity, IdentityError};

/// Maximum size of a whole grant.
pub const GRANT_MAX_BYTES: usize = 4096;

const NONCE_BYTES: usize = 16;
/// First of the signed parts, so no signature made for another protocol
/// can pass as a grant.
const DOMAIN: &str = "SLIM-CHANNEL-GRANT/1";
const FIELDS: [&str; 7] = [
    "channel",
    "invitee",
    "action",
    "role",
    "not_after",
    "nonce",
    "signature",
];

/// What the grant lets happen to the invitee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAction {
    Add,
    Delete,
}

impl GrantAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Delete => "delete",
        }
    }

    fn parse(raw: &str) -> Result<Self, IdentityError> {
        match raw {
            "add" => Ok(Self::Add),
            "delete" => Ok(Self::Delete),
            other => Err(IdentityError::Proof(format!(
                "grant action {other:?} is not add or delete"
            ))),
        }
    }
}

/// What the invitee may do in the channel.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRole {
    Member,
}

impl GrantRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
        }
    }

    fn parse(raw: &str) -> Result<Self, IdentityError> {
        match raw {
            "member" => Ok(Self::Member),
            other => Err(IdentityError::Proof(format!(
                "grant role {other:?} is not one of: member"
            ))),
        }
    }
}

/// A grant whose signature has been checked against the channel's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelGrant {
    /// The channel's SLIM name, `org/namespace/channel`.
    pub channel: String,
    /// The participant's SLIM name.
    pub invitee: String,
    pub action: GrantAction,
    pub role: GrantRole,
    /// Unix seconds after which the grant is no longer accepted.
    pub not_after: u64,
    /// Random and unique per grant, so a verifier can refuse one used before.
    pub nonce: String,
}

impl ChannelGrant {
    fn canonical(&self) -> Vec<u8> {
        signed_bytes([
            self.channel.as_str(),
            self.invitee.as_str(),
            self.action.as_str(),
            self.role.as_str(),
            &self.not_after.to_string(),
            self.nonce.as_str(),
        ])
    }
}

/// Issue a grant: `owner` lets `action` happen to `invitee` in `channel`
/// until `not_after`.
pub fn issue_grant(
    owner: &AgentIdentity,
    channel: &str,
    invitee: &str,
    action: GrantAction,
    role: GrantRole,
    not_after: u64,
) -> Result<Vec<u8>, IdentityError> {
    check_name("channel", channel)?;
    check_name("invitee", invitee)?;
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|e| IdentityError::KeyGen(e.to_string()))?;
    let grant = ChannelGrant {
        channel: channel.to_string(),
        invitee: invitee.to_string(),
        action,
        role,
        not_after,
        nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
    };
    let signature =
        base64::engine::general_purpose::STANDARD.encode(owner.sign_bytes(&grant.canonical()));
    let document = json!({
        "channel": grant.channel,
        "invitee": grant.invitee,
        "action": action.as_str(),
        "role": role.as_str(),
        "not_after": not_after,
        "nonce": grant.nonce,
        "signature": signature,
    });
    serde_json::to_vec(&document).map_err(|e| IdentityError::Proof(e.to_string()))
}

/// Verify a grant that `owner_did` must have signed, rejecting one that
/// expired before `now`.
///
/// `owner_did` is the channel's recorded owner; a grant names no signer, so
/// one signed by anyone else fails here.
pub fn verify_grant(
    grant: &[u8],
    owner_did: &str,
    now: u64,
) -> Result<ChannelGrant, IdentityError> {
    if grant.len() > GRANT_MAX_BYTES {
        return Err(IdentityError::Proof(format!(
            "grant exceeds {GRANT_MAX_BYTES} bytes"
        )));
    }
    let owner_key = parse_did_key(owner_did)?;
    let document: Map<String, Value> = serde_json::from_slice(grant)
        .map_err(|e| IdentityError::Proof(format!("grant is not a JSON object: {e}")))?;
    if let Some(unknown) = document.keys().find(|key| !FIELDS.contains(&key.as_str())) {
        return Err(IdentityError::Proof(format!(
            "grant has an unknown field {unknown:?}"
        )));
    }
    let text = |key: &str| {
        document
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| IdentityError::Proof(format!("grant is missing its {key}")))
    };
    let not_after = document
        .get("not_after")
        .and_then(Value::as_u64)
        .ok_or_else(|| IdentityError::Proof("grant is missing its not_after".to_string()))?;

    let unchecked = Unchecked {
        channel: text("channel")?,
        invitee: text("invitee")?,
        action: text("action")?,
        role: text("role")?,
        not_after,
        nonce: text("nonce")?,
    };
    let signature = base64::engine::general_purpose::STANDARD
        .decode(text("signature")?)
        .map_err(|e| IdentityError::Proof(format!("grant signature is not base64: {e}")))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| IdentityError::Proof("grant signature is not 64 bytes".to_string()))?;
    owner_key
        .verify(&unchecked.canonical(), &Signature::from_bytes(&signature))
        .map_err(|_| {
            IdentityError::Proof(
                "grant signature does not verify under the channel's owner".to_string(),
            )
        })?;

    // Only after the signature: these fields are now the owner's, so a bad
    // one is the owner's mistake rather than tampering.
    if now > not_after {
        return Err(IdentityError::Proof(format!(
            "grant expired at {not_after} (now {now})"
        )));
    }
    check_name("channel", unchecked.channel)?;
    check_name("invitee", unchecked.invitee)?;
    Ok(ChannelGrant {
        channel: unchecked.channel.to_string(),
        invitee: unchecked.invitee.to_string(),
        action: GrantAction::parse(unchecked.action)?,
        role: GrantRole::parse(unchecked.role)?,
        not_after,
        nonce: unchecked.nonce.to_string(),
    })
}

/// The fields as read, before the signature over them is checked.
struct Unchecked<'a> {
    channel: &'a str,
    invitee: &'a str,
    action: &'a str,
    role: &'a str,
    not_after: u64,
    nonce: &'a str,
}

impl Unchecked<'_> {
    fn canonical(&self) -> Vec<u8> {
        signed_bytes([
            self.channel,
            self.invitee,
            self.action,
            self.role,
            &self.not_after.to_string(),
            self.nonce,
        ])
    }
}

/// The bytes the owner signs: the domain, then the fields in order, all
/// NUL-separated.
fn signed_bytes(fields: [&str; 6]) -> Vec<u8> {
    std::iter::once(DOMAIN)
        .chain(fields)
        .collect::<Vec<_>>()
        .join("\0")
        .into_bytes()
}

fn check_name(what: &str, name: &str) -> Result<(), IdentityError> {
    let parts: Vec<&str> = name.split('/').collect();
    let well_formed = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && !p.chars().any(|c| c.is_whitespace() || c == '\0'));
    if well_formed {
        Ok(())
    } else {
        Err(IdentityError::Proof(format!(
            "{what} {name:?} is not a SLIM name (org/namespace/name)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const LATER: u64 = NOW + 3600;
    const CHANNEL: &str = "agntcy/shadi/review-room";
    const INVITEE: &str = "agntcy/shadi/copilot";

    fn add(owner: &AgentIdentity) -> Vec<u8> {
        issue_grant(
            owner,
            CHANNEL,
            INVITEE,
            GrantAction::Add,
            GrantRole::Member,
            LATER,
        )
        .unwrap()
    }

    fn document(grant: &[u8]) -> Map<String, Value> {
        serde_json::from_slice(grant).unwrap()
    }

    fn with(grant: &[u8], key: &str, value: Value) -> Vec<u8> {
        let mut doc = document(grant);
        doc.insert(key.to_string(), value);
        serde_json::to_vec(&doc).unwrap()
    }

    #[test]
    fn a_grant_verifies_under_its_owner() {
        let owner = AgentIdentity::generate().unwrap();
        let verified = verify_grant(&add(&owner), &owner.did(), NOW).unwrap();
        assert_eq!(verified.channel, CHANNEL);
        assert_eq!(verified.invitee, INVITEE);
        assert_eq!(verified.action, GrantAction::Add);
        assert_eq!(verified.role, GrantRole::Member);
        assert_eq!(verified.not_after, LATER);
        assert_eq!(verified.nonce.len(), NONCE_BYTES * 2);
    }

    /// The bytes a channel manager checks: the domain and the fields in order,
    /// NUL-joined, signed by the owner key, in standard padded base64
    /// (agntcy/slim#2180).
    #[test]
    fn the_signature_is_over_the_channel_managers_canonical_bytes() {
        let owner = AgentIdentity::generate().unwrap();
        let doc = document(&add(&owner));
        let mut keys: Vec<&str> = doc.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = FIELDS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected);

        let signed = format!(
            "SLIM-CHANNEL-GRANT/1\0{CHANNEL}\0{INVITEE}\0add\0member\0{LATER}\0{}",
            doc["nonce"].as_str().unwrap()
        );
        let signature = base64::engine::general_purpose::STANDARD
            .decode(doc["signature"].as_str().unwrap())
            .unwrap();
        let signature = Signature::from_bytes(&signature.try_into().unwrap());
        assert!(owner
            .verifying_key()
            .verify(signed.as_bytes(), &signature)
            .is_ok());
        assert!(doc["signature"].as_str().unwrap().ends_with('='));
    }

    #[test]
    fn each_grant_gets_its_own_nonce() {
        let owner = AgentIdentity::generate().unwrap();
        let first = verify_grant(&add(&owner), &owner.did(), NOW).unwrap();
        let second = verify_grant(&add(&owner), &owner.did(), NOW).unwrap();
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn a_grant_from_anyone_but_the_owner_is_refused() {
        let owner = AgentIdentity::generate().unwrap();
        let stranger = AgentIdentity::generate().unwrap();
        let err = verify_grant(&add(&stranger), &owner.did(), NOW).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn editing_any_signed_field_breaks_the_signature() {
        let owner = AgentIdentity::generate().unwrap();
        let grant = add(&owner);
        for (key, value) in [
            ("channel", json!("agntcy/shadi/other-room")),
            ("invitee", json!("agntcy/shadi/codex")),
            ("action", json!("delete")),
            ("not_after", json!(LATER + 3600)),
            ("nonce", json!("00")),
        ] {
            let err = verify_grant(&with(&grant, key, value), &owner.did(), NOW).unwrap_err();
            assert!(err.to_string().contains("does not verify"), "{key}: {err}");
        }
    }

    #[test]
    fn a_delete_grant_is_its_own_action() {
        let owner = AgentIdentity::generate().unwrap();
        let grant = issue_grant(
            &owner,
            CHANNEL,
            INVITEE,
            GrantAction::Delete,
            GrantRole::Member,
            LATER,
        )
        .unwrap();
        assert_eq!(
            verify_grant(&grant, &owner.did(), NOW).unwrap().action,
            GrantAction::Delete
        );
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let owner = AgentIdentity::generate().unwrap();
        let grant = issue_grant(
            &owner,
            CHANNEL,
            INVITEE,
            GrantAction::Add,
            GrantRole::Member,
            NOW - 1,
        )
        .unwrap();
        let err = verify_grant(&grant, &owner.did(), NOW).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        assert!(verify_grant(&grant, &owner.did(), NOW - 2).is_ok());
    }

    #[test]
    fn issuing_refuses_names_that_are_not_slim_names() {
        let owner = AgentIdentity::generate().unwrap();
        for name in [
            "",
            "room",
            "a/b",
            "a/b/c/d",
            "a//c",
            "a/b/has space",
            "a/b/nul\0",
        ] {
            for (channel, invitee) in [(name, INVITEE), (CHANNEL, name)] {
                let err = issue_grant(
                    &owner,
                    channel,
                    invitee,
                    GrantAction::Add,
                    GrantRole::Member,
                    LATER,
                )
                .unwrap_err();
                assert!(
                    err.to_string().contains("not a SLIM name"),
                    "{name:?}: {err}"
                );
            }
        }
    }

    #[test]
    fn values_this_build_does_not_know_are_refused_even_when_signed() {
        // A future action or role must not be read as one this build knows.
        let owner = AgentIdentity::generate().unwrap();
        for (action, role, why) in [
            ("rename", "member", "not add or delete"),
            ("add", "admin", "not one of"),
        ] {
            let unchecked = Unchecked {
                channel: CHANNEL,
                invitee: INVITEE,
                action,
                role,
                not_after: LATER,
                nonce: "00",
            };
            let signature = base64::engine::general_purpose::STANDARD
                .encode(owner.sign_bytes(&unchecked.canonical()));
            let grant = serde_json::to_vec(&json!({
                "channel": CHANNEL, "invitee": INVITEE, "action": action, "role": role,
                "not_after": LATER, "nonce": "00", "signature": signature,
            }))
            .unwrap();
            let err = verify_grant(&grant, &owner.did(), NOW).unwrap_err();
            assert!(err.to_string().contains(why), "{action}/{role}: {err}");
        }
    }

    #[test]
    fn malformed_grants_are_refused_without_panicking() {
        let owner = AgentIdentity::generate().unwrap();
        let grant = add(&owner);
        let mut missing = document(&grant);
        missing.remove("nonce");
        for bad in [
            Vec::new(),
            b"[]".to_vec(),
            b"not json".to_vec(),
            serde_json::to_vec(&missing).unwrap(),
            with(&grant, "extra", json!(1)),
            with(&grant, "not_after", json!("soon")),
            with(&grant, "signature", json!("!!")),
            with(&grant, "signature", json!("AAAA")),
            vec![b' '; GRANT_MAX_BYTES + 1],
        ] {
            assert!(
                verify_grant(&bad, &owner.did(), NOW).is_err(),
                "accepted {bad:?}"
            );
        }
        assert!(verify_grant(&grant, "did:web:nope", NOW).is_err());
    }
}
