// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! An owner's signed channel-manager requests: creating a channel, which
//! makes the signer its owner, and deleting one. They travel in the request's
//! `owner_proof`, in the SLIM channel manager's default format
//! (`SLIM-CHANNEL-CREATE/1`, `SLIM-CHANNEL-DELETE/1`, agntcy/slim#2233), like
//! the grants in [`crate::grant`] that cover membership changes. See
//! agntcy/shadi#463.

use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::grant::{check_name, new_nonce};
use crate::{AgentIdentity, IdentityError};

/// How far ahead a channel manager accepts a create or delete request's
/// `not_after`.
pub const MAX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

const CREATE_DOMAIN: &str = "SLIM-CHANNEL-CREATE/1";
const DELETE_DOMAIN: &str = "SLIM-CHANNEL-DELETE/1";

/// The settings a create request covers; the channel manager refuses one
/// whose request doesn't match them exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCreation<'a> {
    /// The channel manager the request is for: its configured audience, by
    /// default its `local-name`.
    pub audience: &'a str,
    pub channel: &'a str,
    pub mls_enabled: bool,
    pub ttl_seconds: Option<u64>,
    /// Where the channel manager asks the owner to approve others' requests.
    pub owner_callback_name: Option<&'a str>,
}

/// Sign `creation` as `owner`, valid until `not_after`. The channel manager
/// records `owner`'s `did:key` as the channel's owner.
pub fn sign_create(
    owner: &AgentIdentity,
    creation: &ChannelCreation<'_>,
    not_after: u64,
) -> Result<Vec<u8>, IdentityError> {
    check_audience(creation.audience)?;
    check_name("channel", creation.channel)?;
    if let Some(callback) = creation.owner_callback_name {
        check_name("owner_callback_name", callback)?;
    }
    if creation.ttl_seconds == Some(0) {
        return Err(IdentityError::Proof(
            "ttl_seconds must be positive".to_string(),
        ));
    }
    let owner_did = owner.did();
    let nonce = new_nonce()?;
    let ttl = creation
        .ttl_seconds
        .map(|t| t.to_string())
        .unwrap_or_default();
    let not_after_text = not_after.to_string();
    let signed = signed_bytes(
        CREATE_DOMAIN,
        &[
            creation.audience,
            creation.channel,
            &owner_did,
            if creation.mls_enabled {
                "true"
            } else {
                "false"
            },
            &ttl,
            creation.owner_callback_name.unwrap_or(""),
            &not_after_text,
            &nonce,
        ],
    );
    let mut document = Map::new();
    document.insert("audience".into(), json!(creation.audience));
    document.insert("channel".into(), json!(creation.channel));
    document.insert("owner".into(), json!(owner_did));
    document.insert("mls_enabled".into(), json!(creation.mls_enabled));
    if let Some(ttl) = creation.ttl_seconds {
        document.insert("ttl_seconds".into(), json!(ttl));
    }
    if let Some(callback) = creation.owner_callback_name {
        document.insert("owner_callback_name".into(), json!(callback));
    }
    document.insert("not_after".into(), json!(not_after));
    document.insert("nonce".into(), json!(nonce));
    document.insert("signature".into(), json!(signature(owner, &signed)));
    serde_json::to_vec(&Value::Object(document)).map_err(|e| IdentityError::Proof(e.to_string()))
}

/// Sign the deletion of `channel` as its owner, valid until `not_after`.
pub fn sign_delete(
    owner: &AgentIdentity,
    audience: &str,
    channel: &str,
    not_after: u64,
) -> Result<Vec<u8>, IdentityError> {
    check_audience(audience)?;
    check_name("channel", channel)?;
    let nonce = new_nonce()?;
    let not_after_text = not_after.to_string();
    let signed = signed_bytes(DELETE_DOMAIN, &[audience, channel, &not_after_text, &nonce]);
    let document = json!({
        "audience": audience,
        "channel": channel,
        "not_after": not_after,
        "nonce": nonce,
        "signature": signature(owner, &signed),
    });
    serde_json::to_vec(&document).map_err(|e| IdentityError::Proof(e.to_string()))
}

fn check_audience(audience: &str) -> Result<(), IdentityError> {
    if audience.is_empty() || audience.contains('\0') {
        return Err(IdentityError::Proof(format!(
            "audience {audience:?} is empty or contains NUL"
        )));
    }
    Ok(())
}

/// The tag, then the fields in order, NUL-separated, with no trailing NUL.
fn signed_bytes(domain: &str, fields: &[&str]) -> Vec<u8> {
    std::iter::once(domain)
        .chain(fields.iter().copied())
        .collect::<Vec<_>>()
        .join("\0")
        .into_bytes()
}

fn signature(owner: &AgentIdentity, signed: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(owner.sign_bytes(signed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    const AUDIENCE: &str = "agntcy/shadi/channel-manager";
    const CHANNEL: &str = "agntcy/shadi/review-room";
    const LATER: u64 = 1_900_000_000;

    fn verifies(owner: &AgentIdentity, document: &Value, signed: String) -> bool {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(document["signature"].as_str().unwrap())
            .unwrap();
        let signature = Signature::from_slice(&raw).unwrap();
        owner
            .verifying_key()
            .verify(signed.as_bytes(), &signature)
            .is_ok()
    }

    #[test]
    fn a_create_is_signed_over_the_channel_managers_canonical_bytes() {
        let owner = AgentIdentity::generate().unwrap();
        let creation = ChannelCreation {
            audience: AUDIENCE,
            channel: CHANNEL,
            mls_enabled: true,
            ttl_seconds: Some(86_400),
            owner_callback_name: Some("agntcy/shadi/avatar-owner"),
        };
        let document: Value =
            serde_json::from_slice(&sign_create(&owner, &creation, LATER).unwrap()).unwrap();
        assert_eq!(document["owner"], owner.did().as_str());
        let signed = format!(
            "SLIM-CHANNEL-CREATE/1\0{AUDIENCE}\0{CHANNEL}\0{}\0true\086400\0agntcy/shadi/avatar-owner\0{LATER}\0{}",
            owner.did(),
            document["nonce"].as_str().unwrap()
        );
        assert!(verifies(&owner, &document, signed));
    }

    #[test]
    fn unset_settings_are_left_out_and_signed_as_empty() {
        let owner = AgentIdentity::generate().unwrap();
        let creation = ChannelCreation {
            audience: AUDIENCE,
            channel: CHANNEL,
            mls_enabled: false,
            ttl_seconds: None,
            owner_callback_name: None,
        };
        let document: Value =
            serde_json::from_slice(&sign_create(&owner, &creation, LATER).unwrap()).unwrap();
        assert!(
            document.get("ttl_seconds").is_none() && document.get("owner_callback_name").is_none()
        );
        let signed = format!(
            "SLIM-CHANNEL-CREATE/1\0{AUDIENCE}\0{CHANNEL}\0{}\0false\0\0\0{LATER}\0{}",
            owner.did(),
            document["nonce"].as_str().unwrap()
        );
        assert!(verifies(&owner, &document, signed));
    }

    #[test]
    fn a_delete_is_signed_over_the_channel_managers_canonical_bytes() {
        let owner = AgentIdentity::generate().unwrap();
        let document: Value =
            serde_json::from_slice(&sign_delete(&owner, AUDIENCE, CHANNEL, LATER).unwrap())
                .unwrap();
        let signed = format!(
            "SLIM-CHANNEL-DELETE/1\0{AUDIENCE}\0{CHANNEL}\0{LATER}\0{}",
            document["nonce"].as_str().unwrap()
        );
        assert!(verifies(&owner, &document, signed));
    }

    #[test]
    fn malformed_requests_are_refused_before_signing() {
        let owner = AgentIdentity::generate().unwrap();
        let creation = |audience, channel, ttl_seconds, owner_callback_name| ChannelCreation {
            audience,
            channel,
            mls_enabled: true,
            ttl_seconds,
            owner_callback_name,
        };
        for bad in [
            creation("", CHANNEL, None, None),
            creation("agntcy/shadi/cm\0x", CHANNEL, None, None),
            creation(AUDIENCE, "agntcy/shadi", None, None),
            creation(AUDIENCE, CHANNEL, Some(0), None),
            creation(AUDIENCE, CHANNEL, None, Some("")),
        ] {
            assert!(sign_create(&owner, &bad, LATER).is_err(), "{bad:?}");
        }
        assert!(sign_delete(&owner, AUDIENCE, "not a channel", LATER).is_err());
    }
}
