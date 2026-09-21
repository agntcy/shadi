// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Human-to-agent binding certificates.
//!
//! An agent DID proves which agent is speaking. It says nothing about whose
//! agent it is: `AgentIdentity::derive` runs HKDF over the human's *secret*,
//! so the parentage is real but unverifiable by anyone else. A binding is the
//! human key's signature over the agent DID, which makes that parentage
//! checkable by any peer holding the human DID — and `did:key` is
//! self-certifying, so holding the DID *is* holding the public key.
//!
//! Signature rather than derivation because there is no standard public
//! derivation for Ed25519; see agntcy/shadi#141.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier};

use crate::{parse_did_key, AgentIdentity, IdentityError};

const MAGIC: &[u8] = b"SHADI-AGENT-BINDING/1";
const DOMAIN: &[u8] = b"SHADI-AGENT-BINDING/1";

/// Maximum size of a whole binding certificate.
pub const BINDING_MAX_BYTES: usize = 4096;

/// Maximum length of any single line in a certificate.
pub const BINDING_LINE_MAX_BYTES: usize = 1024;

/// A binding whose signature has been checked against the human DID it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBinding {
    pub human_did: String,
    pub agent_did: String,
    pub agent_name: String,
    /// Unix seconds after which the binding is no longer accepted.
    pub not_after: u64,
}

/// True when `bytes` start with the binding certificate header.
pub fn looks_like_binding(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC) && bytes.get(MAGIC.len()) == Some(&b'\n')
}

/// Issue a binding: `human` signs that `agent_did` is its agent `agent_name`.
///
/// The human key is the root identity — an SSH key published at
/// `github.com/<user>.keys` in the #140 model — so issuing requires the human
/// secret, exactly as deriving the agent key already does.
pub fn issue_binding(
    human: &AgentIdentity,
    agent_did: &str,
    agent_name: &str,
    not_after: u64,
) -> Result<Vec<u8>, IdentityError> {
    let human_did = human.did();
    // Reject up front rather than emitting a certificate no verifier accepts.
    parse_did_key(agent_did)?;
    for (what, line) in [("agent name", agent_name), ("agent DID", agent_did)] {
        if line.is_empty() {
            return Err(IdentityError::Proof(format!("{what} cannot be empty")));
        }
        if line.contains('\n') {
            return Err(IdentityError::Proof(format!(
                "{what} cannot contain a newline"
            )));
        }
        if line.len() > BINDING_LINE_MAX_BYTES {
            return Err(IdentityError::Proof(format!(
                "{what} exceeds {BINDING_LINE_MAX_BYTES} bytes"
            )));
        }
    }

    let sig = human.sign_bytes(&canonical(&human_did, agent_did, agent_name, not_after));
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

    let mut out = Vec::with_capacity(BINDING_MAX_BYTES / 4);
    out.extend_from_slice(MAGIC);
    for line in [
        human_did.as_str(),
        agent_did,
        agent_name,
        &not_after.to_string(),
        &sig_b64,
    ] {
        out.push(b'\n');
        out.extend_from_slice(line.as_bytes());
    }
    Ok(out)
}

/// Verify a binding certificate, rejecting one that expired before `now`.
///
/// The public key comes from the `human_did` the certificate names, so a peer
/// that copies another human's DID into the header but signs with its own key
/// fails here.
pub fn verify_binding(certificate: &[u8], now: u64) -> Result<VerifiedBinding, IdentityError> {
    if certificate.len() > BINDING_MAX_BYTES {
        return Err(IdentityError::Proof(format!(
            "binding certificate exceeds {BINDING_MAX_BYTES} bytes"
        )));
    }

    let mut lines = certificate.split(|b| *b == b'\n');
    let magic = lines
        .next()
        .ok_or_else(|| IdentityError::Proof("empty binding certificate".to_string()))?;
    if magic != MAGIC {
        return Err(IdentityError::Proof(
            "not a SHADI-AGENT-BINDING/1 certificate".to_string(),
        ));
    }

    let mut field = |what: &str| -> Result<String, IdentityError> {
        let raw = lines
            .next()
            .ok_or_else(|| IdentityError::Proof(format!("binding is missing its {what}")))?;
        if raw.len() > BINDING_LINE_MAX_BYTES {
            return Err(IdentityError::Proof(format!(
                "binding {what} exceeds {BINDING_LINE_MAX_BYTES} bytes"
            )));
        }
        std::str::from_utf8(raw)
            .map(str::to_string)
            .map_err(|_| IdentityError::Proof(format!("binding {what} is not UTF-8")))
    };

    let human_did = field("human DID")?;
    let agent_did = field("agent DID")?;
    let agent_name = field("agent name")?;
    let not_after_raw = field("expiry")?;
    let sig_b64 = field("signature")?;

    let not_after: u64 = not_after_raw.parse().map_err(|_| {
        IdentityError::Proof(format!(
            "binding expiry {not_after_raw:?} is not a unix timestamp"
        ))
    })?;

    let human_key = parse_did_key(&human_did)?;
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|e| IdentityError::Proof(format!("binding signature is not base64: {e}")))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| IdentityError::Proof("binding signature is not 64 bytes".to_string()))?;

    human_key
        .verify(
            &canonical(&human_did, &agent_did, &agent_name, not_after),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| {
            IdentityError::Proof(
                "binding signature does not verify under the human DID it names".to_string(),
            )
        })?;

    // Only after the signature: an expiry check on unauthenticated bytes says
    // nothing.
    if now > not_after {
        return Err(IdentityError::Proof(format!(
            "binding expired at {not_after} (now {now})"
        )));
    }

    // The agent DID has to be a usable key, not just a well-signed string.
    parse_did_key(&agent_did)?;

    Ok(VerifiedBinding {
        human_did,
        agent_did,
        agent_name,
        not_after,
    })
}

/// Split a certificate carried as a prefix of `bytes` from what follows.
///
/// A binding travels inside the agent's own DID-proof payload, so it is a
/// header on a larger message rather than the whole of it. The certificate is
/// the magic line plus five fields; everything after them is the payload.
pub fn split_binding(bytes: &[u8]) -> Result<(&[u8], &[u8]), IdentityError> {
    if !looks_like_binding(bytes) {
        return Err(IdentityError::Proof(
            "not a SHADI-AGENT-BINDING/1 certificate".to_string(),
        ));
    }
    let mut end = MAGIC.len();
    for _ in 0..5 {
        let rest = &bytes[end + 1..];
        let rel = rest
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| IdentityError::Proof("binding certificate is truncated".to_string()))?;
        end += 1 + rel;
        if end > BINDING_MAX_BYTES {
            return Err(IdentityError::Proof(format!(
                "binding certificate exceeds {BINDING_MAX_BYTES} bytes"
            )));
        }
    }
    Ok((&bytes[..end], &bytes[end + 1..]))
}

fn canonical(human_did: &str, agent_did: &str, agent_name: &str, not_after: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(DOMAIN);
    for part in [human_did, agent_did, agent_name, &not_after.to_string()] {
        msg.push(0);
        msg.extend_from_slice(part.as_bytes());
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const LATER: u64 = NOW + 3600;

    fn human_and_agent() -> (AgentIdentity, AgentIdentity) {
        let human = AgentIdentity::generate().unwrap();
        let agent = AgentIdentity::derive(b"human-root-secret", "claude-code").unwrap();
        (human, agent)
    }

    #[test]
    fn a_binding_issued_by_the_human_verifies_under_its_did() {
        let (human, agent) = human_and_agent();
        let cert = issue_binding(&human, &agent.did(), "claude-code", LATER).unwrap();

        assert!(looks_like_binding(&cert));
        let verified = verify_binding(&cert, NOW).unwrap();
        assert_eq!(verified.human_did, human.did());
        assert_eq!(verified.agent_did, agent.did());
        assert_eq!(verified.agent_name, "claude-code");
        assert_eq!(verified.not_after, LATER);
    }

    #[test]
    fn a_binding_naming_a_human_it_was_not_signed_by_is_rejected() {
        let (human, agent) = human_and_agent();
        let impostor = AgentIdentity::generate().unwrap();
        let cert = issue_binding(&impostor, &agent.did(), "claude-code", LATER).unwrap();

        // Swap the header to claim the real human, keeping the impostor's
        // signature — the public key comes from the claimed DID, so this fails.
        let forged = String::from_utf8(cert)
            .unwrap()
            .replacen(&impostor.did(), &human.did(), 1)
            .into_bytes();

        let err = verify_binding(&forged, NOW).unwrap_err();
        assert!(
            err.to_string().contains("does not verify"),
            "should fail signature verification"
        );
    }

    #[test]
    fn rebinding_the_certificate_to_another_agent_is_rejected() {
        let (human, agent) = human_and_agent();
        let other = AgentIdentity::derive(b"human-root-secret", "copilot").unwrap();
        let cert = issue_binding(&human, &agent.did(), "claude-code", LATER).unwrap();

        let stolen = String::from_utf8(cert)
            .unwrap()
            .replacen(&agent.did(), &other.did(), 1)
            .into_bytes();

        assert!(verify_binding(&stolen, NOW).is_err());
    }

    #[test]
    fn renaming_the_agent_is_rejected() {
        let (human, agent) = human_and_agent();
        let cert = issue_binding(&human, &agent.did(), "claude-code", LATER).unwrap();
        let renamed = String::from_utf8(cert)
            .unwrap()
            .replacen("claude-code", "copilot", 1)
            .into_bytes();

        assert!(verify_binding(&renamed, NOW).is_err());
    }

    #[test]
    fn extending_the_expiry_is_rejected() {
        let (human, agent) = human_and_agent();
        let cert = issue_binding(&human, &agent.did(), "claude-code", NOW - 1).unwrap();
        let extended = String::from_utf8(cert)
            .unwrap()
            .replacen(&(NOW - 1).to_string(), &LATER.to_string(), 1)
            .into_bytes();

        // The expiry is signed, so pushing it out breaks the signature rather
        // than buying more time.
        let err = verify_binding(&extended, NOW).unwrap_err();
        assert!(
            err.to_string().contains("does not verify"),
            "should fail signature verification"
        );
    }

    #[test]
    fn an_expired_binding_is_rejected() {
        let (human, agent) = human_and_agent();
        let cert = issue_binding(&human, &agent.did(), "claude-code", NOW - 1).unwrap();
        let err = verify_binding(&cert, NOW).unwrap_err();
        assert!(err.to_string().contains("expired"), "should report expiry");
        // Valid before it lapsed.
        assert!(verify_binding(&cert, NOW - 2).is_ok());
    }

    #[test]
    fn a_binding_carried_as_a_header_splits_from_its_payload() {
        let (human, agent) = human_and_agent();
        let mut envelope = issue_binding(&human, &agent.did(), "claude-code", LATER).unwrap();
        envelope.push(b'\n');
        envelope.extend_from_slice(b"the actual prompt\nwith two lines");

        let (cert, rest) = split_binding(&envelope).unwrap();
        assert_eq!(rest, b"the actual prompt\nwith two lines");
        let verified = verify_binding(cert, NOW).unwrap();
        assert_eq!(verified.agent_did, agent.did());
    }

    #[test]
    fn splitting_a_truncated_certificate_fails() {
        let (human, agent) = human_and_agent();
        let cert = issue_binding(&human, &agent.did(), "claude-code", LATER).unwrap();
        // Every prefix short of the full five fields is truncated. The last
        // field has no trailing newline, so the whole certificate is one too.
        for cut in [MAGIC.len(), MAGIC.len() + 8, cert.len() / 2, cert.len()] {
            assert!(
                split_binding(&cert[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
    }

    #[test]
    fn splitting_something_that_is_not_a_certificate_fails() {
        let err = split_binding(b"WRONG-MAGIC/1\na\nb\nc\n1\nd\npayload").unwrap_err();
        assert!(
            err.to_string().contains("not a SHADI-AGENT-BINDING/1"),
            "should reject a foreign magic line"
        );
        assert!(split_binding(b"").is_err());
    }

    #[test]
    fn splitting_stops_at_the_size_cap() {
        // A header whose fields never end must not be scanned without bound.
        let mut flood = Vec::from(MAGIC);
        flood.push(b'\n');
        flood.extend(std::iter::repeat_n(b'a', BINDING_MAX_BYTES * 2));
        flood.push(b'\n');
        let err = split_binding(&flood).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "should report the size cap"
        );
    }

    #[test]
    fn issuing_rejects_a_field_longer_than_the_line_cap() {
        let (human, agent) = human_and_agent();
        let long_name = "n".repeat(BINDING_LINE_MAX_BYTES + 1);
        let err = issue_binding(&human, &agent.did(), &long_name, LATER).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "should report the size cap"
        );
    }

    #[test]
    fn verifying_rejects_a_field_longer_than_the_line_cap() {
        let (human, agent) = human_and_agent();
        let cert = issue_binding(&human, &agent.did(), "claude-code", LATER).unwrap();
        // Swap the agent name for one past the cap; the signature would fail
        // anyway, but the length guard has to fire first.
        let bloated = String::from_utf8(cert)
            .unwrap()
            .replacen("claude-code", &"n".repeat(BINDING_LINE_MAX_BYTES + 1), 1)
            .into_bytes();
        let err = verify_binding(&bloated, NOW).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "should report the size cap"
        );
    }

    #[test]
    fn verifying_rejects_an_expiry_that_is_not_a_timestamp() {
        let (human, agent) = human_and_agent();
        let cert = issue_binding(&human, &agent.did(), "claude-code", LATER).unwrap();
        let mangled = String::from_utf8(cert)
            .unwrap()
            .replacen(&LATER.to_string(), "not-a-number", 1)
            .into_bytes();
        let err = verify_binding(&mangled, NOW).unwrap_err();
        assert!(
            err.to_string().contains("unix timestamp"),
            "should report a bad timestamp"
        );
    }

    #[test]
    fn malformed_certificates_are_rejected_without_panicking() {
        for bad in [
            &b""[..],
            b"SHADI-AGENT-BINDING/1",
            b"SHADI-AGENT-BINDING/1\n",
            b"SHADI-AGENT-BINDING/1\ndid:key:zBAD\nx\ny\n1\nz",
            b"WRONG-MAGIC/1\na\nb\nc\n1\nd",
            b"SHADI-AGENT-BINDING/1\ndid:web:nope\ndid:web:nope\nn\n1\nAAAA",
        ] {
            assert!(verify_binding(bad, NOW).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn an_oversize_certificate_is_rejected_before_parsing() {
        let flood = vec![b'a'; BINDING_MAX_BYTES + 1];
        let err = verify_binding(&flood, NOW).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "should report the size cap"
        );
    }

    #[test]
    fn issuing_rejects_an_agent_did_that_is_not_a_key() {
        let human = AgentIdentity::generate().unwrap();
        assert!(issue_binding(&human, "did:web:nope", "claude-code", LATER).is_err());
        let agent = AgentIdentity::generate().unwrap();
        assert!(issue_binding(&human, &agent.did(), "", LATER).is_err());
        assert!(issue_binding(&human, &agent.did(), "has\nnewline", LATER).is_err());
    }
}
