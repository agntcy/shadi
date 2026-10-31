// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SD-JWT VC: the one credential format the vault currently holds.
//!
//! **Parsing here is mostly structural.** Nothing verifies the issuer
//! signature, checks the key binding or evaluates any policy: a credential
//! that would fail verification is still storable, deliberately, so the
//! failure surfaces where it can be reported well rather than as "cannot
//! store".
//!
//! The one binding that is checked: every disclosure must be committed to by
//! a digest in the issuer JWT (or in another disclosure). A disclosure the
//! issuer never committed to would read as an issuer claim to anyone who
//! pulls the credential out of the vault, so it is refused here rather than
//! left to each caller. Only `sha-256` digests can be checked; any other
//! `_sd_alg` is refused.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::store::CredentialRecord;

use crate::vault::CredentialVault;
use crate::CredentialError;

/// The only issuer JWT `typ` this module reads.
pub const SD_JWT_FORMAT: &str = "dc+sd-jwt";

/// One disclosure: `[salt, name, value]`, or `[salt, value]` for an array
/// element, which has no name.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Disclosure {
    pub name: Option<String>,
    pub value: Value,
    /// The base64url segment exactly as the issuer wrote it. A presentation
    /// hashes what it sends, and re-encoding the parsed value does not
    /// reliably reproduce these bytes.
    pub raw: String,
}

/// What the vault lifts out of a credential at import.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ParsedCredential {
    pub issuer: String,
    pub credential_type: String,
    /// The issuer JWT's `typ`, e.g. `dc+sd-jwt`.
    pub format: String,
    /// `cnf.jwk` resolved to the `did:key` of the agent that may present it.
    pub agent_did: String,
    /// `None` when the credential carries no `exp`; `exp` is optional in
    /// SD-JWT VC, and such a credential is treated as non-expiring.
    pub expires_at: Option<i64>,
    pub disclosures: Vec<Disclosure>,
}

fn decode_segment(segment: &str, what: &str) -> Result<Vec<u8>, CredentialError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| CredentialError::Malformed(format!("{what} is not base64url")))
}

pub(crate) fn decode_json(segment: &str, what: &str) -> Result<Value, CredentialError> {
    let bytes = decode_segment(segment, what)?;
    serde_json::from_slice(&bytes)
        .map_err(|err| CredentialError::Malformed(format!("{what} is not JSON: {err}")))
}

/// Split a compact SD-JWT and read `typ`, `iss`, `vct`, `exp` and `cnf` out of
/// the issuer JWT, without verifying anything.
pub fn parse_sd_jwt(raw: &str) -> Result<ParsedCredential, CredentialError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(CredentialError::Malformed("empty input".to_string()));
    }

    let parts: Vec<&str> = raw.split('~').collect();
    // `<issuer-jwt>~<disclosure>~…~` — the trailing tilde is mandatory when
    // there is no key-binding JWT, and a stored credential never has one: a
    // KB-JWT is bound to one verifier, nonce and disclosure set, so it is
    // already spent by the time it could be reused.
    //
    // Without that tilde the final element is a KB-JWT by definition, but a
    // truncated credential looks the same, so tell them apart by shape: a
    // KB-JWT has three dot-separated segments, a disclosure has none.
    match parts.last() {
        Some(&"") => {}
        Some(last) if parts.len() > 1 && last.split('.').count() == 3 => {
            return Err(CredentialError::Malformed(
                "this is a presentation, not an issued credential: it carries a key-binding JWT"
                    .to_string(),
            ))
        }
        _ => {
            return Err(CredentialError::Malformed(
                "missing the trailing `~` that ends a credential with no key-binding JWT"
                    .to_string(),
            ))
        }
    }

    let issuer_jwt: Vec<&str> = parts[0].split('.').collect();
    if issuer_jwt.len() != 3 {
        return Err(CredentialError::Malformed(
            "the issuer JWT is not three dot-separated segments".to_string(),
        ));
    }

    // A plain JWT with a trailing `~` is structurally close enough to pass
    // everything else here, so `typ` is the only thing that says this is an
    // SD-JWT VC the vault can read back.
    let header = decode_json(issuer_jwt[0], "the issuer JWT header")?;
    let format = required_str(&header, "typ")?;
    if format != SD_JWT_FORMAT {
        return Err(CredentialError::Malformed(format!(
            "the issuer JWT `typ` is {format}, expected {SD_JWT_FORMAT}"
        )));
    }

    let payload = decode_json(issuer_jwt[1], "the issuer JWT payload")?;
    let issuer = required_str(&payload, "iss")?;
    let credential_type = required_str(&payload, "vct")?;

    let expires_at = match payload.get("exp") {
        None | Some(Value::Null) => None,
        // NumericDate may be fractional; floor so it can only expire earlier.
        Some(value) => Some(
            value
                .as_i64()
                .or_else(|| value.as_f64().map(|f| f.floor() as i64))
                .ok_or_else(|| {
                    CredentialError::Malformed("`exp` is not a number of seconds".to_string())
                })?,
        ),
    };

    let jwk = payload
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .ok_or_else(|| {
            CredentialError::Malformed(
                "no `cnf.jwk`: the credential is not key-bound and could never be presented"
                    .to_string(),
            )
        })?;
    let agent_did = did_from_jwk(jwk)?;

    let disclosures = parts[1..parts.len() - 1]
        .iter()
        .map(|part| parse_disclosure(part))
        .collect::<Result<Vec<_>, _>>()?;
    check_committed(&payload, &disclosures)?;

    Ok(ParsedCredential {
        issuer,
        credential_type,
        format,
        agent_did,
        expires_at,
        disclosures,
    })
}

/// Every disclosure's digest must appear in the issuer payload or in another
/// disclosure's value. The digests are pooled, so this proves the issuer
/// committed to each disclosure somewhere, not that it attaches where a reader
/// will interpret it.
fn check_committed(payload: &Value, disclosures: &[Disclosure]) -> Result<(), CredentialError> {
    match payload.get("_sd_alg") {
        None => {}
        Some(Value::String(alg)) if alg == "sha-256" => {}
        Some(_) => {
            return Err(CredentialError::Malformed(
                "`_sd_alg` is not sha-256, so disclosures cannot be checked".to_string(),
            ))
        }
    }

    let mut committed = HashSet::new();
    collect_digests(payload, &mut committed);
    for d in disclosures {
        collect_digests(&d.value, &mut committed);
    }
    for d in disclosures {
        if !committed.contains(&URL_SAFE_NO_PAD.encode(Sha256::digest(d.raw.as_bytes()))) {
            let claim = d.name.as_deref().map_or_else(
                || "an array element".to_string(),
                |name| format!("`{name}`"),
            );
            return Err(CredentialError::Malformed(format!(
                "the disclosure for {claim} is not committed to by the issuer"
            )));
        }
    }
    Ok(())
}

/// Gather `_sd` array entries and `{"...": digest}` array-element markers.
fn collect_digests(value: &Value, out: &mut HashSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get("_sd") {
                out.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
            }
            if let (1, Some(Value::String(digest))) = (map.len(), map.get("...")) {
                out.insert(digest.clone());
            }
            map.values().for_each(|v| collect_digests(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| collect_digests(v, out)),
        _ => {}
    }
}

fn required_str(value: &Value, claim: &str) -> Result<String, CredentialError> {
    value
        .get(claim)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| CredentialError::Malformed(format!("no `{claim}` claim")))
}

/// `cnf.jwk` must be the Ed25519 key the credential is bound to; the `did:key`
/// is what `find_valid` filters on and what the operator sees.
fn did_from_jwk(jwk: &Value) -> Result<String, CredentialError> {
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or_default();
    let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or_default();
    if kty != "OKP" || crv != "Ed25519" {
        return Err(CredentialError::Malformed(format!(
            "`cnf.jwk` is {kty}/{crv}, not OKP/Ed25519"
        )));
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| CredentialError::Malformed("`cnf.jwk` has no `x`".to_string()))?;
    let bytes: [u8; 32] = decode_segment(x, "`cnf.jwk.x`")?
        .try_into()
        .map_err(|_| CredentialError::Malformed("`cnf.jwk.x` is not 32 bytes".to_string()))?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
        CredentialError::Malformed("`cnf.jwk.x` is not an Ed25519 public key".to_string())
    })?;
    Ok(shadi_identity::encode_did_key(&key))
}

fn parse_disclosure(segment: &str) -> Result<Disclosure, CredentialError> {
    let parsed = decode_json(segment, "a disclosure")?;
    let Some(array) = parsed.as_array() else {
        return Err(CredentialError::Malformed(
            "a disclosure is not a JSON array".to_string(),
        ));
    };
    match array.len() {
        2 => Ok(Disclosure {
            name: None,
            value: array[1].clone(),
            raw: segment.to_string(),
        }),
        3 => Ok(Disclosure {
            name: Some(
                array[1]
                    .as_str()
                    .ok_or_else(|| {
                        CredentialError::Malformed(
                            "a disclosure's claim name is not a string".to_string(),
                        )
                    })?
                    .to_string(),
            ),
            value: array[2].clone(),
            raw: segment.to_string(),
        }),
        other => Err(CredentialError::Malformed(format!(
            "a disclosure has {other} elements, expected 2 or 3"
        ))),
    }
}

/// Parse `raw`, store it verbatim under a fresh vault-assigned id, and return
/// the stored record.
///
/// The id is ours, not the issuer's: a credential carries no stable id we
/// control, and `jti` is visible to every verifier, so reusing it as a local
/// handle would be both fragile and a correlation aid.
pub fn import(
    vault: &dyn CredentialVault,
    raw: &str,
    now: i64,
) -> Result<CredentialRecord, CredentialError> {
    let parsed = parse_sd_jwt(raw)?;
    let record = CredentialRecord {
        id: uuid::Uuid::new_v4().to_string(),
        agent_did: parsed.agent_did,
        issuer: parsed.issuer,
        credential_type: parsed.credential_type,
        format: parsed.format,
        // Verbatim, disclosures included: one dropped at rest can never be
        // presented later.
        raw: raw.trim().to_string(),
        created_at: now,
        expires_at: parsed.expires_at,
    };
    vault.put(&record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::sqlcipher_vault;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The agent key the fixture credentials are bound to. Fixed bytes so the
    /// expected `did:key` is stable.
    fn holder_key() -> VerifyingKey {
        VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]))
    }

    fn holder_jwk() -> Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(holder_key().as_bytes()),
        })
    }

    fn digest_of(segment: &str) -> String {
        b64(&Sha256::digest(segment.as_bytes()))
    }

    fn disclosure(name: &str, value: Value) -> String {
        b64(serde_json::json!(["c2FsdA", name, value])
            .to_string()
            .as_bytes())
    }

    /// A credential in the shape the vault stores: issuer JWT, disclosures,
    /// trailing tilde, no KB-JWT.
    fn credential_with(mut payload: Value, disclosures: &[String]) -> String {
        let sd: Vec<String> = disclosures.iter().map(|d| digest_of(d)).collect();
        payload["_sd"] = serde_json::json!(sd);
        credential_with_header(
            serde_json::json!({"alg": "EdDSA", "typ": "dc+sd-jwt"}),
            payload,
            disclosures,
        )
    }

    fn credential_with_header(header: Value, payload: Value, disclosures: &[String]) -> String {
        let mut raw = format!(
            "{}.{}.c2ln",
            b64(header.to_string().as_bytes()),
            b64(payload.to_string().as_bytes())
        );
        for part in disclosures {
            raw.push('~');
            raw.push_str(part);
        }
        raw.push('~');
        raw
    }

    fn payload() -> Value {
        serde_json::json!({
            "iss": "https://idp.example/realms/eng",
            "vct": "urn:shadi:agent-admission:1",
            "exp": 2_000,
            "cnf": { "jwk": holder_jwk() },
            "_sd_alg": "sha-256",
        })
    }

    fn fixture() -> String {
        credential_with(
            payload(),
            &[
                disclosure("groups", serde_json::json!("platform-admins")),
                disclosure("email", serde_json::json!("alice@example.test")),
            ],
        )
    }

    #[test]
    fn parses_an_issued_credential() {
        let parsed = parse_sd_jwt(&fixture()).expect("parse");
        assert_eq!(parsed.issuer, "https://idp.example/realms/eng");
        assert_eq!(parsed.credential_type, "urn:shadi:agent-admission:1");
        assert_eq!(parsed.format, "dc+sd-jwt");
        assert_eq!(
            parsed.agent_did,
            shadi_identity::encode_did_key(&holder_key())
        );
        assert_eq!(parsed.expires_at, Some(2_000));
        let names: Vec<_> = parsed
            .disclosures
            .iter()
            .map(|d| d.name.clone().unwrap())
            .collect();
        assert_eq!(names, vec!["groups", "email"]);
        assert_eq!(
            parsed.disclosures[0].value,
            serde_json::json!("platform-admins")
        );
    }

    /// Only `dc+sd-jwt` is readable: a plain JWT with a trailing `~` must be
    /// refused at import, not stored and then reported unsupported at `show`.
    #[test]
    fn rejects_any_typ_other_than_dc_sd_jwt() {
        for typ in ["JWT", "foo-sd-jwt"] {
            let raw = credential_with_header(
                serde_json::json!({"alg": "EdDSA", "typ": typ}),
                payload(),
                &[],
            );
            let err = parse_sd_jwt(&raw).expect_err("reject");
            assert!(err.to_string().contains(typ), "{typ}: {err}");
        }

        let ok = credential_with_header(
            serde_json::json!({"alg": "EdDSA", "typ": SD_JWT_FORMAT}),
            payload(),
            &[],
        );
        assert_eq!(parse_sd_jwt(&ok).expect("parse").format, "dc+sd-jwt");
    }

    #[test]
    fn rejects_a_credential_with_no_typ() {
        let raw = credential_with_header(serde_json::json!({"alg": "EdDSA"}), payload(), &[]);
        let err = parse_sd_jwt(&raw).expect_err("reject");
        assert!(err.to_string().contains("`typ`"), "{err}");
    }

    #[test]
    fn a_credential_without_exp_parses_as_non_expiring() {
        let mut payload = payload();
        payload.as_object_mut().unwrap().remove("exp");
        let parsed = parse_sd_jwt(&credential_with(payload, &[])).expect("parse");
        assert_eq!(parsed.expires_at, None);
    }

    #[test]
    fn rejects_a_presentation() {
        let raw = format!("{}kb.jwt.sig", fixture());
        let err = parse_sd_jwt(&raw).expect_err("reject");
        assert!(err.to_string().contains("key-binding JWT"), "{err}");
    }

    #[test]
    fn rejects_a_missing_trailing_tilde() {
        let raw = fixture();
        let err = parse_sd_jwt(raw.trim_end_matches('~')).expect_err("reject");
        assert!(err.to_string().contains("trailing"), "{err}");
    }

    #[test]
    fn rejects_malformed_input_with_a_reason() {
        for (raw, needle) in [
            ("", "empty"),
            ("not-a-jwt~", "three dot-separated"),
            ("a.!!!.c~", "not base64url"),
            (
                format!("{}.{}.sig~", b64(b"{}"), b64(b"not json")).as_str(),
                "`typ`",
            ),
        ] {
            let err = parse_sd_jwt(raw).expect_err("reject");
            assert!(err.to_string().contains(needle), "{raw}: {err}");
        }
    }

    #[test]
    fn rejects_a_credential_missing_iss_vct_or_cnf() {
        for (claim, needle) in [("iss", "`iss`"), ("vct", "`vct`"), ("cnf", "`cnf.jwk`")] {
            let mut payload = payload();
            payload.as_object_mut().unwrap().remove(claim);
            let err = parse_sd_jwt(&credential_with(payload, &[])).expect_err("reject");
            assert!(err.to_string().contains(needle), "{claim}: {err}");
        }
    }

    #[test]
    fn rejects_a_non_ed25519_cnf_key() {
        let mut payload = payload();
        payload["cnf"]["jwk"] = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AAAA"});
        let err = parse_sd_jwt(&credential_with(payload, &[])).expect_err("reject");
        assert!(err.to_string().contains("OKP/Ed25519"), "{err}");
    }

    /// An `x` of the right length is not yet a key: `agent_did` is derived from
    /// it, so a value that is not a point would bind the credential to a DID no
    /// agent can ever hold.
    #[test]
    fn rejects_a_cnf_key_that_is_not_a_point_on_the_curve() {
        // A `y` coordinate with no matching `x`, so decompression fails.
        let mut off_curve = [0u8; 32];
        off_curve[31] = 1;

        for (x, needle) in [
            (b64(&off_curve), "not an Ed25519 public key"),
            (b64(&[7u8; 31]), "not 32 bytes"),
        ] {
            let mut payload = payload();
            payload["cnf"]["jwk"]["x"] = serde_json::json!(x);
            let err = parse_sd_jwt(&credential_with(payload, &[])).expect_err("reject");
            assert!(err.to_string().contains(needle), "{x}: {err}");
        }
    }

    /// `exp` drives `find_valid`. A non-numeric one must be refused at import
    /// rather than silently stored as non-expiring.
    #[test]
    fn rejects_a_non_numeric_exp() {
        let mut payload = payload();
        payload["exp"] = serde_json::json!("2026-10-13T00:00:00Z");
        let err = parse_sd_jwt(&credential_with(payload, &[])).expect_err("reject");
        assert!(err.to_string().contains("number of seconds"), "{err}");
    }

    /// RFC 7519 NumericDate permits a fractional value.
    #[test]
    fn a_fractional_exp_is_floored() {
        let mut payload = payload();
        payload["exp"] = serde_json::json!(2000.5);
        let parsed = parse_sd_jwt(&credential_with(payload, &[])).expect("parse");
        assert_eq!(parsed.expires_at, Some(2_000));
    }

    #[test]
    fn rejects_a_malformed_disclosure() {
        for (body, needle) in [
            (br#"["salt"]"#.to_vec(), "expected 2 or 3"),
            (br#"{"salt":"x"}"#.to_vec(), "not a JSON array"),
            (
                br#"["salt", 7, "value"]"#.to_vec(),
                "claim name is not a string",
            ),
        ] {
            let raw = credential_with(payload(), &[b64(&body)]);
            let err = parse_sd_jwt(&raw).expect_err("reject");
            assert!(err.to_string().contains(needle), "{needle}: {err}");
        }
    }

    #[test]
    fn errors_never_contain_the_credential() {
        let raw = credential_with(payload(), &[b64(br#"["salt"]"#)]);
        let err = parse_sd_jwt(&raw).expect_err("reject").to_string();
        assert!(!err.contains(&raw));
    }

    #[test]
    fn parses_an_array_element_disclosure() {
        let raw = credential_with(
            payload(),
            &[b64(serde_json::json!(["c2FsdA", "value"])
                .to_string()
                .as_bytes())],
        );
        let parsed = parse_sd_jwt(&raw).expect("parse");
        assert_eq!(parsed.disclosures[0].name, None);
        assert_eq!(parsed.disclosures[0].value, serde_json::json!("value"));
    }

    #[test]
    fn rejects_an_appended_disclosure() {
        let appended = disclosure("admin", serde_json::json!("sekrit-value"));
        let raw = format!("{}{appended}~", fixture());
        let err = parse_sd_jwt(&raw).expect_err("reject").to_string();
        assert!(err.contains("`admin`"), "{err}");
        assert!(!err.contains("sekrit-value"), "{err}");
        assert!(import(&sqlcipher_vault(), &raw, 1_000).is_err());
    }

    #[test]
    fn an_appended_array_element_is_named_as_such() {
        let appended = b64(serde_json::json!(["c2FsdA", "sekrit-value"])
            .to_string()
            .as_bytes());
        let raw = format!("{}{appended}~", fixture());
        let err = parse_sd_jwt(&raw).expect_err("reject").to_string();
        assert!(err.contains("an array element"), "{err}");
        assert!(!err.contains("sekrit-value"), "{err}");
    }

    #[test]
    fn committed_disclosures_come_back_in_order() {
        let first = disclosure("a", serde_json::json!(1));
        let second = disclosure("b", serde_json::json!(2));
        let third = disclosure("c", serde_json::json!(3));
        let mut payload = payload();
        // Commitment order differs from presentation order.
        payload["_sd"] =
            serde_json::json!([digest_of(&third), digest_of(&first), digest_of(&second)]);
        let raw = credential_with_header(
            serde_json::json!({"alg": "EdDSA", "typ": "dc+sd-jwt"}),
            payload,
            &[first.clone(), second.clone(), third.clone()],
        );
        let parsed = parse_sd_jwt(&raw).expect("parse");
        let raws: Vec<_> = parsed.disclosures.iter().map(|d| d.raw.clone()).collect();
        assert_eq!(raws, vec![first, second, third]);
    }

    #[test]
    fn accepts_an_array_element_referenced_by_its_marker() {
        let element = b64(serde_json::json!(["c2FsdA", "x"]).to_string().as_bytes());
        let mut payload = payload();
        payload["roles"] = serde_json::json!([{"...": digest_of(&element)}]);
        let raw = credential_with_header(
            serde_json::json!({"alg": "EdDSA", "typ": "dc+sd-jwt"}),
            payload,
            &[element],
        );
        assert!(parse_sd_jwt(&raw).is_ok());
    }

    #[test]
    fn accepts_a_disclosure_committed_inside_another_disclosure() {
        let inner = disclosure("city", serde_json::json!("Oslo"));
        let outer = disclosure(
            "address",
            serde_json::json!({"_sd": [digest_of(&inner)], "country": "NO"}),
        );
        let mut payload = payload();
        payload["_sd"] = serde_json::json!([digest_of(&outer)]);
        let raw = credential_with_header(
            serde_json::json!({"alg": "EdDSA", "typ": "dc+sd-jwt"}),
            payload,
            &[outer, inner],
        );
        assert_eq!(parse_sd_jwt(&raw).expect("parse").disclosures.len(), 2);
    }

    #[test]
    fn rejects_an_unsupported_sd_alg_even_when_digests_match() {
        let mut payload = payload();
        payload["_sd_alg"] = serde_json::json!("sha-512");
        let raw = credential_with(
            payload,
            &[disclosure("groups", serde_json::json!("admins"))],
        );
        let err = parse_sd_jwt(&raw).expect_err("reject");
        assert!(err.to_string().contains("_sd_alg"), "{err}");
    }

    #[test]
    fn a_missing_sd_alg_defaults_to_sha_256() {
        let mut payload = payload();
        payload.as_object_mut().unwrap().remove("_sd_alg");
        let raw = credential_with(
            payload,
            &[disclosure("groups", serde_json::json!("admins"))],
        );
        assert!(parse_sd_jwt(&raw).is_ok());
    }

    #[test]
    fn a_credential_with_no_disclosures_parses() {
        let parsed = parse_sd_jwt(&credential_with(payload(), &[])).expect("parse");
        assert!(parsed.disclosures.is_empty());
    }

    #[test]
    fn rejects_a_one_byte_mutation_of_a_committed_disclosure() {
        let original = disclosure("groups", serde_json::json!("admins"));
        let mut payload = payload();
        payload["_sd"] = serde_json::json!([digest_of(&original)]);
        // Same JSON, different bytes: `["c2FsdA",...]` with a padded space.
        let mutated = b64(
            String::from_utf8(URL_SAFE_NO_PAD.decode(&original).unwrap())
                .unwrap()
                .replacen(',', ", ", 1)
                .as_bytes(),
        );
        assert_ne!(mutated, original);
        let raw = credential_with_header(
            serde_json::json!({"alg": "EdDSA", "typ": "dc+sd-jwt"}),
            payload,
            &[mutated],
        );
        let err = parse_sd_jwt(&raw).expect_err("reject");
        assert!(err.to_string().contains("`groups`"), "{err}");
    }

    #[test]
    fn import_stores_the_credential_verbatim_and_fills_the_columns() {
        let vault = sqlcipher_vault();
        let stored = import(&vault, &fixture(), 1_000).expect("import");

        assert_eq!(stored.raw, fixture());
        assert_eq!(stored.format, "dc+sd-jwt");
        assert_eq!(stored.credential_type, "urn:shadi:agent-admission:1");
        assert_eq!(stored.issuer, "https://idp.example/realms/eng");
        assert_eq!(
            stored.agent_did,
            shadi_identity::encode_did_key(&holder_key())
        );
        assert_eq!(stored.expires_at, Some(2_000));
        assert_eq!(stored.created_at, 1_000);

        assert_eq!(
            vault
                .find_valid(
                    &stored.agent_did,
                    &stored.issuer,
                    &stored.credential_type,
                    1_500
                )
                .expect("find"),
            vec![stored]
        );
    }

    #[test]
    fn import_rejects_a_bad_credential_without_storing() {
        let vault = sqlcipher_vault();
        assert!(import(&vault, "nonsense", 1_000).is_err());
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn each_import_gets_its_own_id() {
        let vault = sqlcipher_vault();
        let first = import(&vault, &fixture(), 1_000).expect("import");
        let second = import(&vault, &fixture(), 1_000).expect("import");
        assert_ne!(first.id, second.id);
        assert_eq!(vault.list().expect("list").len(), 2);
    }
}
