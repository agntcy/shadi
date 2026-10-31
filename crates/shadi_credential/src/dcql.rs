// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The subset of DCQL this holder answers, and the local policy that bounds
//! which selectively disclosable claims it will release.
//!
//! A query arrives inside a challenge the peer wrote, and that reply is not
//! signed, so every byte here is untrusted input: caps apply before anything
//! is interpreted, and the release policy is intersected with the query
//! before a credential is even looked up. `trusted_authorities` narrows which
//! issuer answers rather than widening it: it can only pick among credentials
//! the policy already allows, never release a claim the policy forbids.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::sd_jwt::{parse_sd_jwt, Disclosure};
use crate::store::CredentialRecord;
use crate::vault::{pin_issuer, CredentialVault};
use crate::CredentialError;

/// Bytes of query text accepted: the whole query is peer-written.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;
/// Credential queries per request: a `Selection` carries one credential, and
/// every query must be satisfied, so more than one could never be answered.
pub const MAX_CREDENTIAL_QUERIES: usize = 1;
/// Claims per credential query: bounds per-credential matching work.
pub const MAX_CLAIMS_PER_QUERY: usize = 16;
/// Path elements per claim: a disclosure carries its whole value, so answering
/// a nested path would leak the siblings of the claim asked for.
pub const MAX_PATH_DEPTH: usize = 1;
/// `vct_values` entries per credential query: bounds the any-of list.
pub const MAX_VCT_VALUES: usize = 8;
/// `values` entries per claim: bounds the value probe list.
pub const MAX_CLAIM_VALUES: usize = 8;
/// `trusted_authorities` entries per credential query.
pub const MAX_TRUSTED_AUTHORITIES: usize = 8;
/// `values` entries per `trusted_authorities` entry.
pub const MAX_TRUSTED_AUTHORITY_VALUES: usize = 8;

/// What a verifier asks for.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(from = "WireCredentialQuery")]
#[non_exhaustive]
pub struct CredentialQuery {
    pub id: String,
    pub format: String,
    pub vct_values: Vec<String>,
    pub claims: Vec<ClaimQuery>,
    /// Empty means any held issuer may answer. Non-empty restricts selection
    /// to a record whose issuer appears in some entry's `values` — `type` is
    /// not interpreted, this holder only matches issuer identifiers.
    pub trusted_authorities: Vec<TrustedAuthority>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClaimQuery {
    pub path: Vec<String>,
    /// When present, the verifier is probing for one of these values.
    pub values: Option<Vec<Value>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TrustedAuthority {
    pub r#type: String,
    pub values: Vec<String>,
}

/// The wire nests `vct_values` under `meta`; this flattens it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCredentialQuery {
    id: String,
    format: String,
    meta: WireMeta,
    claims: Vec<ClaimQuery>,
    #[serde(default)]
    trusted_authorities: Vec<TrustedAuthority>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMeta {
    vct_values: Vec<String>,
}

impl From<WireCredentialQuery> for CredentialQuery {
    fn from(wire: WireCredentialQuery) -> Self {
        Self {
            id: wire.id,
            format: wire.format,
            vct_values: wire.meta.vct_values,
            claims: wire.claims,
            trusted_authorities: wire.trusted_authorities,
        }
    }
}

impl DcqlQuery {
    /// Cap the text, parse it, then check the structural caps. Unknown fields
    /// (`credential_sets`, …) are errors, not ignored.
    pub fn parse(text: &str) -> Result<Self, CredentialError> {
        if text.len() > MAX_QUERY_BYTES {
            return Err(malformed(format!("query is over {MAX_QUERY_BYTES} bytes")));
        }
        let query: Self = serde_json::from_str(text)
            .map_err(|err| malformed(format!("unsupported query: {err}")))?;
        query.validate()?;
        Ok(query)
    }

    /// The structural caps. `select` repeats this: the fields are public, so a
    /// query need not have come through `parse`.
    fn validate(&self) -> Result<(), CredentialError> {
        let count = self.credentials.len();
        if count == 0 || count > MAX_CREDENTIAL_QUERIES {
            return Err(malformed(format!(
                "query has {count} credential queries, this holder answers {MAX_CREDENTIAL_QUERIES}"
            )));
        }
        for credential in &self.credentials {
            let id = &credential.id;
            let vcts = credential.vct_values.len();
            if vcts == 0 || vcts > MAX_VCT_VALUES {
                return Err(malformed(format!(
                    "credential query {id:?} has {vcts} vct_values, expected 1 to {MAX_VCT_VALUES}"
                )));
            }
            let claims = credential.claims.len();
            if claims == 0 || claims > MAX_CLAIMS_PER_QUERY {
                return Err(malformed(format!(
                    "credential query {id:?} has {claims} claims, expected 1 to {MAX_CLAIMS_PER_QUERY}"
                )));
            }
            for claim in &credential.claims {
                let depth = claim.path.len();
                if depth == 0 {
                    return Err(malformed(format!("claim path in {id:?} has 0 elements")));
                }
                if depth > MAX_PATH_DEPTH {
                    return Err(malformed(format!(
                        "claim {}: nested claims are not supported",
                        show(&claim.path)
                    )));
                }
                if claim
                    .values
                    .as_ref()
                    .is_some_and(|v| v.len() > MAX_CLAIM_VALUES)
                {
                    return Err(malformed(format!(
                        "claim {} has over {MAX_CLAIM_VALUES} values",
                        show(&claim.path)
                    )));
                }
            }
            let authorities = credential.trusted_authorities.len();
            if authorities > MAX_TRUSTED_AUTHORITIES {
                return Err(malformed(format!(
                    "credential query {id:?} has {authorities} trusted_authorities, over the limit of {MAX_TRUSTED_AUTHORITIES}"
                )));
            }
            for authority in &credential.trusted_authorities {
                let values = authority.values.len();
                if values > MAX_TRUSTED_AUTHORITY_VALUES {
                    return Err(malformed(format!(
                        "credential query {id:?} has a trusted_authorities entry with {values} values, over the limit of {MAX_TRUSTED_AUTHORITY_VALUES}"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn malformed(reason: String) -> CredentialError {
    CredentialError::Malformed(reason)
}

fn show(path: &[String]) -> String {
    format!("`{}`", path.join("."))
}

/// The claim paths this holder will release, and to whom. A peer with its own
/// entry gets exactly that list, not the global one. The default releases
/// nothing.
///
/// Paths are gated, values are not: `ClaimQuery.values` lets a verifier probe
/// for a specific value and read admission as the answer, so a released path
/// is also a membership oracle for that path.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ReleasePolicy {
    global: Vec<Vec<String>>,
    per_peer: HashMap<String, Vec<Vec<String>>>,
}

fn owned(paths: &[&[&str]]) -> Vec<Vec<String>> {
    paths
        .iter()
        .map(|path| path.iter().map(|s| (*s).to_string()).collect())
        .collect()
}

impl ReleasePolicy {
    /// Release exactly `paths` to every peer.
    pub fn new(paths: &[&[&str]]) -> Self {
        Self {
            global: owned(paths),
            per_peer: HashMap::new(),
        }
    }

    /// Replace the global list with `paths` for `peer_did`.
    pub fn with_peer(mut self, peer_did: &str, paths: &[&[&str]]) -> Self {
        self.per_peer.insert(peer_did.to_string(), owned(paths));
        self
    }

    /// May `path` be released to `peer_did`? Exact match only: allowing
    /// `["address"]` does not allow `["address","city"]`.
    pub fn allows(&self, peer_did: &str, path: &[String]) -> bool {
        self.per_peer
            .get(peer_did)
            .unwrap_or(&self.global)
            .iter()
            .any(|allowed| allowed == path)
    }
}

/// A credential and exactly the disclosures that answer the query.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Selection {
    pub record: CredentialRecord,
    pub disclosures: Vec<Disclosure>,
}

/// Pick the credential and the minimum disclosure set that answers `query`.
///
/// Reads `vault.list()` rather than `find_valid`: a query may name the one
/// issuer it trusts via `trusted_authorities`, and a holder's vault is small
/// enough that filtering in memory costs nothing.
pub fn select(
    vault: &dyn CredentialVault,
    agent_did: &str,
    query: &DcqlQuery,
    policy: &ReleasePolicy,
    peer_did: &str,
    now: i64,
) -> Result<Selection, CredentialError> {
    query.validate()?;

    // Before any credential is read: a query outside the policy selects nothing.
    for claim in query.credentials.iter().flat_map(|c| &c.claims) {
        if !policy.allows(peer_did, &claim.path) {
            return Err(CredentialError::Refused(format!(
                "challenge requests claims this holder does not release: {}",
                show(&claim.path)
            )));
        }
    }

    let records = vault.list()?;
    let mut reason = "no held credential matches the requested format and type".to_string();
    // `validate` guarantees exactly one credential query.
    let credential = &query.credentials[0];
    let trusted = |issuer: &str| {
        credential.trusted_authorities.is_empty()
            || credential
                .trusted_authorities
                .iter()
                .any(|a| a.values.iter().any(|v| pin_issuer(v) == pin_issuer(issuer)))
    };
    for record in &records {
        if record.agent_did != agent_did
            || record.format != credential.format
            || !credential.vct_values.contains(&record.credential_type)
            || record.expires_at.is_some_and(|exp| exp <= now)
            || !trusted(&record.issuer)
        {
            continue;
        }
        match disclose(record, &credential.claims) {
            Ok(disclosures) => {
                return Ok(Selection {
                    record: record.clone(),
                    disclosures,
                })
            }
            Err(why) => reason = why,
        }
    }
    Err(CredentialError::Refused(reason))
}

/// One disclosure per requested claim, or the reason one cannot be answered.
fn disclose(record: &CredentialRecord, claims: &[ClaimQuery]) -> Result<Vec<Disclosure>, String> {
    let parsed =
        parse_sd_jwt(&record.raw).map_err(|_| "a held credential is unreadable".to_string())?;
    let mut out: Vec<Disclosure> = Vec::new();
    for claim in claims {
        let found = parsed
            .disclosures
            .iter()
            .find(|d| {
                d.name.as_deref() == claim.path.first().map(String::as_str)
                    && claim
                        .values
                        .as_ref()
                        .is_none_or(|values| values.contains(&d.value))
            })
            .ok_or_else(|| format!("no held credential answers claim {}", show(&claim.path)))?;
        if !out.contains(found) {
            out.push(found.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sd_jwt::import;
    use crate::vault::tests::sqlcipher_vault;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::Digest;

    const VCT: &str = "urn:shadi:agent-admission:1";
    const PEER: &str = "did:key:zPeer";

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn key() -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]))
    }

    fn agent() -> String {
        shadi_identity::encode_did_key(&key())
    }

    fn credential(typ: &str, vct: &str, exp: i64) -> String {
        credential_with(
            typ,
            vct,
            exp,
            &[
                ("groups", serde_json::json!("platform-admins")),
                ("email", serde_json::json!("alice@example.test")),
                ("ssn", serde_json::json!("000-00-0000")),
            ],
        )
    }

    fn credential_with(typ: &str, vct: &str, exp: i64, disclosures: &[(&str, Value)]) -> String {
        issued_by("https://idp.example", typ, vct, exp, disclosures)
    }

    fn issued_by(
        issuer: &str,
        typ: &str,
        vct: &str,
        exp: i64,
        disclosures: &[(&str, Value)],
    ) -> String {
        let header = serde_json::json!({"alg": "EdDSA", "typ": typ});
        let segments: Vec<String> = disclosures
            .iter()
            .map(|(name, value)| {
                b64(serde_json::json!(["c2FsdA", name, value])
                    .to_string()
                    .as_bytes())
            })
            .collect();
        let sd: Vec<String> = segments
            .iter()
            .map(|s| b64(&sha2::Sha256::digest(s.as_bytes())))
            .collect();
        let payload = serde_json::json!({
            "iss": issuer,
            "vct": vct,
            "exp": exp,
            "_sd": sd,
            "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64(key().as_bytes())}},
        });
        let mut raw = format!(
            "{}.{}.c2ln",
            b64(header.to_string().as_bytes()),
            b64(payload.to_string().as_bytes())
        );
        for segment in &segments {
            raw.push('~');
            raw.push_str(segment);
        }
        raw.push('~');
        raw
    }

    fn vault_with(typ: &str, vct: &str, exp: i64) -> impl CredentialVault {
        let vault = sqlcipher_vault();
        import(&vault, &credential(typ, vct, exp), 1_000).expect("import");
        vault
    }

    fn held() -> impl CredentialVault {
        vault_with("dc+sd-jwt", VCT, 2_000)
    }

    fn policy() -> ReleasePolicy {
        ReleasePolicy::new(&[&["groups"], &["email"]])
    }

    fn query_json(format: &str, vct: &str, claims: &str) -> String {
        format!(
            r#"{{"credentials":[{{"id":"c1","format":"{format}",
            "meta":{{"vct_values":["{vct}"]}},"claims":{claims}}}]}}"#
        )
    }

    fn sample() -> DcqlQuery {
        DcqlQuery::parse(&query_json(
            "dc+sd-jwt",
            VCT,
            r#"[{"path":["groups"],"values":["platform-admins"]}]"#,
        ))
        .expect("parse")
    }

    fn run(
        vault: &dyn CredentialVault,
        query: &DcqlQuery,
        policy: &ReleasePolicy,
    ) -> Result<Selection, CredentialError> {
        select(vault, &agent(), query, policy, PEER, 1_500)
    }

    #[test]
    fn a_sample_query_parses_and_matches() {
        let query = sample();
        assert_eq!(query.credentials[0].vct_values, vec![VCT]);
        let selection = run(&held(), &query, &policy()).expect("select");
        assert_eq!(selection.disclosures.len(), 1);
        assert_eq!(selection.disclosures[0].name.as_deref(), Some("groups"));
    }

    #[test]
    fn caps_are_enforced_at_parse() {
        let claim = r#"{"path":["groups"]}"#;
        let claims = |n: usize| format!("[{}]", vec![claim; n].join(","));
        let cred = |n: usize| {
            format!(
                r#"{{"id":"c","format":"dc+sd-jwt","meta":{{"vct_values":["{VCT}"]}},"claims":{}}}"#,
                claims(n)
            )
        };
        let many_creds = format!(
            r#"{{"credentials":[{}]}}"#,
            vec![cred(1); MAX_CREDENTIAL_QUERIES + 1].join(",")
        );
        let many_claims = format!(r#"{{"credentials":[{}]}}"#, cred(MAX_CLAIMS_PER_QUERY + 1));
        let oversized = format!(
            r#"{{"credentials":[],"x":"{}"}}"#,
            "a".repeat(MAX_QUERY_BYTES)
        );
        let deep = query_json("dc+sd-jwt", VCT, r#"[{"path":["a","b","c"]}]"#);
        let empty = query_json("dc+sd-jwt", VCT, r#"[{"path":[]}]"#);
        let no_claims = query_json("dc+sd-jwt", VCT, "[]");
        let many_vcts = format!(
            r#"{{"credentials":[{{"id":"c","format":"dc+sd-jwt","meta":{{"vct_values":[{}]}},"claims":[{claim}]}}]}}"#,
            vec![format!("\"{VCT}\""); MAX_VCT_VALUES + 1].join(",")
        );
        let many_values = query_json(
            "dc+sd-jwt",
            VCT,
            &format!(
                r#"[{{"path":["groups"],"values":[{}]}}]"#,
                ["1"; MAX_CLAIM_VALUES + 1].join(",")
            ),
        );
        let many_authorities = format!(
            r#"{{"credentials":[{{"id":"c","format":"dc+sd-jwt","meta":{{"vct_values":["{VCT}"]}},
            "claims":[{claim}],"trusted_authorities":[{}]}}]}}"#,
            vec![r#"{"type":"issuer","values":["a"]}"#; MAX_TRUSTED_AUTHORITIES + 1].join(",")
        );
        let many_authority_values = format!(
            r#"{{"credentials":[{{"id":"c","format":"dc+sd-jwt","meta":{{"vct_values":["{VCT}"]}},
            "claims":[{claim}],"trusted_authorities":[{{"type":"issuer","values":[{}]}}]}}]}}"#,
            vec!["\"a\""; MAX_TRUSTED_AUTHORITY_VALUES + 1].join(",")
        );
        for (text, needle) in [
            (oversized, "bytes"),
            (many_creds, "credential queries"),
            (many_claims, "claims"),
            (no_claims, "0 claims"),
            (deep, "nested"),
            (empty, "0 elements"),
            (many_vcts, "vct_values"),
            (many_values, "values"),
            (many_authorities, "trusted_authorities"),
            (many_authority_values, "values"),
        ] {
            let err = DcqlQuery::parse(&text).expect_err("reject").to_string();
            assert!(err.contains(needle), "{needle}: {err}");
        }
    }

    #[test]
    fn select_applies_the_caps_to_a_hand_built_query() {
        let mut query = sample();
        query.credentials[0].claims[0].path = vec!["a".into(), "b".into(), "c".into()];
        // Allowed by policy, so only `validate` can be what refuses it.
        let policy = ReleasePolicy::new(&[&["a", "b", "c"]]);
        let err = run(&held(), &query, &policy).expect_err("deep").to_string();
        assert!(err.contains("nested"), "{err}");
    }

    #[test]
    fn unsupported_features_are_rejected_not_ignored() {
        let sets = r#"{"credentials":[],"credential_sets":[{"options":[["c1"]]}]}"#.to_string();
        let unknown_claim_field =
            query_json("dc+sd-jwt", VCT, r#"[{"path":["a"],"values":[1],"gt":3}]"#);
        let unknown_cred_field = format!(
            r#"{{"credentials":[{{"id":"c","format":"dc+sd-jwt","multiple":true,
            "meta":{{"vct_values":["{VCT}"]}},"claims":[]}}]}}"#
        );
        let unknown_meta = format!(
            r#"{{"credentials":[{{"id":"c","format":"dc+sd-jwt",
            "meta":{{"vct_values":["{VCT}"],"doctype_value":"x"}},"claims":[]}}]}}"#
        );
        for text in [sets, unknown_claim_field, unknown_cred_field, unknown_meta] {
            let err = DcqlQuery::parse(&text).expect_err("reject").to_string();
            assert!(err.contains("unknown field"), "{err}");
        }
    }

    fn trusted_authorities_query(claims: &str, authorities: &[&str]) -> DcqlQuery {
        let values: Vec<String> = authorities.iter().map(|a| format!("{a:?}")).collect();
        DcqlQuery::parse(&format!(
            r#"{{"credentials":[{{"id":"c1","format":"dc+sd-jwt",
            "meta":{{"vct_values":["{VCT}"]}},"claims":{claims},
            "trusted_authorities":[{{"type":"issuer","values":[{}]}}]}}]}}"#,
            values.join(",")
        ))
        .expect("parse")
    }

    #[test]
    fn trusted_authorities_pick_the_named_issuer() {
        let vault = sqlcipher_vault();
        let claims = &[("groups", serde_json::json!("platform-admins"))];
        import(
            &vault,
            &issued_by("https://idp-a.example", "dc+sd-jwt", VCT, 2_000, claims),
            1_000,
        )
        .expect("import a");
        import(
            &vault,
            &issued_by("https://idp-b.example", "dc+sd-jwt", VCT, 2_000, claims),
            1_000,
        )
        .expect("import b");

        let query = trusted_authorities_query(
            r#"[{"path":["groups"]}]"#,
            &["https://idp-b.example"],
        );
        let selection = run(&vault, &query, &policy()).expect("select");
        assert_eq!(selection.record.issuer, "https://idp-b.example");
    }

    #[test]
    fn a_trailing_slash_does_not_dodge_the_trusted_authority() {
        let query = trusted_authorities_query(
            r#"[{"path":["groups"]}]"#,
            &["https://idp.example/"],
        );
        assert!(run(&held(), &query, &policy()).is_ok());
    }

    #[test]
    fn an_unmatched_trusted_authority_selects_nothing() {
        let query = trusted_authorities_query(
            r#"[{"path":["groups"]}]"#,
            &["https://idp-c.example"],
        );
        let err = run(&held(), &query, &policy())
            .expect_err("no match")
            .to_string();
        assert!(err.contains("matches the requested format and type"), "{err}");
    }

    #[test]
    fn a_missing_claim_is_named() {
        let query = DcqlQuery::parse(&query_json("dc+sd-jwt", VCT, r#"[{"path":["phone"]}]"#))
            .expect("parse");
        let policy = ReleasePolicy::new(&[&["phone"]]);
        let err = run(&held(), &query, &policy)
            .expect_err("missing")
            .to_string();
        assert!(err.contains("`phone`"), "{err}");
    }

    #[test]
    fn a_probe_that_misses_does_not_match_and_does_not_echo_the_value() {
        let query = DcqlQuery::parse(&query_json(
            "dc+sd-jwt",
            VCT,
            r#"[{"path":["groups"],"values":["probe-me"]}]"#,
        ))
        .expect("parse");
        let err = run(&held(), &query, &policy())
            .expect_err("no match")
            .to_string();
        assert!(err.contains("`groups`"), "{err}");
        assert!(
            !err.contains("probe-me") && !err.contains("platform-admins"),
            "{err}"
        );
    }

    #[test]
    fn a_query_outside_the_policy_is_refused_and_selects_nothing() {
        let query = DcqlQuery::parse(&query_json(
            "dc+sd-jwt",
            VCT,
            r#"[{"path":["groups"]},{"path":["ssn"]}]"#,
        ))
        .expect("parse");
        let err = run(&held(), &query, &policy())
            .expect_err("refuse")
            .to_string();
        assert!(err.contains("does not release"), "{err}");
        assert!(err.contains("`ssn`"), "{err}");
        // The default policy releases nothing at all.
        assert!(run(&held(), &sample(), &ReleasePolicy::default()).is_err());
    }

    #[test]
    fn a_peer_entry_replaces_the_global_list() {
        let policy = policy().with_peer(PEER, &[&["email"]]);
        assert!(run(&held(), &sample(), &policy).is_err());
        assert!(select(
            &held(),
            &agent(),
            &sample(),
            &policy,
            "did:key:zOther",
            1_500
        )
        .is_ok());
    }

    #[test]
    fn nested_paths_are_refused() {
        let text = query_json("dc+sd-jwt", VCT, r#"[{"path":["address","city"]}]"#);
        let err = DcqlQuery::parse(&text).expect_err("nested").to_string();
        assert!(err.contains("nested"), "{err}");
    }

    #[test]
    fn an_empty_claims_array_is_refused_even_against_the_default_policy() {
        let mut query = sample();
        query.credentials[0].claims.clear();
        let err = run(&held(), &query, &ReleasePolicy::default())
            .expect_err("empty")
            .to_string();
        assert!(err.contains("0 claims"), "{err}");
    }

    #[test]
    fn a_multi_credential_query_is_refused_whole() {
        let mut query = sample();
        let mut second = query.credentials[0].clone();
        second.id = "c2".into();
        second.format = "mso_mdoc".into();
        query.credentials.push(second);
        let err = run(&held(), &query, &policy())
            .expect_err("two")
            .to_string();
        assert!(err.contains("2 credential queries"), "{err}");
    }

    /// Refused at import, so a value probe can never choose between two
    /// disclosures sharing a name.
    #[test]
    fn a_credential_repeating_a_claim_name_is_refused() {
        let vault = sqlcipher_vault();
        let raw = credential_with(
            "dc+sd-jwt",
            VCT,
            2_000,
            &[
                ("groups", serde_json::json!("interns")),
                ("groups", serde_json::json!("platform-admins")),
            ],
        );
        assert!(import(&vault, &raw, 1_000).is_err());
    }

    #[test]
    fn format_and_vct_mismatches_do_not_match() {
        let claims = r#"[{"path":["groups"]}]"#;
        for text in [
            query_json("mso_mdoc", VCT, claims),
            query_json("dc+sd-jwt", "urn:other:1", claims),
        ] {
            let query = DcqlQuery::parse(&text).expect("parse");
            assert!(run(&held(), &query, &policy()).is_err(), "{text}");
        }
    }

    #[test]
    fn an_expired_credential_is_not_selected() {
        let vault = vault_with("dc+sd-jwt", VCT, 1_500);
        assert!(run(&vault, &sample(), &policy()).is_err());
        let vault = vault_with("dc+sd-jwt", VCT, 1_501);
        assert!(run(&vault, &sample(), &policy()).is_ok());
    }

    #[test]
    fn another_agents_credential_is_not_selected() {
        let err = select(&held(), "did:key:zOther", &sample(), &policy(), PEER, 1_500);
        assert!(err.is_err());
    }

    /// Whatever is asked and whatever the policy says, a selection is exactly
    /// the requested paths, all of them released.
    #[test]
    fn selected_disclosures_are_within_the_request_and_the_policy() {
        let paths = ["groups", "email", "ssn", "phone"];
        let vault = held();
        for asked in 0u32..16 {
            for allowed in 0u32..16 {
                let pick = |mask: u32| -> Vec<&str> {
                    (0..4)
                        .filter(|i| mask >> i & 1 == 1)
                        .map(|i| paths[i])
                        .collect()
                };
                let (asked, allowed) = (pick(asked), pick(allowed));
                let claims = serde_json::json!(asked
                    .iter()
                    .map(|p| serde_json::json!({"path": [p]}))
                    .collect::<Vec<_>>());
                let parsed = DcqlQuery::parse(&query_json("dc+sd-jwt", VCT, &claims.to_string()));
                if asked.is_empty() {
                    assert!(parsed.is_err(), "an empty claims array must not parse");
                    continue;
                }
                let query = parsed.expect("parse");
                let singles: Vec<[&str; 1]> = allowed.iter().map(|p| [*p]).collect();
                let slices: Vec<&[&str]> = singles.iter().map(|p| p.as_slice()).collect();
                let policy = ReleasePolicy::new(&slices);

                // Inside the policy and held: must succeed, so the checks below
                // cannot pass vacuously.
                let answerable = asked.iter().all(|p| allowed.contains(p) && *p != "phone");
                let result = run(&vault, &query, &policy);
                assert_eq!(result.is_ok(), answerable, "{asked:?} {allowed:?}");
                let Ok(selection) = result else {
                    continue;
                };
                let names: Vec<&str> = selection
                    .disclosures
                    .iter()
                    .map(|d| d.name.as_deref().expect("named"))
                    .collect();
                for name in &names {
                    assert!(asked.contains(name) && allowed.contains(name), "{name}");
                }
                assert_eq!(names.len(), asked.len(), "{asked:?} {allowed:?}");
            }
        }
    }
}
