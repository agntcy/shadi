// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The operator's admission policy: which issuers a listener trusts and what
//! their credentials must say. It yields the challenge query and judges a
//! verified presentation. Offline, and it never reads the clock.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::dcql::{DcqlQuery, MAX_CLAIMS_PER_QUERY};
use crate::jwks::JwksStore;
use crate::vault::pin_issuer;
use crate::verify::VerifiedPresentation;
use crate::CredentialError;

/// One trusted issuer and what its credentials must carry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct IssuerPolicy {
    pub iss: String,
    /// Pinned keys; paired with `iss` so an issuer cannot exist without them.
    pub jwks: PathBuf,
    pub vct: String,
    /// Claim name to required value; an array-valued claim matches by containment.
    #[serde(default)]
    pub require_claims: BTreeMap<String, String>,
    /// Deny a credential with no `exp`. An expired one is `verify`'s to refuse.
    #[serde(default)]
    pub require_exp: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    issuers: Vec<IssuerPolicy>,
}

/// The admission verdict. A reason names the failing claim, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    Admit,
    Deny(String),
}

#[non_exhaustive]
pub struct AdmissionPolicy {
    pub issuers: Vec<IssuerPolicy>,
    jwks: JwksStore,
}

impl AdmissionPolicy {
    /// Load and pin. Anything unrecognised, or a file naming no issuer, is an
    /// error rather than "no restrictions".
    pub fn from_file(path: &Path) -> Result<Self, CredentialError> {
        let shown = path.display();
        let text = std::fs::read_to_string(path)
            .map_err(|e| CredentialError::Storage(format!("cannot read {shown}: {e}")))?;
        let file: PolicyFile = serde_json::from_str(&text)
            .map_err(|e| CredentialError::Malformed(format!("policy {shown}: {e}")))?;
        if file.issuers.is_empty() {
            return Err(CredentialError::Refused(format!(
                "policy {shown} declares no `issuers`"
            )));
        }
        // A challenge names one credential query, so more cannot be answered.
        if file.issuers.len() > 1 {
            return Err(CredentialError::Refused(format!(
                "policy {shown} lists {} issuers; a challenge can name only one",
                file.issuers.len()
            )));
        }
        let dir = path.parent().unwrap_or(Path::new(""));
        let mut jwks = JwksStore::new();
        for entry in &file.issuers {
            // A challenge cannot ask for no claims, so such an entry could
            // never be presented against — refuse it here, not on first contact.
            if entry.require_claims.is_empty() {
                return Err(CredentialError::Refused(format!(
                    "policy {shown}: issuer {} must require at least one claim",
                    pin_issuer(&entry.iss)
                )));
            }
            if entry.require_claims.len() > MAX_CLAIMS_PER_QUERY {
                return Err(CredentialError::Refused(format!(
                    "policy {shown}: issuer {} requires {} claims, over the limit of {MAX_CLAIMS_PER_QUERY}",
                    pin_issuer(&entry.iss),
                    entry.require_claims.len()
                )));
            }
            // A relative path is the policy's own neighbour, not the CWD's.
            jwks.add_file(&entry.iss, &dir.join(&entry.jwks))?;
        }
        Ok(Self {
            issuers: file.issuers,
            jwks,
        })
    }

    /// The pinned keys for `verify`.
    pub fn jwks(&self) -> &JwksStore {
        &self.jwks
    }

    /// The challenge query as JSON text. A holder answers one credential query,
    /// so a policy with several issuers cannot be turned into one; `from_file`
    /// already refuses that, and this is the backstop.
    pub fn challenge_query(&self) -> Result<String, CredentialError> {
        let [issuer] = self.issuers.as_slice() else {
            return Err(CredentialError::Refused(format!(
                "{} issuers are configured; a challenge can name only one",
                self.issuers.len()
            )));
        };
        let claims: Vec<Value> = issuer
            .require_claims
            .keys()
            .map(|name| json!({ "path": [name] }))
            .collect();
        let query = json!({"credentials": [{
            "id": "admission",
            "format": crate::sd_jwt::SD_JWT_FORMAT,
            "meta": { "vct_values": [&issuer.vct] },
            "claims": claims,
        }]});
        // Through the real parser, so the holder's caps are checked here too.
        let text = query.to_string();
        DcqlQuery::parse(&text)?;
        Ok(text)
    }

    /// Judge a presentation that `verify` accepted.
    pub fn evaluate(&self, presented: &VerifiedPresentation) -> Decision {
        let Some(issuer) = self
            .issuers
            .iter()
            .find(|i| pin_issuer(&i.iss) == pin_issuer(&presented.issuer))
        else {
            return Decision::Deny("the issuer is not configured".to_string());
        };
        if issuer.vct != presented.credential_type {
            return Decision::Deny("the credential type is not the one required".to_string());
        }
        if issuer.require_exp && presented.expires_at.is_none() {
            return Decision::Deny("the credential carries no `exp`".to_string());
        }
        for (name, want) in &issuer.require_claims {
            let mut named = presented
                .claims
                .iter()
                .filter(|d| d.name.as_deref() == Some(name.as_str()))
                .peekable();
            if named.peek().is_none() {
                return Decision::Deny(format!("required claim `{name}` was not disclosed"));
            }
            if !named.any(|d| matches(&d.value, want)) {
                return Decision::Deny(format!("required claim `{name}` does not match"));
            }
        }
        Decision::Admit
    }
}

fn matches(have: &Value, want: &str) -> bool {
    match have {
        Value::String(s) => s == want,
        Value::Array(items) => items.iter().any(|v| v.as_str() == Some(want)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::NonceStore;
    use crate::testkit::{
        base_claims, base_header, credential, disclosure, issuer_key, present_n, ISS, NOW,
    };
    use crate::SD_JWT_FORMAT;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use shadi_identity::AgentIdentity;

    const VCT: &str = "urn:shadi:agent-admission:1";
    const TASK: &str = "task-1";

    struct Fx {
        dir: tempfile::TempDir,
        holder: AgentIdentity,
        nonces: NonceStore,
    }

    impl Fx {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let key = issuer_key();
            let jwk = json!({
                "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
            });
            std::fs::write(
                dir.path().join("jwks.json"),
                json!({ "keys": [jwk] }).to_string(),
            )
            .unwrap();
            Self {
                dir,
                holder: AgentIdentity::generate().unwrap(),
                nonces: NonceStore::new("did:key:listener", "{}"),
            }
        }

        fn jwks_path(&self) -> PathBuf {
            self.dir.path().join("jwks.json")
        }

        fn entry(&self, iss: &str, extra: Value) -> Value {
            let mut e = json!({"iss": iss, "jwks": self.jwks_path(), "vct": VCT});
            e.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            e
        }

        fn load_doc(&self, doc: &Value) -> Result<AdmissionPolicy, String> {
            let path = self.dir.path().join("policy.json");
            std::fs::write(&path, doc.to_string()).unwrap();
            AdmissionPolicy::from_file(&path).map_err(|e| e.to_string())
        }

        fn load(&self, entries: Vec<Value>) -> AdmissionPolicy {
            self.load_doc(&json!({ "issuers": entries })).unwrap()
        }

        /// A genuine presentation of every disclosure, run through `verify`.
        fn verified(
            &self,
            jwks: &JwksStore,
            iss: &str,
            vct: &str,
            exp: Option<i64>,
            discs: &[(&str, Value)],
        ) -> VerifiedPresentation {
            let d: Vec<String> = discs
                .iter()
                .map(|(n, v)| disclosure(n, v.clone()))
                .collect();
            let mut claims = base_claims(&self.holder, &d);
            claims["iss"] = json!(iss);
            claims["vct"] = json!(vct);
            claims["exp"] = json!(exp);
            let raw = credential(&issuer_key(), &base_header(), &claims, &d);
            let c = self.nonces.issue(TASK, NOW).unwrap();
            let pres = present_n(&self.holder, &raw, d.len(), &c.nonce, &c.aud, NOW);
            crate::verify::verify(&pres, &self.holder.did(), TASK, &self.nonces, jwks, NOW)
                .expect("verify")
        }

        fn present(
            &self,
            p: &AdmissionPolicy,
            iss: &str,
            vct: &str,
            exp: Option<i64>,
            discs: &[(&str, Value)],
        ) -> Decision {
            p.evaluate(&self.verified(p.jwks(), iss, vct, exp, discs))
        }
    }

    fn groups() -> [(&'static str, Value); 1] {
        [("groups", json!("platform-admins"))]
    }

    fn denied(d: Decision) -> String {
        match d {
            Decision::Deny(why) => why,
            Decision::Admit => panic!("expected a denial"),
        }
    }

    fn refused(r: Result<AdmissionPolicy, String>) -> String {
        match r {
            Err(e) => e,
            Ok(_) => panic!("must be refused"),
        }
    }

    fn admin() -> Value {
        json!({"require_claims": {"groups": "platform-admins"}})
    }

    #[test]
    fn a_minimal_policy_loads_round_trips_and_admits() {
        let fx = Fx::new();
        let p = fx.load(vec![fx.entry(ISS, admin())]);
        let q = DcqlQuery::parse(&p.challenge_query().unwrap()).unwrap();
        let c = &q.credentials[0];
        assert_eq!(c.format, SD_JWT_FORMAT);
        assert_eq!(c.vct_values, vec![VCT]);
        assert_eq!(c.claims.len(), 1);
        assert_eq!(c.claims[0].path, vec!["groups"]);
        assert_eq!(
            fx.present(&p, ISS, VCT, Some(NOW + 60), &groups()),
            Decision::Admit
        );
    }

    #[test]
    fn unknown_or_empty_files_are_refused_distinguishably() {
        let fx = Fx::new();
        let top = refused(fx.load_doc(&json!({"issuers": [fx.entry(ISS, admin())], "isuers": []})));
        let entry =
            refused(fx.load_doc(&json!({"issuers": [fx.entry(ISS, json!({"requre_exp": true}))]})));
        let neither = refused(fx.load_doc(&json!({})));
        let empty = refused(fx.load_doc(&json!({"issuers": []})));
        assert!(top.contains("unknown field `isuers`"), "{top}");
        assert!(entry.contains("unknown field `requre_exp`"), "{entry}");
        assert!(neither.contains("declares no `issuers`"), "{neither}");
        assert!(empty.contains("declares no `issuers`"), "{empty}");
    }

    #[test]
    fn a_missing_or_malformed_jwks_is_refused_at_load() {
        let fx = Fx::new();
        let mut missing = fx.entry(ISS, admin());
        missing["jwks"] = json!(fx.dir.path().join("nope.json"));
        assert!(refused(fx.load_doc(&json!({"issuers": [missing]}))).contains("cannot read"));

        let bad = fx.dir.path().join("bad.json");
        std::fs::write(&bad, "not json").unwrap();
        let mut malformed = fx.entry(ISS, admin());
        malformed["jwks"] = json!(bad);
        assert!(refused(fx.load_doc(&json!({"issuers": [malformed]}))).contains("not JSON"));

        let no_jwks = json!({"iss": ISS, "vct": VCT});
        assert!(
            refused(fx.load_doc(&json!({"issuers": [no_jwks]}))).contains("missing field `jwks`")
        );
    }

    #[test]
    fn the_same_issuer_twice_is_refused() {
        let fx = Fx::new();
        let e = refused(fx.load_doc(
            &json!({"issuers": [fx.entry(ISS, admin()), fx.entry(&format!("{ISS}/"), admin())]}),
        ));
        assert!(e.contains("can name only one"), "{e}");
    }

    /// A vct-only entry could never be challenged for, so it fails at load
    /// rather than on first contact.
    #[test]
    fn an_issuer_requiring_no_claim_is_refused() {
        let fx = Fx::new();
        let e = refused(fx.load_doc(&json!({"issuers": [fx.entry(ISS, json!({}))]})));
        assert!(e.contains("at least one claim"), "{e}");
    }

    #[test]
    fn require_exp_true_denies_a_credential_without_exp_and_admits_a_future_one() {
        let fx = Fx::new();
        let entry = fx.entry(
            ISS,
            json!({"require_exp": true, "require_claims": {"groups": "platform-admins"}}),
        );
        let p = fx.load(vec![entry]);
        let why = denied(fx.present(&p, ISS, VCT, None, &groups()));
        assert!(why.contains("no `exp`"), "{why}");
        assert_eq!(
            fx.present(&p, ISS, VCT, Some(NOW + 60), &groups()),
            Decision::Admit
        );
    }

    #[test]
    fn require_exp_absent_defaults_to_false_and_admits_a_credential_without_exp() {
        let fx = Fx::new();
        let entry = fx.entry(ISS, admin());
        assert!(entry.get("require_exp").is_none());
        let p = fx.load(vec![entry]);
        assert!(!p.issuers[0].require_exp);
        assert_eq!(fx.present(&p, ISS, VCT, None, &groups()), Decision::Admit);
    }

    #[test]
    fn each_denial_has_its_own_message() {
        let fx = Fx::new();
        let p = fx.load(vec![fx.entry(ISS, admin())]);
        let exp = Some(NOW + 60);

        let vct = denied(fx.present(&p, ISS, "urn:other:1", exp, &groups()));
        assert!(vct.contains("credential type"), "{vct}");

        // An issuer `verify` trusts but this policy does not list.
        let mut elsewhere = JwksStore::new();
        elsewhere
            .add_file("https://other.example", &fx.jwks_path())
            .unwrap();
        let unlisted =
            p.evaluate(&fx.verified(&elsewhere, "https://other.example", VCT, exp, &groups()));
        assert!(denied(unlisted).contains("issuer is not configured"));

        let missing = denied(fx.present(&p, ISS, VCT, exp, &[("email", json!("a@b.test"))]));
        assert!(missing.contains("`groups` was not disclosed"), "{missing}");

        let differs = denied(fx.present(&p, ISS, VCT, exp, &[("groups", json!("interns"))]));
        assert!(differs.contains("`groups` does not match"), "{differs}");
    }

    #[test]
    fn array_claims_match_by_containment() {
        let fx = Fx::new();
        let p = fx.load(vec![fx.entry(ISS, admin())]);
        let has = [("groups", json!(["platform-admins", "other"]))];
        assert_eq!(fx.present(&p, ISS, VCT, None, &has), Decision::Admit);
        let lacks = [("groups", json!(["interns", "other"]))];
        let why = denied(fx.present(&p, ISS, VCT, None, &lacks));
        assert!(why.contains("`groups` does not match"), "{why}");
    }

    #[test]
    fn a_denial_never_contains_the_claim_value() {
        let fx = Fx::new();
        let p = fx.load(vec![fx.entry(ISS, admin())]);
        for value in [json!("sekrit-value"), json!(["sekrit-value", "x"])] {
            let why = denied(fx.present(&p, ISS, VCT, None, &[("groups", value)]));
            assert!(!why.contains("sekrit-value"), "{why}");
            assert!(!why.contains("platform-admins"), "{why}");
        }
    }

    #[test]
    fn a_challenge_names_one_issuer_only() {
        let fx = Fx::new();
        let e = refused(fx.load_doc(&json!({"issuers": [
            fx.entry(ISS, admin()),
            fx.entry("https://other.example", admin()),
        ]})));
        assert!(e.contains("can name only one"), "{e}");
    }

    #[test]
    fn challenge_query_still_refuses_what_load_would_have() {
        let fx = Fx::new();
        let mut p = fx.load(vec![fx.entry(ISS, admin())]);
        let again = p.issuers[0].clone();
        p.issuers.push(again);
        let e = p.challenge_query().expect_err("two issuers").to_string();
        assert!(e.contains("can name only one"), "{e}");
    }

    #[test]
    fn too_many_required_claims_is_refused_at_load() {
        let fx = Fx::new();
        let claims = |n: usize| -> Value {
            json!({"require_claims": (0..n).map(|i| (format!("c{i}"), "v")).collect::<BTreeMap<_, _>>()})
        };
        let p = fx.load(vec![fx.entry(ISS, claims(MAX_CLAIMS_PER_QUERY))]);
        assert!(p.challenge_query().is_ok());
        let e = refused(
            fx.load_doc(&json!({"issuers": [fx.entry(ISS, claims(MAX_CLAIMS_PER_QUERY + 1))]})),
        );
        assert!(e.contains(ISS) && e.contains("limit of 16"), "{e}");
    }

    #[test]
    fn a_relative_jwks_resolves_against_the_policy_directory() {
        let fx = Fx::new();
        let mut rel = fx.entry(ISS, admin());
        rel["jwks"] = json!("jwks.json");
        // The CWD is not the policy directory, so only the policy-relative
        // reading can find the file.
        assert!(fx.load_doc(&json!({"issuers": [rel]})).is_ok());

        let elsewhere = tempfile::tempdir().unwrap();
        let mut abs = fx.entry(ISS, admin());
        abs["jwks"] = json!(fx.jwks_path());
        let path = elsewhere.path().join("policy.json");
        std::fs::write(&path, json!({"issuers": [abs]}).to_string()).unwrap();
        assert!(AdmissionPolicy::from_file(&path).is_ok());
    }

    /// The query is derived from `require_claims`, so a claim the policy
    /// requires is always one the challenge asks for.
    #[test]
    fn every_required_claim_is_asked_for() {
        let fx = Fx::new();
        let req = json!({"require_claims": {"groups": "a", "email": "b", "team": "c"}});
        let p = fx.load(vec![fx.entry(ISS, req)]);
        let query = DcqlQuery::parse(&p.challenge_query().unwrap()).unwrap();
        let asked: Vec<String> = query.credentials[0]
            .claims
            .iter()
            .map(|c| c.path[0].clone())
            .collect();
        let required: Vec<String> = p.issuers[0].require_claims.keys().cloned().collect();
        assert_eq!(asked, required);
    }

    #[test]
    fn a_trailing_slash_on_the_configured_issuer_matches() {
        let fx = Fx::new();
        let p = fx.load(vec![fx.entry(&format!("{ISS}/"), admin())]);
        assert_eq!(fx.present(&p, ISS, VCT, None, &groups()), Decision::Admit);
    }
}
