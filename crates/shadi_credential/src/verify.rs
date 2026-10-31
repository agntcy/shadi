// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The offline admission decision: is this presentation acceptable?
//!
//! No network I/O of any kind. Keys come from the pinned JWKS and the
//! audience from the nonce store, so a listener verifies with the IdP down.
//! Errors never carry token content, claim values or key material.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::jwks::JwksStore;
use crate::nonce::NonceStore;
use crate::sd_jwt::{ed25519_from_jwk, parse_presentation, Disclosure, Jwt};
use crate::CredentialError;

/// The only `alg` this crate can verify without new dependencies.
pub const ALLOWED_ALGS: &[&str] = &["EdDSA"];

/// Tolerated holder clock lead: two laptops' clocks are rarely in step.
pub const KB_FUTURE_SKEW_SECS: i64 = 30;

/// Oldest acceptable key-binding `iat`: a nonce lives 60s, so this covers one
/// round trip plus slack while bounding how long a signed answer stays usable.
pub const KB_MAX_AGE_SECS: i64 = 120;

/// What a presentation proved.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedPresentation {
    pub issuer: String,
    pub credential_type: String,
    pub agent_did: String,
    /// The credential's `exp`, if it carries one.
    pub expires_at: Option<i64>,
    /// Disclosed claims only — nothing the issuer did not reveal here.
    pub claims: Vec<Disclosure>,
}

fn refused(msg: &str) -> CredentialError {
    CredentialError::Refused(msg.to_string())
}

/// `signer_did` is the DID that signed the outer `SHADI-DID-PROOF/1` envelope.
pub fn verify(
    raw: &str,
    signer_did: &str,
    task_id: &str,
    nonces: &NonceStore,
    jwks: &JwksStore,
    now: i64,
) -> Result<VerifiedPresentation, CredentialError> {
    // 1. Caps, issuer `typ` pin, `cnf.jwk`, disclosure digest binding. The
    // issuer JWT's `typ` is settled here, so it is not checked again below.
    let parsed = parse_presentation(raw)?;
    let (issuer_jwt, kb_jwt) = (&parsed.issuer_jwt, &parsed.key_binding_jwt);

    // 2. Spend the nonce before any signature work, so a replay costs no
    // signature verification. Parsing already hashed the disclosures, which
    // the parser's cap bounds and which is far cheaper than a signature. The
    // payload is unverified: the nonce is all that is taken from it.
    let nonce = kb_jwt
        .payload
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| CredentialError::Malformed("no `nonce` claim".to_string()))?;
    // The only audience accepted below; never one the token names.
    let audience = nonces.consume(nonce, task_id, now)?;

    // 3. Algorithm allow-list (no `none`, no alg confusion) and KB `typ`.
    check_alg(issuer_jwt, "issuer JWT")?;
    check_alg(kb_jwt, "key-binding JWT")?;
    if kb_jwt.header.get("typ").and_then(Value::as_str) != Some("kb+jwt") {
        return Err(refused("the key-binding JWT `typ` is not kb+jwt"));
    }

    // 4. Resolve the key from the pinned set by (iss, kid); an unpinned issuer
    // fails here, before any signature check. `x5c` is ignored on purpose:
    // promoting an unvalidated chain to trust material is the drift pinning
    // exists to prevent.
    let kid = issuer_jwt.header.get("kid").and_then(Value::as_str);
    let issuer_key = jwks.key(&parsed.credential.issuer, kid)?;

    // 5. The issuer really issued this credential.
    check_signature(&issuer_key, issuer_jwt, "issuer JWT")?;

    // 6. The holder really signed the key-binding JWT.
    let holder_key = ed25519_from_jwk(&issuer_jwt.payload["cnf"]["jwk"], "cnf.jwk")?;
    check_signature(&holder_key, kb_jwt, "key-binding JWT")?;

    // 7. The disclosures sent are the ones the holder signed over.
    let sd_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(parsed.sd_hash_input.as_bytes()));
    if kb_jwt.payload.get("sd_hash").and_then(Value::as_str) != Some(sd_hash.as_str()) {
        return Err(refused("`sd_hash` does not match the disclosures sent"));
    }

    // 8. Replay at another verifier: the audience is ours, not the token's.
    if kb_jwt.payload.get("aud").and_then(Value::as_str) != Some(audience.as_str()) {
        return Err(refused(
            "the key-binding JWT audience is not the one this listener issued",
        ));
    }

    // 9. A credential presented by an agent that is not its holder. Raw key
    // bytes, never serialised JWKs or DID strings, whose encoding the wire
    // controls.
    let signer = shadi_identity::parse_did_key(signer_did)
        .map_err(|_| refused("the envelope signer is not a usable did:key"))?;
    if signer.as_bytes() != holder_key.as_bytes() {
        return Err(refused(
            "the credential is not bound to the key that signed the envelope",
        ));
    }

    // 10. Freshness, against the injected clock only.
    if parsed.credential.expires_at.is_some_and(|exp| exp <= now) {
        return Err(refused("the credential has expired"));
    }
    // Rounded up, so a fractional `nbf` can only start later.
    if seconds(&issuer_jwt.payload, "nbf", f64::ceil)?.is_some_and(|nbf| nbf > now) {
        return Err(refused("the credential is not yet valid"));
    }
    let iat = seconds(&kb_jwt.payload, "iat", f64::floor)?
        .ok_or_else(|| CredentialError::Malformed("no `iat` claim".to_string()))?;
    if iat > now.saturating_add(KB_FUTURE_SKEW_SECS) {
        return Err(refused("the key-binding JWT `iat` is in the future"));
    }
    if now.saturating_sub(iat) > KB_MAX_AGE_SECS {
        return Err(refused("the key-binding JWT is too old"));
    }

    // 12. Only what the issuer committed to and the holder chose to reveal.
    Ok(VerifiedPresentation {
        issuer: parsed.credential.issuer,
        credential_type: parsed.credential.credential_type,
        agent_did: parsed.credential.agent_did,
        expires_at: parsed.credential.expires_at,
        claims: parsed.credential.disclosures,
    })
}

/// An unexpected `alg` is a hard rejection; the value is not echoed.
fn check_alg(jwt: &Jwt, what: &str) -> Result<(), CredentialError> {
    match jwt.header.get("alg").and_then(Value::as_str) {
        Some(alg) if ALLOWED_ALGS.contains(&alg) => Ok(()),
        _ => Err(CredentialError::Refused(format!(
            "the {what} `alg` is not an accepted algorithm"
        ))),
    }
}

fn check_signature(key: &VerifyingKey, jwt: &Jwt, what: &str) -> Result<(), CredentialError> {
    let bad = || CredentialError::Refused(format!("the {what} signature does not verify"));
    let sig = Signature::from_slice(&jwt.signature).map_err(|_| bad())?;
    key.verify_strict(jwt.signing_input.as_bytes(), &sig)
        .map_err(|_| bad())
}

/// A NumericDate claim, which may be fractional; `round` picks the safe side.
fn seconds(
    payload: &Value,
    claim: &str,
    round: fn(f64) -> f64,
) -> Result<Option<i64>, CredentialError> {
    match payload.get(claim) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().map(|f| round(f) as i64))
            .map(Some)
            .ok_or_else(|| {
                CredentialError::Malformed(format!("`{claim}` is not a number of seconds"))
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::Challenge;
    use crate::sd_jwt::{decode_json, import, parse_sd_jwt};
    use crate::vault::tests::sqlcipher_vault;
    use crate::Selection;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use shadi_identity::AgentIdentity;

    const ISS: &str = "https://idp.example/realms/eng";
    const AUD: &str = "did:key:listener";
    const TASK: &str = "task-1";
    const NOW: i64 = 1_700_000_000;

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn jwks() -> JwksStore {
        let jwk = json!({
            "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA",
            "x": URL_SAFE_NO_PAD.encode(issuer_key().verifying_key().as_bytes()),
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, json!({ "keys": [jwk] }).to_string()).unwrap();
        let mut store = JwksStore::new();
        store.add_file(ISS, &path).unwrap();
        store
    }

    fn disclosure(name: &str, value: &str) -> String {
        b64(&json!(["c2FsdA", name, value]).to_string())
    }

    fn discs() -> Vec<String> {
        vec![
            disclosure("groups", "platform-admins"),
            disclosure("email", "alice@example.test"),
        ]
    }

    fn base_header() -> Value {
        json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": "k1"})
    }

    fn base_claims(holder: &AgentIdentity, discs: &[String]) -> Value {
        let sd: Vec<String> = discs
            .iter()
            .map(|d| URL_SAFE_NO_PAD.encode(Sha256::digest(d.as_bytes())))
            .collect();
        json!({
            "iss": ISS,
            "vct": "urn:shadi:agent-admission:1",
            "exp": NOW + 3_600,
            "cnf": { "jwk": holder.public_jwk() },
            "_sd_alg": "sha-256",
            "_sd": sd,
        })
    }

    fn credential(key: &SigningKey, header: &Value, claims: &Value, discs: &[String]) -> String {
        use ed25519_dalek::Signer;
        let input = format!("{}.{}", b64(&header.to_string()), b64(&claims.to_string()));
        let sig = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
        let mut raw = format!("{input}.{sig}");
        for d in discs {
            raw.push('~');
            raw.push_str(d);
        }
        raw.push('~');
        raw
    }

    /// The holder answers with the first `take` disclosures, via the real builder.
    fn present_n(
        holder: &AgentIdentity,
        cred: &str,
        take: usize,
        nonce: &str,
        aud: &str,
        iat: i64,
    ) -> String {
        let record = import(&sqlcipher_vault(), cred, 1_000).unwrap();
        let disclosures = parse_sd_jwt(cred).unwrap().disclosures[..take].to_vec();
        let sel = Selection {
            record,
            disclosures,
        };
        crate::presentation::build(holder, &sel, nonce, aud, iat).unwrap()
    }

    /// Replace the key-binding JWT with a re-signed, edited copy.
    fn resign(
        signer: &AgentIdentity,
        pres: &str,
        edit: impl FnOnce(&mut Value, &mut Value),
    ) -> String {
        let (head, kb) = pres.rsplit_once('~').unwrap();
        let seg: Vec<&str> = kb.split('.').collect();
        let mut header = decode_json(seg[0], "h").unwrap();
        let mut payload = decode_json(seg[1], "p").unwrap();
        edit(&mut header, &mut payload);
        let input = format!("{}.{}", b64(&header.to_string()), b64(&payload.to_string()));
        let sig = URL_SAFE_NO_PAD.encode(signer.sign_bytes(input.as_bytes()));
        format!("{head}~{input}.{sig}")
    }

    struct Env {
        holder: AgentIdentity,
        nonces: NonceStore,
        jwks: JwksStore,
    }

    impl Env {
        fn new() -> Self {
            Self {
                holder: AgentIdentity::generate().unwrap(),
                nonces: NonceStore::new(AUD),
                jwks: jwks(),
            }
        }

        fn challenge(&self) -> Challenge {
            self.nonces.issue(TASK, NOW).unwrap()
        }

        /// A valid presentation, with the credential edited by `edit` first.
        fn pres(&self, edit: impl FnOnce(&mut Value, &mut Value)) -> String {
            let d = discs();
            let (mut header, mut claims) = (base_header(), base_claims(&self.holder, &d));
            edit(&mut header, &mut claims);
            let cred = credential(&issuer_key(), &header, &claims, &d);
            let c = self.challenge();
            present_n(&self.holder, &cred, d.len(), &c.nonce, &c.aud, NOW)
        }

        fn verify_as(&self, pres: &str, signer: &str) -> Result<VerifiedPresentation, String> {
            verify(pres, signer, TASK, &self.nonces, &self.jwks, NOW).map_err(|e| e.to_string())
        }

        fn verify(&self, pres: &str) -> Result<VerifiedPresentation, String> {
            self.verify_as(pres, &self.holder.did())
        }

        /// The rejection must be this check's own.
        fn rejects(&self, pres: &str, needle: &str) {
            let err = self.verify(pres).expect_err("must reject");
            assert!(err.contains(needle), "wanted `{needle}`, got: {err}");
        }
    }

    #[test]
    fn a_valid_presentation_verifies() {
        let e = Env::new();
        let got = e.verify(&e.pres(|_, _| {})).expect("verify");
        assert_eq!(got.issuer, ISS);
        assert_eq!(got.credential_type, "urn:shadi:agent-admission:1");
        assert_eq!(got.agent_did, e.holder.did());
        let claims: Vec<_> = got
            .claims
            .iter()
            .map(|d| (d.name.clone().unwrap(), d.value.clone()))
            .collect();
        assert_eq!(
            claims,
            vec![
                ("groups".to_string(), json!("platform-admins")),
                ("email".to_string(), json!("alice@example.test")),
            ]
        );
    }

    #[test]
    fn only_the_disclosed_subset_comes_back() {
        let e = Env::new();
        let d = discs();
        let cred = credential(
            &issuer_key(),
            &base_header(),
            &base_claims(&e.holder, &d),
            &d,
        );
        let c = e.challenge();
        let pres = present_n(&e.holder, &cred, 1, &c.nonce, &c.aud, NOW);
        let got = e.verify(&pres).expect("verify");
        assert_eq!(got.claims.len(), 1);
        assert_eq!(got.claims[0].name.as_deref(), Some("groups"));
    }

    #[test]
    fn rejects_a_bad_issuer_signature() {
        let e = Env::new();
        let d = discs();
        let forger = SigningKey::from_bytes(&[10u8; 32]);
        let cred = credential(&forger, &base_header(), &base_claims(&e.holder, &d), &d);
        let c = e.challenge();
        let pres = present_n(&e.holder, &cred, d.len(), &c.nonce, &c.aud, NOW);
        e.rejects(&pres, "issuer JWT signature");
    }

    #[test]
    fn rejects_none_and_unlisted_alg_on_the_issuer_jwt() {
        for alg in ["none", "RS256", "HS256"] {
            let e = Env::new();
            let pres = e.pres(|h, _| h["alg"] = json!(alg));
            e.rejects(&pres, "issuer JWT `alg`");
        }
        let e = Env::new();
        let pres = e.pres(|h, _| {
            h.as_object_mut().unwrap().remove("alg");
        });
        e.rejects(&pres, "issuer JWT `alg`");
    }

    #[test]
    fn rejects_none_and_unlisted_alg_on_the_key_binding_jwt() {
        for alg in ["none", "RS256", "HS256"] {
            let e = Env::new();
            let pres = resign(&e.holder, &e.pres(|_, _| {}), |h, _| h["alg"] = json!(alg));
            e.rejects(&pres, "key-binding JWT `alg`");
        }
    }

    #[test]
    fn rejects_a_key_binding_jwt_with_the_wrong_typ() {
        let e = Env::new();
        let pres = resign(&e.holder, &e.pres(|_, _| {}), |h, _| {
            h["typ"] = json!("JWT")
        });
        e.rejects(&pres, "`typ` is not kb+jwt");
    }

    /// A plain JWT from the trusted issuer, carrying `cnf` and the same claim
    /// names, must not pass as a credential.
    #[test]
    fn rejects_a_plain_jwt_from_the_trusted_issuer() {
        let e = Env::new();
        let good = e.pres(|_, _| {});
        let d = discs();
        let mut header = base_header();
        header["typ"] = json!("JWT");
        let plain = credential(&issuer_key(), &header, &base_claims(&e.holder, &d), &[]);
        let plain_jwt = plain.trim_end_matches('~');
        let (_, rest) = good.split_once('~').unwrap();
        e.rejects(&format!("{plain_jwt}~{rest}"), "expected dc+sd-jwt");
    }

    #[test]
    fn rejects_an_unknown_issuer() {
        let e = Env::new();
        let pres = e.pres(|_, c| c["iss"] = json!("https://evil.example"));
        e.rejects(&pres, "is not pinned");
    }

    #[test]
    fn rejects_an_unknown_kid() {
        let e = Env::new();
        let pres = e.pres(|h, _| h["kid"] = json!("nope"));
        e.rejects(&pres, "no key with kid");
    }

    #[test]
    fn rejects_a_credential_bound_to_another_key_than_the_envelope_signer() {
        let e = Env::new();
        let other = AgentIdentity::generate().unwrap();
        e.rejects_signer(&e.pres(|_, _| {}), &other.did());
    }

    impl Env {
        fn rejects_signer(&self, pres: &str, signer: &str) {
            let err = self.verify_as(pres, signer).expect_err("must reject");
            assert!(err.contains("not bound to the key that signed"), "{err}");
        }
    }

    #[test]
    fn rejects_an_envelope_signer_that_is_not_a_did_key() {
        let e = Env::new();
        let err = e
            .verify_as(&e.pres(|_, _| {}), "did:web:example.com")
            .expect_err("must reject");
        assert!(err.contains("not a usable did:key"), "{err}");
    }

    #[test]
    fn rejects_a_key_binding_jwt_signed_by_another_key() {
        let e = Env::new();
        let attacker = AgentIdentity::generate().unwrap();
        let pres = resign(&attacker, &e.pres(|_, _| {}), |_, _| {});
        e.rejects(&pres, "key-binding JWT signature");
    }

    #[test]
    fn rejects_an_audience_other_than_the_one_issued() {
        let e = Env::new();
        let pres = resign(&e.holder, &e.pres(|_, _| {}), |_, p| {
            p["aud"] = json!("did:key:someone-else");
        });
        e.rejects(&pres, "audience is not the one this listener issued");
    }

    #[test]
    fn rejects_a_nonce_that_was_never_issued() {
        let e = Env::new();
        let pres = resign(&e.holder, &e.pres(|_, _| {}), |_, p| {
            p["nonce"] = json!("never-issued");
        });
        e.rejects(&pres, "challenge nonce is not valid");
    }

    #[test]
    fn rejects_a_nonce_issued_for_another_task() {
        let e = Env::new();
        let d = discs();
        let cred = credential(
            &issuer_key(),
            &base_header(),
            &base_claims(&e.holder, &d),
            &d,
        );
        let c = e.nonces.issue("task-2", NOW).unwrap();
        let pres = present_n(&e.holder, &cred, d.len(), &c.nonce, &c.aud, NOW);
        e.rejects(&pres, "challenge nonce is not valid");
    }

    #[test]
    fn a_replayed_presentation_fails_the_second_time() {
        let e = Env::new();
        let pres = e.pres(|_, _| {});
        e.verify(&pres).expect("first");
        e.rejects(&pres, "challenge nonce is not valid");
    }

    #[test]
    fn a_replay_costs_no_signature_check() {
        let e = Env::new();
        // A forged signature would say so if it were reached.
        let pres = resign(&e.holder, &e.pres(|_, _| {}), |_, _| {});
        let forged = {
            let (head, kb) = pres.rsplit_once('~').unwrap();
            let (input, _) = kb.rsplit_once('.').unwrap();
            format!("{head}~{input}.{}", URL_SAFE_NO_PAD.encode([0u8; 64]))
        };
        e.rejects(&forged, "key-binding JWT signature");
        e.rejects(&forged, "challenge nonce is not valid");
    }

    #[test]
    fn rejects_an_expired_credential() {
        let e = Env::new();
        let pres = e.pres(|_, c| c["exp"] = json!(NOW - 1));
        e.rejects(&pres, "has expired");
        let at_exp = e.pres(|_, c| c["exp"] = json!(NOW));
        e.rejects(&at_exp, "has expired");
    }

    #[test]
    fn rejects_a_credential_that_is_not_yet_valid() {
        let e = Env::new();
        let pres = e.pres(|_, c| c["nbf"] = json!(NOW + 1));
        e.rejects(&pres, "not yet valid");
        let ok = e.pres(|_, c| c["nbf"] = json!(NOW));
        e.verify(&ok).expect("nbf == now is valid");
    }

    #[test]
    fn rejects_an_iat_too_far_in_the_future_or_past() {
        let e = Env::new();
        let pres = e.pres(|_, _| {});
        let future = resign(&e.holder, &pres, |_, p| {
            p["iat"] = json!(NOW + KB_FUTURE_SKEW_SECS + 1);
        });
        e.rejects(&future, "`iat` is in the future");

        let e = Env::new();
        let past = resign(&e.holder, &e.pres(|_, _| {}), |_, p| {
            p["iat"] = json!(NOW - KB_MAX_AGE_SECS - 1);
        });
        e.rejects(&past, "too old");
    }

    #[test]
    fn accepts_an_iat_at_the_skew_and_age_limits() {
        for iat in [NOW + KB_FUTURE_SKEW_SECS, NOW - KB_MAX_AGE_SECS] {
            let e = Env::new();
            let pres = resign(&e.holder, &e.pres(|_, _| {}), |_, p| p["iat"] = json!(iat));
            e.verify(&pres).expect("within the window");
        }
    }

    #[test]
    fn rejects_a_tampered_sd_hash() {
        let e = Env::new();
        let pres = resign(&e.holder, &e.pres(|_, _| {}), |_, p| {
            p["sd_hash"] = json!(URL_SAFE_NO_PAD.encode([0u8; 32]));
        });
        e.rejects(&pres, "`sd_hash` does not match");
    }

    /// The issuer committed to a third disclosure, but the holder never signed
    /// over it: adding it after the build changes what `sd_hash` covers.
    #[test]
    fn rejects_a_committed_disclosure_appended_after_the_build() {
        let e = Env::new();
        let mut d = discs();
        d.push(disclosure("admin", "sekrit-value"));
        let cred = credential(
            &issuer_key(),
            &base_header(),
            &base_claims(&e.holder, &d),
            &d,
        );
        let c = e.challenge();
        let pres = present_n(&e.holder, &cred, 2, &c.nonce, &c.aud, NOW);
        let (head, kb) = pres.rsplit_once('~').unwrap();
        let tampered = format!("{head}~{}~{kb}", d[2]);
        e.rejects(&tampered, "`sd_hash` does not match");
    }

    #[test]
    fn rejects_an_uncommitted_disclosure_appended_after_the_build() {
        let e = Env::new();
        let pres = e.pres(|_, _| {});
        let (head, kb) = pres.rsplit_once('~').unwrap();
        let appended = disclosure("admin", "sekrit-value");
        let err = e
            .verify(&format!("{head}~{appended}~{kb}"))
            .expect_err("must reject");
        assert!(err.contains("not committed"), "{err}");
        assert!(!err.contains("sekrit-value"), "{err}");
    }

    #[test]
    fn errors_never_carry_token_content() {
        let e = Env::new();
        let pres = resign(&e.holder, &e.pres(|_, _| {}), |_, p| {
            p["aud"] = json!("secret-audience");
        });
        let err = e.verify(&pres).expect_err("must reject");
        assert!(!err.contains("secret-audience"), "{err}");
        assert!(!err.contains(&pres), "{err}");
    }
}
