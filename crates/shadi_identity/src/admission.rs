// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The enforcement point: an envelope-verified DID in, a verdict out.
//!
//! Order matters and is the security property. Deny-lists are consulted
//! *before* the cache, so revocation is immediate rather than TTL-bound; and
//! an anchor that *errors* must never degrade to "unknown peer", or DoSing the
//! anchor becomes a way to soften the verdict.
//!
//! # The trade this makes
//!
//! Today a stolen `SLIM_HUMAN_SEED` yields DIDs that a human still has to
//! paste into every peer's allow-list, and that friction is real containment.
//! Attestation-driven admission removes it: those DIDs become admissible
//! org-wide with no human in the loop. That is a better provenance story and a
//! *wider* blast radius for key compromise. [`AdmissionPolicy::denied_dids`]
//! is the lever that has to exist because of it — keep `permitted_tools`
//! narrow for the same reason.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::trust_anchor::{Attestation, TrustAnchor, ATTESTATION_TTL};
use crate::IdentityError;

/// The verdict on one peer. Four outcomes, because they mean different things
/// operationally even where two of them park the same task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Admitted {
        did: String,
        principal: String,
        authority: String,
    },
    /// Identified, and the answer is no. Terminal — retrying will not help.
    Denied { did: String, reason: String },
    /// No authority vouches for this DID. Recoverable: the peer may enroll.
    Unattested { did: String },
    /// An authority should have known, but could not be reached. Fails closed.
    /// Distinct from `Unattested` so an outage is diagnosable from logs —
    /// "I don't know you" and "I can't reach who would" are not the same
    /// incident.
    AnchorUnavailable { did: String, reason: String },
}

/// One authority and who it may speak for.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    /// Matched against [`Attestation::authority`] — an OIDC issuer URL, or
    /// `github.com`.
    pub issuer: String,
    /// Email domains this issuer may vouch for. Matched only against a
    /// *verified* address, and only as the exact label after the last `@`.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Individual principals, as this issuer names them.
    #[serde(default)]
    pub allowed_principals: Vec<String>,
    /// Tools this issuer's principals may run.
    ///
    /// **Not enforced yet**: nothing on the wire names the *sender's* tool, so
    /// there is no input to match against. Accepted so a deployment can write
    /// the intended list now, and so the field is not silently dropped.
    #[serde(default)]
    pub permitted_tools: Vec<String>,
}

/// The whole of a deployment's trust configuration.
///
/// Note what is absent: no DIDs *to admit*. Nobody edits this file when an
/// agent joins or leaves — only to revoke, or to change who is trusted.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionPolicy {
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// Checked before the cache, so it takes effect on an already-cached peer.
    #[serde(default)]
    pub denied_dids: Vec<String>,
    #[serde(default)]
    pub denied_principals: Vec<String>,
    /// How long past [`ATTESTATION_TTL`] a cached attestation may still be
    /// served when the anchor is unreachable. Trades a longer revocation
    /// window for outage tolerance; `0` disables stale serving.
    #[serde(default = "default_stale_grace")]
    pub stale_grace_seconds: u64,
    /// Reject payloads carrying no freshness fields. Leave `false` while any
    /// sender still predates sealing, then turn it on.
    #[serde(default)]
    pub require_freshness: bool,
    /// `LocalAnchor` entries: the operator-pinned `principal -> did` pairs.
    #[serde(default)]
    pub local_attestations: Vec<Attestation>,
}

fn default_stale_grace() -> u64 {
    1200
}

impl AdmissionPolicy {
    /// Load from disk.
    ///
    /// Nothing checks the file's owner or mode yet: whoever can write it owns
    /// admission, so that is worth adding, but it belongs with the wider
    /// question of how a `LocalAnchor`'s pinned attestations are trusted
    /// rather than bolted on here.
    /// TODO: add owner check to admission policy file read.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let bytes = std::fs::read(path)
            .map_err(|e| IdentityError::Config(format!("read {}: {e}", path.display())))?;

        let policy: Self = serde_json::from_slice(&bytes).map_err(|e| {
            IdentityError::Config(format!("parse policy {}: {e}", path.display()))
        })?;
        policy.validate()?;

        // Logged so configuration drift across hosts is detectable from logs
        // alone, without shipping the file itself.
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(&bytes);
        tracing::info!(
            path = %path.display(),
            sha256 = %digest[..8].iter().map(|b| format!("{b:02x}")).collect::<String>(),
            issuers = policy.trusted_issuers.len(),
            denied_dids = policy.denied_dids.len(),
            "loaded admission policy"
        );
        Ok(policy)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        for issuer in &self.trusted_issuers {
            if issuer.issuer.is_empty() {
                return Err(IdentityError::Config(
                    "trusted_issuers entry has an empty issuer".to_string(),
                ));
            }
            for domain in &issuer.allowed_domains {
                // Under rollout pressure the tempting entry is "*". If the
                // grammar cannot express it, it cannot happen.
                if domain.contains('*') {
                    return Err(IdentityError::Config(format!(
                        "wildcard {domain:?} is not permitted in allowed_domains"
                    )));
                }
                if domain != domain.trim() || domain.is_empty() || !domain.is_ascii() {
                    return Err(IdentityError::Config(format!(
                        "allowed_domains entry {domain:?} is not a plain ASCII domain"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Evaluate an attestation. `Err` carries the denial reason.
    fn evaluate(&self, att: &Attestation) -> Result<(), String> {
        if self.denied_dids.iter().any(|d| d == &att.did) {
            return Err("DID is deny-listed".to_string());
        }
        if self.denied_principals.iter().any(|p| p == &att.principal) {
            return Err("principal is deny-listed".to_string());
        }

        // Identity is the (authority, principal) pair, never principal alone:
        // two issuers can both mint `sub = alice`.
        let issuer = self
            .trusted_issuers
            .iter()
            .find(|i| i.issuer == att.authority)
            .ok_or_else(|| format!("authority {} is not trusted", att.authority))?;

        if issuer.allowed_principals.iter().any(|p| p == &att.principal) {
            return Ok(());
        }

        if !issuer.allowed_domains.is_empty() {
            // Email is policy input, never identity, and only when verified —
            // at some IdPs the claim is attacker-chosen.
            let email = att
                .email
                .as_deref()
                .filter(|_| att.email_verified)
                .ok_or_else(|| "no verified email for domain policy".to_string())?;
            let domain =
                email_domain(email).ok_or_else(|| format!("unparseable email {email}"))?;
            if issuer
                .allowed_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(domain))
            {
                return Ok(());
            }
        }

        Err(format!(
            "principal {} is not permitted by issuer {}",
            att.principal, issuer.issuer
        ))
    }
}

/// The exact domain after the **last** `@`.
///
/// Never a suffix or substring test: `evil-cisco.com`, `cisco.com.evil.com`,
/// a trailing dot and `a@b@cisco.com` must all fail against `cisco.com`.
/// Non-ASCII is refused outright rather than guessed at — homoglyph domains
/// need IDNA normalisation, which is not done here.
fn email_domain(email: &str) -> Option<&str> {
    if email.matches('@').count() != 1 || !email.is_ascii() {
        return None;
    }
    let (local, domain) = email.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.ends_with('.') || !domain.contains('.') {
        return None;
    }
    Some(domain)
}

/// Resolves a DID to a principal through the configured anchors, then judges it.
pub struct Admitter {
    anchors: Vec<Box<dyn TrustAnchor>>,
    policy: AdmissionPolicy,
    cache: Mutex<HashMap<String, (Attestation, Instant)>>,
}

impl Admitter {
    pub fn new(anchors: Vec<Box<dyn TrustAnchor>>, policy: AdmissionPolicy) -> Self {
        Self {
            anchors,
            policy,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn policy(&self) -> &AdmissionPolicy {
        &self.policy
    }

    /// Judge `did`, which the caller must already have envelope-verified.
    ///
    /// `hint` is unauthenticated; it only selects whose attestation to fetch.
    pub fn admit(&self, did: &str, hint: Option<&str>) -> Admission {
        // Deny-list first, so revocation does not wait for a cached
        // attestation to expire.
        if self.policy.denied_dids.iter().any(|d| d == did) {
            return Admission::Denied {
                did: did.to_string(),
                reason: "DID is deny-listed".to_string(),
            };
        }

        let att = match self.resolve_cached(did, hint) {
            Ok(Some(att)) => att,
            Ok(None) => {
                return Admission::Unattested {
                    did: did.to_string(),
                }
            }
            Err(reason) => {
                return Admission::AnchorUnavailable {
                    did: did.to_string(),
                    reason,
                }
            }
        };

        // An anchor must not be able to answer about a DID other than the one
        // asked about, whatever the hint said.
        if att.did != did {
            return Admission::Denied {
                did: did.to_string(),
                reason: format!("anchor {} answered for a different DID", att.authority),
            };
        }

        match self.policy.evaluate(&att) {
            Ok(()) => Admission::Admitted {
                did: att.did,
                principal: att.principal,
                authority: att.authority,
            },
            Err(reason) => Admission::Denied {
                did: did.to_string(),
                reason,
            },
        }
    }

    /// Warm the cache for a DID learned during discovery, so the first message
    /// does no network I/O on the latency- and availability-critical path.
    pub fn prewarm(&self, did: &str, hint: Option<&str>) {
        if let Err(e) = self.resolve_cached(did, hint) {
            tracing::debug!(%did, "attestation prewarm failed: {e}");
        }
    }

    fn resolve_cached(&self, did: &str, hint: Option<&str>) -> Result<Option<Attestation>, String> {
        if let Some((att, at)) = self.cached(did) {
            if at.elapsed() < ATTESTATION_TTL {
                return Ok(Some(att));
            }
        }

        let mut last_err = None;
        for anchor in &self.anchors {
            match anchor.resolve(did, hint) {
                Ok(Some(att)) => {
                    self.cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(did.to_string(), (att.clone(), Instant::now()));
                    return Ok(Some(att));
                }
                // Abstained. Another anchor may still be able to answer.
                Ok(None) => {}
                Err(e) => last_err = Some(format!("{}: {e}", anchor.authority())),
            }
        }

        let Some(err) = last_err else {
            return Ok(None);
        };

        // An anchor errored rather than abstaining. Serve a stale entry if
        // policy allows, else fail closed — never fall through to
        // `Unattested`, which would let an attacker DoS an anchor to soften
        // the verdict.
        if self.policy.stale_grace_seconds > 0 {
            let grace = ATTESTATION_TTL + Duration::from_secs(self.policy.stale_grace_seconds);
            if let Some((att, at)) = self.cached(did) {
                if at.elapsed() < grace {
                    tracing::warn!(%did, "serving stale attestation: {err}");
                    return Ok(Some(att));
                }
            }
        }
        Err(err)
    }

    fn cached(&self, did: &str) -> Option<(Attestation, Instant)> {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(did)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_anchor::LocalAnchor;

    const ISSUER: &str = "https://sso.example/oauth2/default";
    const ALICE: &str = "did:key:zAlice";

    fn attestation(did: &str, principal: &str, email: Option<&str>, verified: bool) -> Attestation {
        Attestation {
            did: did.to_string(),
            principal: principal.to_string(),
            authority: ISSUER.to_string(),
            email: email.map(str::to_string),
            email_verified: verified,
            claims: serde_json::Map::new(),
        }
    }

    fn policy(domains: &[&str]) -> AdmissionPolicy {
        AdmissionPolicy {
            trusted_issuers: vec![TrustedIssuer {
                issuer: ISSUER.to_string(),
                allowed_domains: domains.iter().map(|d| d.to_string()).collect(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn admitter(entries: Vec<Attestation>, policy: AdmissionPolicy) -> Admitter {
        Admitter::new(vec![Box::new(LocalAnchor::new(ISSUER, entries))], policy)
    }

    /// An anchor that always fails, standing in for an unreachable authority.
    struct BrokenAnchor;

    impl TrustAnchor for BrokenAnchor {
        fn resolve(
            &self,
            _did: &str,
            _hint: Option<&str>,
        ) -> Result<Option<Attestation>, IdentityError> {
            Err(IdentityError::Config("connection refused".to_string()))
        }

        fn authority(&self) -> &str {
            "broken.example"
        }
    }

    #[test]
    fn admits_an_attested_principal_in_an_allowed_domain() {
        let a = admitter(
            vec![attestation(ALICE, "alice-sub", Some("alice@corp.com"), true)],
            policy(&["corp.com"]),
        );
        match a.admit(ALICE, None) {
            Admission::Admitted {
                principal,
                authority,
                ..
            } => {
                assert_eq!(principal, "alice-sub");
                assert_eq!(authority, ISSUER);
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_did_is_unattested_not_denied() {
        let a = admitter(vec![], policy(&["corp.com"]));
        assert!(matches!(
            a.admit("did:key:zStranger", None),
            Admission::Unattested { .. }
        ));
    }

    /// The point of moving the deny-list into this phase: it has to bite a
    /// peer whose valid attestation is already cached, so revocation does not
    /// wait for `ATTESTATION_TTL`.
    #[test]
    fn the_deny_list_is_checked_before_any_resolution() {
        let att = attestation(ALICE, "alice-sub", Some("alice@corp.com"), true);
        let mut p = policy(&["corp.com"]);
        p.denied_dids = vec![ALICE.to_string()];

        let a = admitter(vec![att], p.clone());
        a.prewarm(ALICE, None);
        match a.admit(ALICE, None) {
            Admission::Denied { reason, .. } => {
                assert!(reason.contains("deny-listed"), "{reason}")
            }
            other => panic!("expected Denied on a cached attestation, got {other:?}"),
        }

        // And with an anchor that cannot answer at all: `Denied`, not
        // `AnchorUnavailable`, proves the check precedes resolution entirely.
        let broken = Admitter::new(vec![Box::new(BrokenAnchor)], p);
        assert!(matches!(broken.admit(ALICE, None), Admission::Denied { .. }));
    }

    #[test]
    fn a_deny_listed_principal_is_rejected() {
        let mut p = policy(&["corp.com"]);
        p.denied_principals = vec!["alice-sub".to_string()];
        let a = admitter(
            vec![attestation(ALICE, "alice-sub", Some("alice@corp.com"), true)],
            p,
        );
        assert!(matches!(a.admit(ALICE, None), Admission::Denied { .. }));
    }

    /// The classic domain-matching bugs, each of which would admit a stranger.
    #[test]
    fn domain_matching_is_exact_and_anchored() {
        for email in [
            "alice@evil-corp.com",
            "alice@corp.com.evil.com",
            "alice@corp.com.",
            "alice@sub.corp.com",
            "a@b@corp.com",
            "alice@",
            "@corp.com",
            "alice-at-corp.com",
        ] {
            let a = admitter(
                vec![attestation(ALICE, "alice-sub", Some(email), true)],
                policy(&["corp.com"]),
            );
            assert!(
                matches!(a.admit(ALICE, None), Admission::Denied { .. }),
                "must reject {email}"
            );
        }
        // Case folds, since domains are case-insensitive.
        let a = admitter(
            vec![attestation(ALICE, "alice-sub", Some("Alice@CORP.COM"), true)],
            policy(&["corp.com"]),
        );
        assert!(matches!(a.admit(ALICE, None), Admission::Admitted { .. }));
    }

    #[test]
    fn an_unverified_email_fails_the_domain_check() {
        let a = admitter(
            vec![attestation(ALICE, "alice-sub", Some("alice@corp.com"), false)],
            policy(&["corp.com"]),
        );
        assert!(matches!(a.admit(ALICE, None), Admission::Denied { .. }));
    }

    /// Identity is `(authority, principal)`. The same `sub` from another
    /// issuer must not inherit access.
    #[test]
    fn the_same_sub_from_another_issuer_does_not_cross_admit() {
        let mut att = attestation(ALICE, "alice-sub", Some("alice@corp.com"), true);
        att.authority = "https://other-idp.example".to_string();
        let a = Admitter::new(
            vec![Box::new(LocalAnchor::new("https://other-idp.example", vec![att]))],
            policy(&["corp.com"]),
        );
        match a.admit(ALICE, None) {
            Admission::Denied { reason, .. } => assert!(reason.contains("not trusted"), "{reason}"),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn allowed_principals_admits_without_an_email() {
        let mut p = policy(&[]);
        p.trusted_issuers[0].allowed_principals = vec!["alice-sub".to_string()];
        let a = admitter(vec![attestation(ALICE, "alice-sub", None, false)], p);
        assert!(matches!(a.admit(ALICE, None), Admission::Admitted { .. }));
    }

    /// Fail closed. If an anchor error degraded to `Unattested` — or worse,
    /// to admitted — DoSing the anchor would be a bypass.
    #[test]
    fn an_anchor_error_yields_anchor_unavailable() {
        let a = Admitter::new(vec![Box::new(BrokenAnchor)], policy(&["corp.com"]));
        match a.admit(ALICE, None) {
            Admission::AnchorUnavailable { reason, .. } => {
                assert!(reason.contains("broken.example"), "{reason}")
            }
            other => panic!("expected AnchorUnavailable, got {other:?}"),
        }
    }

    /// An abstaining anchor ahead of a working one must not mask it.
    #[test]
    fn anchors_are_tried_in_order_and_abstention_is_not_failure() {
        let a = Admitter::new(
            vec![
                Box::new(LocalAnchor::new(ISSUER, vec![])),
                Box::new(LocalAnchor::new(
                    ISSUER,
                    vec![attestation(ALICE, "alice-sub", Some("alice@corp.com"), true)],
                )),
            ],
            policy(&["corp.com"]),
        );
        assert!(matches!(a.admit(ALICE, None), Admission::Admitted { .. }));
    }

    #[test]
    fn a_wildcard_domain_refuses_to_load() {
        let mut p = policy(&["*"]);
        assert!(p.validate().is_err());
        p = policy(&["*.corp.com"]);
        assert!(p.validate().is_err());
        assert!(policy(&["corp.com"]).validate().is_ok());
        assert!(policy(&[" corp.com"]).validate().is_err());
    }

    #[test]
    fn policy_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("shadi-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "trusted_issuers": [{ "issuer": ISSUER, "allowed_domains": ["corp.com"] }],
                "denied_dids": [ALICE],
            })
            .to_string(),
        )
        .unwrap();
        let loaded = AdmissionPolicy::load(&path).unwrap();
        assert_eq!(loaded.trusted_issuers[0].allowed_domains, ["corp.com"]);
        assert_eq!(loaded.denied_dids, [ALICE]);
        assert_eq!(loaded.stale_grace_seconds, default_stale_grace());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_policy_field_is_an_error_not_a_silent_ignore() {
        // A typo in a security-relevant key must not be silently dropped.
        assert!(serde_json::from_str::<AdmissionPolicy>(r#"{"denied_did": []}"#).is_err());
    }
}
