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
    /// Tools this issuer's principals may run, matched against the
    /// attestation's `tool` claim.
    ///
    /// Empty means unrestricted. Fail-open here is deliberate: every policy
    /// file written before tools were enforced omits the field, and reading
    /// that as "no tool may run" would deny every sender on upgrade.
    ///
    /// **Not a boundary against a dishonest principal.** The `tool` claim is
    /// self-asserted — the sender signs its own attestation — so this narrows
    /// what an honest principal's agents can do, not what a compromised key
    /// can claim. Use `denied_principals` for that.
    #[serde(default)]
    pub permitted_tools: Vec<String>,
    /// Where this issuer publishes an account's SSH keys, `{}` standing for the
    /// principal. Set it and the issuer is backed by a published key list; omit
    /// it and only pinned `local_attestations` speak for it.
    ///
    /// From policy, never from a message: a sender-supplied URL would let it
    /// nominate its own authority.
    #[serde(default)]
    pub keys_url_template: Option<String>,
    /// How stale a fetched key list may be.
    #[serde(default = "default_key_list_ttl")]
    pub key_list_ttl_seconds: u64,
}

fn default_key_list_ttl() -> u64 {
    900
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
    /// Tolerance on an attestation's `iat`/`exp` against local time.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
}

fn default_stale_grace() -> u64 {
    1200
}

fn default_clock_skew() -> u64 {
    60
}

/// Upper bound on `clock_skew_seconds`. An hour absorbs any real drift; past
/// that the skew starts substituting for expiry rather than tolerating it.
const MAX_CLOCK_SKEW_SECONDS: u64 = 3600;

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

        let policy: Self = serde_json::from_slice(&bytes)
            .map_err(|e| IdentityError::Config(format!("parse policy {}: {e}", path.display())))?;
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
            if let Some(template) = &issuer.keys_url_template {
                // Without the placeholder every principal resolves to the same
                // URL, which would admit one account's keys for everyone.
                if !template.contains("{}") {
                    return Err(IdentityError::Config(format!(
                        "keys_url_template {template:?} has no {{}} placeholder for the principal"
                    )));
                }
                if !template.starts_with("https://") {
                    return Err(IdentityError::Config(format!(
                        "keys_url_template {template:?} must be https"
                    )));
                }
                // A published-keys anchor only ever fetches for a principal on
                // this list, and the attestation it builds carries no verified
                // email, so `allowed_domains` cannot admit anyone either. With
                // an empty list the issuer silently admits nobody.
                if issuer.allowed_principals.is_empty() {
                    return Err(IdentityError::Config(format!(
                        "issuer {} sets keys_url_template but no allowed_principals, so it \
                         can admit nobody; list the principals or drop the template",
                        issuer.issuer
                    )));
                }
                // Zero would refetch the key list on every single message.
                if issuer.key_list_ttl_seconds == 0 {
                    return Err(IdentityError::Config(format!(
                        "issuer {} has key_list_ttl_seconds 0, which refetches on every message",
                        issuer.issuer
                    )));
                }
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

        // Expiry is `now <= exp + skew`, so a large skew saturates and stops
        // bounding anything at all.
        if self.clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS {
            return Err(IdentityError::Config(format!(
                "clock_skew_seconds {} exceeds {MAX_CLOCK_SKEW_SECONDS}; a skew that large \
                 disables attestation expiry",
                self.clock_skew_seconds
            )));
        }

        // A pinned attestation's claims are written by hand, so an issuer that
        // restricts tools would reject its own pins at admission time. Catch it
        // here instead, where the operator is looking at the file.
        for att in &self.local_attestations {
            let Some(issuer) = self
                .trusted_issuers
                .iter()
                .find(|i| i.issuer == att.authority)
            else {
                continue;
            };
            if issuer.permitted_tools.is_empty() {
                continue;
            }
            if att.claims.get("tool").and_then(|t| t.as_str()).is_none() {
                return Err(IdentityError::Config(format!(
                    "local_attestations entry for {} has no string \"tool\" claim, but issuer {} \
                     restricts permitted_tools, so it would be denied on every message",
                    att.did, issuer.issuer
                )));
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

        let permitted = if issuer
            .allowed_principals
            .iter()
            .any(|p| p == &att.principal)
        {
            true
        } else if !issuer.allowed_domains.is_empty() {
            // Email is policy input, never identity, and only when verified —
            // at some IdPs the claim is attacker-chosen.
            let email = att
                .email
                .as_deref()
                .filter(|_| att.email_verified)
                .ok_or_else(|| "no verified email for domain policy".to_string())?;
            let domain = email_domain(email).ok_or_else(|| format!("unparseable email {email}"))?;
            issuer
                .allowed_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(domain))
        } else {
            false
        };

        if !permitted {
            return Err(format!(
                "principal {} is not permitted by issuer {}",
                att.principal, issuer.issuer
            ));
        }

        // Applies to both routes above: being an allowed principal does not
        // also decide which tool that principal may run. Keeping this out of
        // the branches is what stops an allow-listed user running any tool.
        Self::evaluate_tool(issuer, att)
    }

    fn evaluate_tool(issuer: &TrustedIssuer, att: &Attestation) -> Result<(), String> {
        if issuer.permitted_tools.is_empty() {
            return Ok(());
        }
        match att.claims.get("tool").and_then(|t| t.as_str()) {
            Some(tool) if issuer.permitted_tools.iter().any(|t| t == tool) => Ok(()),
            Some(tool) => Err(format!(
                "tool {tool} is not permitted for principal {}",
                att.principal
            )),
            // An absent or non-string claim is a denial, never a skipped check.
            None => Err(format!(
                "attestation for principal {} names no tool, but issuer {} restricts tools",
                att.principal, issuer.issuer
            )),
        }
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
            vec![attestation(
                ALICE,
                "alice-sub",
                Some("alice@corp.com"),
                true,
            )],
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

    fn with_tool(mut att: Attestation, tool: &str) -> Attestation {
        att.claims.insert("tool".to_string(), tool.into());
        att
    }

    fn tool_policy(principals: &[&str], tools: &[&str]) -> AdmissionPolicy {
        AdmissionPolicy {
            trusted_issuers: vec![TrustedIssuer {
                issuer: ISSUER.to_string(),
                allowed_principals: principals.iter().map(|p| p.to_string()).collect(),
                permitted_tools: tools.iter().map(|t| t.to_string()).collect(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn a_permitted_tool_is_admitted_and_others_are_denied() {
        let policy = tool_policy(&["alice-sub"], &["claude-code", "copilot"]);
        let allowed = with_tool(attestation(ALICE, "alice-sub", None, false), "claude-code");
        assert!(matches!(
            admitter(vec![allowed], policy.clone()).admit(ALICE, None),
            Admission::Admitted { .. }
        ));

        let wrong = with_tool(attestation(ALICE, "alice-sub", None, false), "codex");
        match admitter(vec![wrong], policy).admit(ALICE, None) {
            Admission::Denied { reason, .. } => assert!(reason.contains("tool codex"), "{reason}"),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    /// The tool gate has to survive *both* ways a principal can be permitted.
    /// Inside the allow-list branch it would be skipped for exactly the users
    /// a deployment names explicitly — silently, with no log line.
    #[test]
    fn the_tool_gate_applies_to_domain_matches_too() {
        let mut policy = tool_policy(&[], &["claude-code"]);
        policy.trusted_issuers[0].allowed_domains = vec!["corp.com".to_string()];
        let att = with_tool(
            attestation(ALICE, "alice-sub", Some("alice@corp.com"), true),
            "codex",
        );
        match admitter(vec![att], policy).admit(ALICE, None) {
            Admission::Denied { reason, .. } => assert!(reason.contains("tool codex"), "{reason}"),
            other => panic!("a domain match must still be tool-checked, got {other:?}"),
        }
    }

    #[test]
    fn an_attestation_with_no_tool_is_denied_only_when_tools_are_restricted() {
        let att = attestation(ALICE, "alice-sub", None, false);
        match admitter(
            vec![att.clone()],
            tool_policy(&["alice-sub"], &["claude-code"]),
        )
        .admit(ALICE, None)
        {
            Admission::Denied { reason, .. } => {
                assert!(reason.contains("names no tool"), "{reason}")
            }
            other => panic!("expected Denied, got {other:?}"),
        }

        // Empty `permitted_tools` stays unrestricted, so existing policy files
        // keep admitting senders that name no tool.
        assert!(matches!(
            admitter(vec![att], tool_policy(&["alice-sub"], &[])).admit(ALICE, None),
            Admission::Admitted { .. }
        ));
    }

    /// A non-string claim must not read as absent-and-allowed.
    #[test]
    fn a_non_string_tool_claim_is_denied() {
        let mut att = attestation(ALICE, "alice-sub", None, false);
        att.claims.insert("tool".to_string(), 42.into());
        match admitter(vec![att], tool_policy(&["alice-sub"], &["claude-code"])).admit(ALICE, None)
        {
            Admission::Denied { .. } => {}
            other => panic!("expected Denied, got {other:?}"),
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
        assert!(matches!(
            broken.admit(ALICE, None),
            Admission::Denied { .. }
        ));
    }

    #[test]
    fn a_deny_listed_principal_is_rejected() {
        let mut p = policy(&["corp.com"]);
        p.denied_principals = vec!["alice-sub".to_string()];
        let a = admitter(
            vec![attestation(
                ALICE,
                "alice-sub",
                Some("alice@corp.com"),
                true,
            )],
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
            vec![attestation(
                ALICE,
                "alice-sub",
                Some("Alice@CORP.COM"),
                true,
            )],
            policy(&["corp.com"]),
        );
        assert!(matches!(a.admit(ALICE, None), Admission::Admitted { .. }));
    }

    #[test]
    fn an_unverified_email_fails_the_domain_check() {
        let a = admitter(
            vec![attestation(
                ALICE,
                "alice-sub",
                Some("alice@corp.com"),
                false,
            )],
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
            vec![Box::new(LocalAnchor::new(
                "https://other-idp.example",
                vec![att],
            ))],
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
                    vec![attestation(
                        ALICE,
                        "alice-sub",
                        Some("alice@corp.com"),
                        true,
                    )],
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

    /// A template without the placeholder would resolve every principal to one
    /// URL, admitting a single account's keys for everyone.
    #[test]
    fn a_keys_url_template_must_be_https_and_name_the_principal() {
        let with_template = |t: &str| {
            let mut p = policy(&["corp.com"]);
            p.trusted_issuers[0].keys_url_template = Some(t.to_string());
            p.trusted_issuers[0].allowed_principals = vec!["alice-sub".to_string()];
            p.trusted_issuers[0].key_list_ttl_seconds = 900;
            p
        };
        assert!(with_template("https://github.com/{}.keys")
            .validate()
            .is_ok());
        assert!(with_template("https://github.com/keys").validate().is_err());
        assert!(with_template("http://github.com/{}.keys")
            .validate()
            .is_err());
    }

    /// The anchor only fetches for a listed principal, and the attestation it
    /// builds carries no verified email, so a domains-only issuer with a
    /// template admits nobody at all.
    #[test]
    fn a_keys_url_template_needs_allowed_principals() {
        let mut p = policy(&["corp.com"]);
        p.trusted_issuers[0].keys_url_template = Some("https://github.com/{}.keys".to_string());
        p.trusted_issuers[0].key_list_ttl_seconds = 900;
        let err = p.validate().expect_err("must refuse to load").to_string();
        assert!(err.contains("admit nobody"), "{err}");
    }

    #[test]
    fn a_zero_key_list_ttl_refuses_to_load() {
        let mut p = policy(&["corp.com"]);
        p.trusted_issuers[0].keys_url_template = Some("https://github.com/{}.keys".to_string());
        p.trusted_issuers[0].allowed_principals = vec!["alice-sub".to_string()];
        p.trusted_issuers[0].key_list_ttl_seconds = 0;
        let err = p.validate().expect_err("must refuse to load").to_string();
        assert!(err.contains("key_list_ttl_seconds"), "{err}");
    }

    /// `now <= exp + skew` saturates, so a huge skew stops bounding expiry.
    #[test]
    fn an_absurd_clock_skew_refuses_to_load() {
        let mut p = policy(&["corp.com"]);
        p.clock_skew_seconds = u64::MAX;
        let err = p.validate().expect_err("must refuse to load").to_string();
        assert!(err.contains("disables attestation expiry"), "{err}");

        p.clock_skew_seconds = 60;
        assert!(p.validate().is_ok());
    }

    /// Pinned attestations carry hand-written claims. An issuer that restricts
    /// tools would deny its own pins on every message, so say so at load.
    #[test]
    fn a_pinned_attestation_without_a_tool_refuses_to_load_under_tool_policy() {
        let mut p = tool_policy(&["alice-sub"], &["claude-code"]);
        p.local_attestations = vec![attestation(ALICE, "alice-sub", None, false)];
        let err = p.validate().expect_err("must refuse to load").to_string();
        assert!(err.contains("no string \"tool\" claim"), "{err}");

        // With the claim present, or with tools unrestricted, it loads.
        p.local_attestations = vec![with_tool(
            attestation(ALICE, "alice-sub", None, false),
            "claude-code",
        )];
        assert!(p.validate().is_ok());

        let mut unrestricted = tool_policy(&["alice-sub"], &[]);
        unrestricted.local_attestations = vec![attestation(ALICE, "alice-sub", None, false)];
        assert!(unrestricted.validate().is_ok());
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
