// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The owner's side of a channel: what its SHADI does when an agent asks to
//! let someone in.
//!
//! Standing rules decide most requests, so agents stay autonomous: *allow*
//! signs a grant on the spot, *block* refuses, and *ask* waits for the human,
//! denying on timeout. Every decision is appended to an audit log. See
//! agntcy/shadi#420 for the contract and #421 for the Desktop view.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use shadi_identity::{issue_grant, parse_did_key, AgentIdentity, GrantAction, GrantRole};

const DEFAULT_ASK_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_GRANT_SECONDS: u64 = 3600;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OwnerError {
    #[error("owner policy: {0}")]
    Policy(String),
    #[error("no pending ask {0}")]
    UnknownAsk(u64),
    #[error("ask {0} expired before it was answered")]
    Expired(u64),
    #[error("signing the grant failed: {0}")]
    Grant(String),
    #[error("writing the audit log failed: {0}")]
    Audit(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Block,
}

/// A request to let `invitee_name` into `channel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InviteRequest {
    pub channel: String,
    /// The participant's SLIM name: the invite goes to it and the grant
    /// binds it.
    pub invitee_name: String,
    /// The DID the room admits under that name, when the requester gave one.
    pub invitee_did: Option<String>,
    /// Who asked: the agent DID its proof established, or the subject a
    /// channel manager verified.
    pub requester: String,
    /// The human the requester's binding names, when it carried one.
    pub requester_human_did: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    /// A channel name, or `*` for every channel this owner holds.
    channel: String,
    invitee: Option<String>,
    requested_by: Option<String>,
    requested_by_human: Option<String>,
    decision: Decision,
}

impl Rule {
    fn matches(&self, request: &InviteRequest) -> bool {
        let is = |want: &Option<String>, have: Option<&str>| {
            want.as_deref().is_none_or(|want| Some(want) == have)
        };
        (self.channel == "*" || self.channel == request.channel)
            && match self.invitee.as_deref() {
                Some(did) if did.starts_with("did:") => Some(did) == request.invitee_did.as_deref(),
                invitee => is(&invitee.map(str::to_string), Some(&request.invitee_name)),
            }
            && is(&self.requested_by, Some(&request.requester))
            && is(
                &self.requested_by_human,
                request.requester_human_did.as_deref(),
            )
    }
}

/// The owner's standing rules. The first matching rule decides; `default`
/// decides when none matches, and is `ask` when omitted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPolicy {
    #[serde(default = "ask")]
    default: Decision,
    #[serde(default = "default_ask_timeout")]
    ask_timeout_seconds: u64,
    #[serde(default = "default_grant")]
    grant_seconds: u64,
    #[serde(default)]
    rules: Vec<Rule>,
}

fn ask() -> Decision {
    Decision::Ask
}

fn default_ask_timeout() -> u64 {
    DEFAULT_ASK_TIMEOUT_SECONDS
}

fn default_grant() -> u64 {
    DEFAULT_GRANT_SECONDS
}

impl Default for OwnerPolicy {
    fn default() -> Self {
        Self {
            default: Decision::Ask,
            ask_timeout_seconds: DEFAULT_ASK_TIMEOUT_SECONDS,
            grant_seconds: DEFAULT_GRANT_SECONDS,
            rules: Vec::new(),
        }
    }
}

/// Which part of the policy decided, for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "by", content = "index")]
pub enum DecidedBy {
    Rule(usize),
    Default,
    /// The channel isn't one this owner holds, so no rule applied.
    NotHeld,
    Owner,
    Timeout,
}

impl OwnerPolicy {
    /// Parse and validate a policy, refusing at load what could never match
    /// or would silently mean something else.
    pub fn from_json(text: &str) -> Result<Self, OwnerError> {
        let policy: Self =
            serde_json::from_str(text).map_err(|e| OwnerError::Policy(e.to_string()))?;
        if policy.ask_timeout_seconds == 0 {
            return Err(OwnerError::Policy(
                "ask_timeout_seconds of 0 denies every ask before anyone sees it".to_string(),
            ));
        }
        if policy.grant_seconds == 0 {
            return Err(OwnerError::Policy(
                "grant_seconds of 0 issues grants that are already expired".to_string(),
            ));
        }
        for (index, rule) in policy.rules.iter().enumerate() {
            let at = |what: String| OwnerError::Policy(format!("rule {index}: {what}"));
            if rule.channel != "*" && !is_slim_name(&rule.channel) {
                return Err(at(format!(
                    "channel {:?} is neither `*` nor org/namespace/channel",
                    rule.channel
                )));
            }
            // A DID must be a key; anything else is a name the request
            // carries as is.
            for (field, value) in [
                ("invitee", &rule.invitee),
                ("requested_by", &rule.requested_by),
                ("requested_by_human", &rule.requested_by_human),
            ] {
                match value.as_deref() {
                    Some(did) if did.starts_with("did:") || field == "requested_by_human" => {
                        parse_did_key(did).map_err(|e| at(format!("{field}: {e}")))?;
                    }
                    Some(name) if field == "invitee" && !is_slim_name(name) => {
                        return Err(at(format!(
                            "invitee {name:?} is neither a did:key nor a SLIM name"
                        )));
                    }
                    Some("") => return Err(at(format!("{field} is empty"))),
                    _ => {}
                }
            }
        }
        Ok(policy)
    }

    pub fn decide(&self, request: &InviteRequest) -> (Decision, DecidedBy) {
        self.rules
            .iter()
            .position(|rule| rule.matches(request))
            .map(|index| (self.rules[index].decision, DecidedBy::Rule(index)))
            .unwrap_or((self.default, DecidedBy::Default))
    }
}

fn is_slim_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Signed now. The caller invites the invitee with it.
    Granted(Vec<u8>),
    /// Waiting for the owner until `expires_at`.
    Pending {
        ask_id: u64,
        expires_at: u64,
    },
    Refused(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingAsk {
    pub id: u64,
    pub request: InviteRequest,
    pub asked_at: u64,
    pub expires_at: u64,
}

/// One decision, as a line of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    pub at: u64,
    pub outcome: &'static str,
    #[serde(flatten)]
    pub by: DecidedBy,
    #[serde(flatten)]
    pub request: InviteRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_not_after: Option<u64>,
}

/// The owner's SHADI for the channels it holds.
pub struct Owner {
    identity: AgentIdentity,
    policy: OwnerPolicy,
    channels: BTreeSet<String>,
    pending: BTreeMap<u64, PendingAsk>,
    next_ask: u64,
    audit_path: Option<PathBuf>,
    audit: Vec<AuditEntry>,
}

impl Owner {
    /// `identity` is the human key that signs grants. Decisions are appended
    /// to `audit_path` as JSON lines when one is given.
    pub fn new(identity: AgentIdentity, policy: OwnerPolicy, audit_path: Option<PathBuf>) -> Self {
        Self {
            identity,
            policy,
            channels: BTreeSet::new(),
            pending: BTreeMap::new(),
            next_ask: 1,
            audit_path,
            audit: Vec::new(),
        }
    }

    pub fn owner_did(&self) -> String {
        self.identity.did()
    }

    /// Hold `channel`: only requests for held channels are decided at all.
    pub fn hold(&mut self, channel: impl Into<String>) {
        self.channels.insert(channel.into());
    }

    pub fn release(&mut self, channel: &str) {
        self.channels.remove(channel);
    }

    /// Hold exactly `channels`, releasing any other.
    pub fn hold_only(&mut self, channels: impl IntoIterator<Item = String>) {
        self.channels = channels.into_iter().collect();
    }

    pub fn held(&self) -> impl Iterator<Item = &str> {
        self.channels.iter().map(String::as_str)
    }

    pub fn set_policy(&mut self, policy: OwnerPolicy) {
        self.policy = policy;
    }

    pub fn pending(&self) -> impl Iterator<Item = &PendingAsk> {
        self.pending.values()
    }

    /// Every decision made since this owner started, oldest first.
    pub fn audit(&self) -> &[AuditEntry] {
        &self.audit
    }

    pub fn request(&mut self, request: InviteRequest, now: u64) -> Result<Outcome, OwnerError> {
        if !self.channels.contains(&request.channel) {
            let reason = format!("{} is not a channel this owner holds", request.channel);
            self.record(now, "refused", DecidedBy::NotHeld, &request, None, None)?;
            return Ok(Outcome::Refused(reason));
        }
        match self.policy.decide(&request) {
            (Decision::Allow, by) => self.grant(request, by, None, now).map(Outcome::Granted),
            (Decision::Block, by) => {
                self.record(now, "refused", by, &request, None, None)?;
                Ok(Outcome::Refused(
                    "refused by the owner's policy".to_string(),
                ))
            }
            (Decision::Ask, by) => {
                let id = self.next_ask;
                self.next_ask += 1;
                let expires_at = now + self.policy.ask_timeout_seconds;
                self.record(now, "asked", by, &request, Some(id), None)?;
                self.pending.insert(
                    id,
                    PendingAsk {
                        id,
                        request,
                        asked_at: now,
                        expires_at,
                    },
                );
                Ok(Outcome::Pending {
                    ask_id: id,
                    expires_at,
                })
            }
        }
    }

    /// The owner allows a pending ask: sign its grant.
    pub fn approve(&mut self, ask_id: u64, now: u64) -> Result<Vec<u8>, OwnerError> {
        let ask = self.take_live(ask_id, now)?;
        self.grant(ask.request, DecidedBy::Owner, Some(ask_id), now)
    }

    pub fn deny(&mut self, ask_id: u64, now: u64) -> Result<(), OwnerError> {
        let ask = self.take_live(ask_id, now)?;
        self.record(
            now,
            "denied",
            DecidedBy::Owner,
            &ask.request,
            Some(ask_id),
            None,
        )
    }

    /// Deny every ask nobody answered in time, returning them.
    pub fn expire(&mut self, now: u64) -> Result<Vec<PendingAsk>, OwnerError> {
        let lapsed: Vec<u64> = self
            .pending
            .values()
            .filter(|ask| now >= ask.expires_at)
            .map(|ask| ask.id)
            .collect();
        let mut denied = Vec::new();
        for id in lapsed {
            let ask = self.pending.remove(&id).expect("listed above");
            self.record(
                now,
                "denied",
                DecidedBy::Timeout,
                &ask.request,
                Some(id),
                None,
            )?;
            denied.push(ask);
        }
        Ok(denied)
    }

    fn take_live(&mut self, ask_id: u64, now: u64) -> Result<PendingAsk, OwnerError> {
        let ask = self
            .pending
            .get(&ask_id)
            .ok_or(OwnerError::UnknownAsk(ask_id))?;
        if now >= ask.expires_at {
            self.expire(now)?;
            return Err(OwnerError::Expired(ask_id));
        }
        Ok(self.pending.remove(&ask_id).expect("checked above"))
    }

    fn grant(
        &mut self,
        request: InviteRequest,
        by: DecidedBy,
        ask_id: Option<u64>,
        now: u64,
    ) -> Result<Vec<u8>, OwnerError> {
        let not_after = now + self.policy.grant_seconds;
        let grant = issue_grant(
            &self.identity,
            &request.channel,
            &request.invitee_name,
            GrantAction::Add,
            GrantRole::Member,
            not_after,
        )
        .map_err(|e| OwnerError::Grant(e.to_string()))?;
        self.record(now, "granted", by, &request, ask_id, Some(not_after))?;
        Ok(grant)
    }

    fn record(
        &mut self,
        at: u64,
        outcome: &'static str,
        by: DecidedBy,
        request: &InviteRequest,
        ask_id: Option<u64>,
        grant_not_after: Option<u64>,
    ) -> Result<(), OwnerError> {
        let entry = AuditEntry {
            at,
            outcome,
            by,
            request: request.clone(),
            ask_id,
            grant_not_after,
        };
        if let Some(path) = &self.audit_path {
            let mut line =
                serde_json::to_string(&entry).map_err(|e| OwnerError::Audit(e.to_string()))?;
            line.push('\n');
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut file| file.write_all(line.as_bytes()))
                .map_err(|e| OwnerError::Audit(format!("{}: {e}", path.display())))?;
        }
        tracing::info!(
            outcome,
            channel = %request.channel,
            invitee = %request.invitee_name,
            requester = %request.requester,
            "channel owner decided a request"
        );
        self.audit.push(entry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadi_identity::verify_grant;

    const NOW: u64 = 1_700_000_000;
    const ROOM: &str = "agntcy/shadi/review-room";
    const PEER: &str = "agntcy/shadi/copilot";

    struct Cast {
        owner: AgentIdentity,
        agent: AgentIdentity,
        peer: AgentIdentity,
        human: AgentIdentity,
    }

    fn cast() -> Cast {
        Cast {
            owner: AgentIdentity::generate().unwrap(),
            agent: AgentIdentity::generate().unwrap(),
            peer: AgentIdentity::generate().unwrap(),
            human: AgentIdentity::generate().unwrap(),
        }
    }

    fn request(cast: &Cast, channel: &str, human: Option<&AgentIdentity>) -> InviteRequest {
        InviteRequest {
            channel: channel.to_string(),
            invitee_name: PEER.to_string(),
            invitee_did: Some(cast.peer.did()),
            requester: cast.agent.did(),
            requester_human_did: human.map(AgentIdentity::did),
        }
    }

    fn owner(cast: &Cast, policy: &str) -> Owner {
        let owner = AgentIdentity::from_signing_key_bytes(&cast.owner.signing_key_bytes());
        let mut owner = Owner::new(owner, OwnerPolicy::from_json(policy).unwrap(), None);
        owner.hold(ROOM);
        owner
    }

    #[test]
    fn an_allow_rule_signs_a_grant_the_owner_did_verifies() {
        let cast = cast();
        let policy = format!(
            r#"{{"rules": [{{"channel": "*", "requested_by_human": "{}", "decision": "allow"}}]}}"#,
            cast.human.did()
        );
        let mut owner = owner(&cast, &policy);

        let Outcome::Granted(grant) = owner
            .request(request(&cast, ROOM, Some(&cast.human)), NOW)
            .unwrap()
        else {
            panic!("expected a grant");
        };
        let grant = verify_grant(&grant, &cast.owner.did(), NOW).unwrap();
        assert_eq!(
            (grant.channel.as_str(), grant.invitee.as_str()),
            (ROOM, PEER)
        );
        assert_eq!(grant.not_after, NOW + DEFAULT_GRANT_SECONDS);
        assert_eq!(owner.audit()[0].by, DecidedBy::Rule(0));
        assert_eq!(owner.audit()[0].outcome, "granted");
    }

    #[test]
    fn the_first_matching_rule_decides() {
        let cast = cast();
        let policy = format!(
            r#"{{"default": "allow", "rules": [
                {{"channel": "{ROOM}", "invitee": "{}", "decision": "block"}},
                {{"channel": "*", "decision": "allow"}}
            ]}}"#,
            cast.peer.did()
        );
        let mut owner = owner(&cast, &policy);
        let outcome = owner.request(request(&cast, ROOM, None), NOW).unwrap();
        assert_eq!(
            outcome,
            Outcome::Refused("refused by the owner's policy".to_string())
        );
        assert_eq!(owner.audit()[0].by, DecidedBy::Rule(0));
    }

    #[test]
    fn an_invitee_rule_matches_by_name_or_by_did() {
        let cast = cast();
        for invitee in [PEER.to_string(), cast.peer.did()] {
            let policy = format!(
                r#"{{"default": "block", "rules": [{{"channel": "*", "invitee": "{invitee}", "decision": "allow"}}]}}"#
            );
            let mut owner = owner(&cast, &policy);
            let outcome = owner.request(request(&cast, ROOM, None), NOW).unwrap();
            assert!(
                matches!(outcome, Outcome::Granted(_)),
                "{invitee}: {outcome:?}"
            );
        }

        // Without the invitee's DID, a DID rule can't match.
        let policy = format!(
            r#"{{"default": "block", "rules": [{{"channel": "*", "invitee": "{}", "decision": "allow"}}]}}"#,
            cast.peer.did()
        );
        let mut owner = owner(&cast, &policy);
        let mut nameless = request(&cast, ROOM, None);
        nameless.invitee_did = None;
        assert!(matches!(
            owner.request(nameless, NOW).unwrap(),
            Outcome::Refused(_)
        ));
    }

    #[test]
    fn a_requester_may_be_any_subject_a_channel_manager_verified() {
        let cast = cast();
        let policy = r#"{"default": "block", "rules": [{"channel": "*", "requested_by": "spiffe://example.org/agent", "decision": "allow"}]}"#;
        let mut owner = owner(&cast, policy);
        let mut request = request(&cast, ROOM, None);
        request.requester = "spiffe://example.org/agent".to_string();
        assert!(matches!(
            owner.request(request, NOW).unwrap(),
            Outcome::Granted(_)
        ));
    }

    #[test]
    fn a_rule_naming_a_human_skips_a_requester_with_no_binding() {
        let cast = cast();
        let policy = format!(
            r#"{{"default": "block", "rules": [{{"channel": "*", "requested_by_human": "{}", "decision": "allow"}}]}}"#,
            cast.human.did()
        );
        let mut owner = owner(&cast, &policy);
        let outcome = owner.request(request(&cast, ROOM, None), NOW).unwrap();
        assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
        assert_eq!(owner.audit()[0].by, DecidedBy::Default);
    }

    #[test]
    fn with_no_rules_the_owner_is_asked_and_can_approve() {
        let cast = cast();
        let mut owner = owner(&cast, "{}");
        let Outcome::Pending { ask_id, expires_at } =
            owner.request(request(&cast, ROOM, None), NOW).unwrap()
        else {
            panic!("expected an ask");
        };
        assert_eq!(expires_at, NOW + DEFAULT_ASK_TIMEOUT_SECONDS);
        assert_eq!(owner.pending().count(), 1);

        let grant = owner.approve(ask_id, NOW + 10).unwrap();
        verify_grant(&grant, &cast.owner.did(), NOW + 10).unwrap();
        assert_eq!(owner.pending().count(), 0);
        let outcomes: Vec<_> = owner.audit().iter().map(|e| (e.outcome, e.by)).collect();
        assert_eq!(
            outcomes,
            [("asked", DecidedBy::Default), ("granted", DecidedBy::Owner)]
        );
        assert_eq!(
            owner.approve(ask_id, NOW + 11),
            Err(OwnerError::UnknownAsk(ask_id))
        );
    }

    #[test]
    fn an_unanswered_ask_is_denied_and_cannot_be_approved_late() {
        let cast = cast();
        let mut owner = owner(&cast, r#"{"ask_timeout_seconds": 60}"#);
        let Outcome::Pending { ask_id, .. } =
            owner.request(request(&cast, ROOM, None), NOW).unwrap()
        else {
            panic!("expected an ask");
        };
        assert!(owner.expire(NOW + 59).unwrap().is_empty());
        assert_eq!(
            owner.approve(ask_id, NOW + 60),
            Err(OwnerError::Expired(ask_id))
        );
        assert_eq!(owner.pending().count(), 0);
        let last = owner.audit().last().unwrap();
        assert_eq!((last.outcome, last.by), ("denied", DecidedBy::Timeout));
    }

    #[test]
    fn the_owner_can_deny_and_expire_sweeps_what_is_left() {
        let cast = cast();
        let mut owner = owner(&cast, r#"{"ask_timeout_seconds": 60}"#);
        let ask = |owner: &mut Owner| match owner.request(request(&cast, ROOM, None), NOW).unwrap()
        {
            Outcome::Pending { ask_id, .. } => ask_id,
            other => panic!("expected an ask, got {other:?}"),
        };
        let (first, second) = (ask(&mut owner), ask(&mut owner));
        assert_ne!(first, second);
        owner.deny(first, NOW + 1).unwrap();
        let swept = owner.expire(NOW + 60).unwrap();
        assert_eq!(swept.iter().map(|a| a.id).collect::<Vec<_>>(), [second]);
        assert_eq!(
            owner.deny(first, NOW + 61),
            Err(OwnerError::UnknownAsk(first))
        );
    }

    #[test]
    fn a_channel_the_owner_does_not_hold_is_refused_before_any_rule() {
        let cast = cast();
        let mut owner = owner(&cast, r#"{"default": "allow"}"#);
        let outcome = owner
            .request(request(&cast, "agntcy/shadi/someone-elses", None), NOW)
            .unwrap();
        assert!(
            matches!(outcome, Outcome::Refused(ref r) if r.contains("not a channel")),
            "{outcome:?}"
        );
        assert_eq!(owner.audit()[0].by, DecidedBy::NotHeld);

        owner.release(ROOM);
        let outcome = owner.request(request(&cast, ROOM, None), NOW).unwrap();
        assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");

        owner.hold_only([ROOM.to_string()]);
        assert_eq!(owner.held().collect::<Vec<_>>(), [ROOM]);
        assert!(matches!(
            owner.request(request(&cast, ROOM, None), NOW).unwrap(),
            Outcome::Granted(_)
        ));
    }

    #[test]
    fn decisions_are_appended_to_the_audit_file() {
        let cast = cast();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner-audit.jsonl");
        let identity = AgentIdentity::from_signing_key_bytes(&cast.owner.signing_key_bytes());
        let policy = OwnerPolicy::from_json(r#"{"default": "allow"}"#).unwrap();
        let mut owner = Owner::new(identity, policy, Some(path.clone()));
        owner.hold(ROOM);
        owner.request(request(&cast, ROOM, None), NOW).unwrap();
        owner.request(request(&cast, ROOM, None), NOW + 1).unwrap();

        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["outcome"], "granted");
        assert_eq!(lines[0]["by"], "default");
        assert_eq!(lines[0]["channel"], ROOM);
        assert_eq!(lines[1]["at"], NOW + 1);
        assert_eq!(lines[0]["grant_not_after"], NOW + DEFAULT_GRANT_SECONDS);
    }

    #[test]
    fn a_policy_that_could_not_mean_what_it_says_is_refused_at_load() {
        for (bad, why) in [
            (
                r#"{"rules": [{"channel": "*", "decision": "maybe"}]}"#,
                "unknown variant",
            ),
            (
                r#"{"rules": [{"channel": "room", "decision": "allow"}]}"#,
                "neither",
            ),
            (
                r#"{"rules": [{"channel": "*", "invitee": "did:web:x", "decision": "allow"}]}"#,
                "rule 0: invitee",
            ),
            (
                r#"{"rules": [{"channel": "*", "invitee": "room", "decision": "allow"}]}"#,
                "neither a did:key nor a SLIM name",
            ),
            (
                r#"{"rules": [{"channel": "*", "requested_by": "", "decision": "allow"}]}"#,
                "requested_by is empty",
            ),
            (
                r#"{"rules": [{"channel": "*", "decision": "allow", "extra": 1}]}"#,
                "unknown field",
            ),
            (r#"{"defaults": "allow"}"#, "unknown field"),
            (r#"{"ask_timeout_seconds": 0}"#, "denies every ask"),
            (r#"{"grant_seconds": 0}"#, "already expired"),
        ] {
            let err = OwnerPolicy::from_json(bad).unwrap_err().to_string();
            assert!(err.contains(why), "{bad}: {err}");
        }
        assert_eq!(
            OwnerPolicy::from_json("{}").unwrap(),
            OwnerPolicy::default()
        );
    }
}
