use std::collections::{BTreeMap, BTreeSet};

use crate::runtime::CoordinationEngine;
use crate::types::{
    AgentId, Epoch, EventId, EventOutcome, FinalizationSummary, PatternKind, RejectReason,
    RuntimeCounters, SemanticEvent, SemanticPayload,
};

/// Configuration for the `DevelopmentEngine`.
///
/// Each round, agents submit code artifacts (as `ExternalBytes`) and every
/// participant casts a ballot: `ToolResult { accepted: true }` endorses the
/// agent named in `tool_name`, `accepted: false` abstains. Once every
/// participant has cast one, the most endorsed artifact wins if it has at
/// least `quorum` endorsements. Otherwise the round closes without a winner
/// and the next one starts, until the last of `max_rounds` selects the most
/// endorsed artifact whatever its count. Ties go to the alphabetically first
/// agent.
///
/// With no `participants`, nobody can tell when everyone has voted, so a
/// round closes only when an artifact reaches `quorum`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevelopmentEngineConfig {
    pub participants: BTreeSet<AgentId>,
    /// Endorsements the winning artifact needs.
    pub quorum: usize,
    /// Rounds before the last one selects the most endorsed artifact without
    /// `quorum`.
    pub max_rounds: u64,
}

impl DevelopmentEngineConfig {
    pub fn new<I>(participants: I, quorum: usize, max_rounds: u64) -> Self
    where
        I: IntoIterator<Item = AgentId>,
    {
        Self {
            participants: participants.into_iter().collect(),
            quorum,
            max_rounds,
        }
    }
}

/// Coordinates multiple agents toward a shared software artifact, as
/// [`DevelopmentEngineConfig`] describes. A finalization's
/// `selected_value` is the winner's endorsement count. Finalized artifacts
/// are retrievable via [`selected_artifact`](Self::selected_artifact).
#[derive(Clone, Debug)]
pub struct DevelopmentEngine {
    active_epoch: Epoch,
    config: DevelopmentEngineConfig,
    seen_events: BTreeSet<EventId>,
    /// Proposals indexed by submitting participant.
    proposals: BTreeMap<AgentId, Vec<u8>>,
    /// Ballots: voter → the participant they endorse, `None` to abstain.
    ballots: BTreeMap<AgentId, Option<AgentId>>,
    /// Finalized artifacts keyed by epoch.
    selected: BTreeMap<Epoch, Vec<u8>>,
    counters: RuntimeCounters,
}

impl DevelopmentEngine {
    pub fn new(active_epoch: Epoch, config: DevelopmentEngineConfig) -> Self {
        Self {
            active_epoch,
            config,
            seen_events: BTreeSet::new(),
            proposals: BTreeMap::new(),
            ballots: BTreeMap::new(),
            selected: BTreeMap::new(),
            counters: RuntimeCounters::default(),
        }
    }

    pub fn active_epoch(&self) -> Epoch {
        self.active_epoch
    }

    /// Returns the finalized artifact for an epoch, if any.
    pub fn selected_artifact(&self, epoch: Epoch) -> Option<&[u8]> {
        self.selected.get(&epoch).map(|v| v.as_slice())
    }

    fn knows(&self, agent: &AgentId) -> bool {
        self.config.participants.is_empty() || self.config.participants.contains(agent)
    }

    /// The most endorsed proposal and its endorsements; the first in agent
    /// order on a tie.
    fn leader(&self) -> Option<(AgentId, usize)> {
        let mut leader: Option<(&AgentId, usize)> = None;
        for agent in self.proposals.keys() {
            let endorsements = self
                .ballots
                .values()
                .filter(|endorsee| endorsee.as_ref() == Some(agent))
                .count();
            if leader.is_none_or(|(_, most)| endorsements > most) {
                leader = Some((agent, endorsements));
            }
        }
        leader.map(|(agent, endorsements)| (agent.clone(), endorsements))
    }

    /// Close the round once its outcome is known: every participant has
    /// voted or, with an open participant set, an artifact reached quorum.
    fn try_close(&mut self) -> EventOutcome {
        let leader = self.leader();
        let reached = leader
            .as_ref()
            .is_some_and(|(_, endorsements)| *endorsements >= self.config.quorum);
        if self.config.participants.is_empty() {
            return match leader {
                Some(winner) if reached => self.finalize(winner),
                _ => EventOutcome::Applied,
            };
        }
        if !self
            .config
            .participants
            .iter()
            .all(|participant| self.ballots.contains_key(participant))
        {
            return EventOutcome::Applied;
        }
        let last_round = self.active_epoch.0 + 1 >= self.config.max_rounds;
        match leader {
            Some(winner) if reached || last_round => self.finalize(winner),
            _ => {
                self.next_round();
                EventOutcome::Applied
            }
        }
    }

    fn finalize(&mut self, (winner, endorsements): (AgentId, usize)) -> EventOutcome {
        let summary = FinalizationSummary {
            epoch: self.active_epoch,
            participants: self.proposals.len(),
            selected_value: endorsements as i64,
        };
        let artifact = self.proposals.remove(&winner).unwrap_or_default();
        self.selected.insert(self.active_epoch, artifact);
        self.counters.finalized += 1;
        self.next_round();
        EventOutcome::Finalized(summary)
    }

    fn next_round(&mut self) {
        self.proposals.clear();
        self.ballots.clear();
        self.active_epoch = Epoch(self.active_epoch.0 + 1);
    }

    fn accept_proposal(&mut self, participant: AgentId, artifact: Vec<u8>) -> EventOutcome {
        if !self.knows(&participant) {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::UnknownParticipant);
        }
        self.proposals.insert(participant, artifact);
        self.counters.applied += 1;
        EventOutcome::Applied
    }

    fn accept_ballot(&mut self, voter: AgentId, endorsee: Option<AgentId>) -> EventOutcome {
        if !self.knows(&voter) {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::UnknownParticipant);
        }
        self.ballots.insert(voter, endorsee);
        self.counters.applied += 1;
        self.try_close()
    }
}

impl CoordinationEngine for DevelopmentEngine {
    fn pattern(&self) -> PatternKind {
        PatternKind::Development
    }

    fn apply(&mut self, event: SemanticEvent) -> EventOutcome {
        if event.pattern != PatternKind::Development {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::IncompatiblePattern);
        }

        if self.selected.contains_key(&event.metadata.epoch) {
            self.counters.rejected += 1;
            self.counters.stale += 1;
            return EventOutcome::Rejected(RejectReason::FinalizedEpoch {
                epoch: event.metadata.epoch,
            });
        }

        if event.metadata.epoch < self.active_epoch {
            self.counters.rejected += 1;
            self.counters.stale += 1;
            return EventOutcome::Rejected(RejectReason::StaleEpoch {
                current: self.active_epoch,
            });
        }

        if event.metadata.epoch > self.active_epoch {
            self.counters.deferred += 1;
            return EventOutcome::Deferred {
                expected: self.active_epoch,
                received: event.metadata.epoch,
            };
        }

        let event_id = event.metadata.event_id.clone();
        if !self.seen_events.insert(event_id) {
            self.counters.rejected += 1;
            self.counters.duplicates += 1;
            return EventOutcome::Rejected(RejectReason::DuplicateEvent);
        }

        match event.payload {
            // Code artifact submission: source agent is the proposing participant.
            SemanticPayload::ExternalBytes(bytes) => {
                let participant = match &event.metadata.source {
                    crate::types::EventSource::Peer(id) => id.clone(),
                    crate::types::EventSource::Local => {
                        AgentId("local".to_string())
                    }
                    _ => {
                        self.counters.rejected += 1;
                        return EventOutcome::Rejected(RejectReason::UnknownParticipant);
                    }
                };
                self.accept_proposal(participant, bytes)
            }
            // Ballot: accepted=true endorses tool_name (an AgentId), false abstains.
            SemanticPayload::ToolResult {
                tool_name,
                accepted,
            } => {
                let voter = match &event.metadata.source {
                    crate::types::EventSource::Peer(id) => id.clone(),
                    _ => AgentId("local".to_string()),
                };
                self.accept_ballot(voter, accepted.then_some(AgentId(tool_name)))
            }
            _ => {
                self.counters.applied += 1;
                EventOutcome::Applied
            }
        }
    }

    fn counters(&self) -> RuntimeCounters {
        self.counters.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::MasRuntime;
    use crate::types::{EventMetadata, EventSource};

    fn engine() -> MasRuntime<DevelopmentEngine> {
        engine_with(3, 10)
    }

    fn engine_with(quorum: usize, max_rounds: u64) -> MasRuntime<DevelopmentEngine> {
        let config = DevelopmentEngineConfig::new(
            [
                AgentId::from("claude"),
                AgentId::from("copilot"),
                AgentId::from("codex"),
            ],
            quorum,
            max_rounds,
        );
        MasRuntime::new(DevelopmentEngine::new(Epoch(0), config))
    }

    fn propose_all(rt: &mut MasRuntime<DevelopmentEngine>, epoch: u64) {
        for agent in ["claude", "copilot", "codex"] {
            let id = format!("p-{agent}-{epoch}");
            let outcome = rt.apply(proposal(&id, epoch, agent, agent.as_bytes()));
            assert_eq!(outcome, EventOutcome::Applied);
        }
    }

    fn abstain(id: &str, epoch: u64, voter: &str) -> SemanticEvent {
        let mut event = vote(id, epoch, voter, "");
        event.payload = SemanticPayload::ToolResult {
            tool_name: String::new(),
            accepted: false,
        };
        event
    }

    fn proposal(id: &str, epoch: u64, agent: &str, code: &[u8]) -> SemanticEvent {
        SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from(id),
                correlation_id: None,
                epoch: Epoch(epoch),
                source: EventSource::Peer(AgentId::from(agent)),
            },
            payload: SemanticPayload::ExternalBytes(code.to_vec()),
        }
    }

    fn vote(id: &str, epoch: u64, voter: &str, endorsee: &str) -> SemanticEvent {
        SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from(id),
                correlation_id: None,
                epoch: Epoch(epoch),
                source: EventSource::Peer(AgentId::from(voter)),
            },
            payload: SemanticPayload::ToolResult {
                tool_name: endorsee.to_string(),
                accepted: true,
            },
        }
    }

    #[test]
    fn finalizes_once_every_participant_has_voted() {
        let mut rt = engine();
        propose_all(&mut rt, 0);
        assert_eq!(
            rt.apply(vote("v1", 0, "claude", "codex")),
            EventOutcome::Applied
        );
        assert_eq!(
            rt.apply(vote("v2", 0, "copilot", "codex")),
            EventOutcome::Applied
        );

        let outcome = rt.apply(vote("v3", 0, "codex", "codex"));
        assert!(matches!(outcome, EventOutcome::Finalized(ref s) if s.selected_value == 3));
        assert_eq!(rt.engine().active_epoch(), Epoch(1));
        assert_eq!(
            rt.engine().selected_artifact(Epoch(0)),
            Some(b"codex".as_slice())
        );
    }

    /// agntcy/shadi#319: a quorum below the participant count used to close
    /// the round on proposals, so every vote landed after it and was refused.
    #[test]
    fn a_quorum_below_the_participant_count_counts_every_vote() {
        let mut rt = engine_with(2, 10);
        propose_all(&mut rt, 0);
        rt.apply(vote("v1", 0, "claude", "codex"));
        rt.apply(vote("v2", 0, "copilot", "codex"));
        let outcome = rt.apply(vote("v3", 0, "codex", "codex"));

        assert!(matches!(outcome, EventOutcome::Finalized(ref s) if s.selected_value == 3));
        assert_eq!(
            rt.engine().selected_artifact(Epoch(0)),
            Some(b"codex".as_slice())
        );
        let counters = rt.engine().counters();
        assert_eq!((counters.applied, counters.rejected), (6, 0));
    }

    #[test]
    fn the_most_endorsed_artifact_wins() {
        let mut rt = engine_with(2, 10);
        propose_all(&mut rt, 0);
        rt.apply(vote("v1", 0, "claude", "claude"));
        rt.apply(vote("v2", 0, "copilot", "claude"));
        rt.apply(vote("v3", 0, "codex", "copilot"));

        assert_eq!(
            rt.engine().selected_artifact(Epoch(0)),
            Some(b"claude".as_slice())
        );
    }

    #[test]
    fn ties_go_to_the_alphabetically_first_agent() {
        let mut rt = engine_with(1, 10);
        propose_all(&mut rt, 0);
        rt.apply(vote("v1", 0, "claude", "copilot"));
        rt.apply(vote("v2", 0, "copilot", "codex"));
        rt.apply(abstain("v3", 0, "codex"));

        assert_eq!(
            rt.engine().selected_artifact(Epoch(0)),
            Some(b"codex".as_slice())
        );
    }

    #[test]
    fn a_round_without_quorum_closes_and_the_next_one_starts() {
        let mut rt = engine_with(2, 10);
        propose_all(&mut rt, 0);
        rt.apply(vote("v1", 0, "claude", "claude"));
        rt.apply(vote("v2", 0, "copilot", "copilot"));
        assert_eq!(rt.apply(abstain("v3", 0, "codex")), EventOutcome::Applied);

        assert_eq!(rt.engine().active_epoch(), Epoch(1));
        assert_eq!(rt.engine().selected_artifact(Epoch(0)), None);
        propose_all(&mut rt, 1);
        assert_eq!(
            rt.apply(proposal("p-late", 0, "claude", b"late")),
            EventOutcome::Rejected(RejectReason::StaleEpoch { current: Epoch(1) })
        );
    }

    #[test]
    fn the_last_round_selects_the_most_endorsed_artifact_without_quorum() {
        let mut rt = engine_with(3, 1);
        propose_all(&mut rt, 0);
        rt.apply(vote("v1", 0, "claude", "copilot"));
        rt.apply(vote("v2", 0, "copilot", "copilot"));
        let outcome = rt.apply(abstain("v3", 0, "codex"));

        assert!(matches!(outcome, EventOutcome::Finalized(ref s) if s.selected_value == 2));
        assert_eq!(
            rt.engine().selected_artifact(Epoch(0)),
            Some(b"copilot".as_slice())
        );
    }

    #[test]
    fn an_unknown_voter_is_rejected() {
        let mut rt = engine();
        assert_eq!(
            rt.apply(vote("v-mallory", 0, "mallory", "claude")),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );
    }

    #[test]
    fn rejects_duplicate_event() {
        let mut rt = engine();
        let ev = proposal("p1", 0, "claude", b"fn x() {}");
        assert_eq!(rt.apply(ev.clone()), EventOutcome::Applied);
        assert_eq!(rt.apply(ev), EventOutcome::Rejected(RejectReason::DuplicateEvent));
    }

    #[test]
    fn defers_future_epoch() {
        let mut rt = engine();
        let ev = proposal("future", 1, "claude", b"fn x() {}");
        assert_eq!(
            rt.apply(ev),
            EventOutcome::Deferred { expected: Epoch(0), received: Epoch(1) }
        );
    }

    #[test]
    fn rejects_incompatible_pattern() {
        let mut rt = engine();
        let ev = SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from("e1"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Local,
            },
            payload: SemanticPayload::ExternalBytes(b"code".to_vec()),
        };
        assert_eq!(rt.apply(ev), EventOutcome::Rejected(RejectReason::IncompatiblePattern));
    }

    #[test]
    fn pattern_returns_development() {
        let config = DevelopmentEngineConfig::new([], 1, 10);
        let engine = DevelopmentEngine::new(Epoch(0), config);
        assert_eq!(engine.pattern(), PatternKind::Development);
    }

    #[test]
    fn counters_accessible_on_engine() {
        let config = DevelopmentEngineConfig::new([], 1, 10);
        let engine = DevelopmentEngine::new(Epoch(0), config);
        let c = engine.counters();
        assert_eq!(c.applied, 0);
        assert_eq!(c.rejected, 0);
    }

    #[test]
    fn unknown_participant_rejected_in_proposal() {
        // Closed participant set; "mallory" is not a member.
        let config = DevelopmentEngineConfig::new(
            [AgentId::from("claude"), AgentId::from("copilot")],
            2,
            10,
        );
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let ev = SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from("e-unknown"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from("mallory")),
            },
            payload: SemanticPayload::ExternalBytes(b"malicious".to_vec()),
        };
        assert_eq!(rt.apply(ev), EventOutcome::Rejected(RejectReason::UnknownParticipant));
    }

    #[test]
    fn an_open_participant_set_finalizes_at_quorum() {
        let config = DevelopmentEngineConfig::new([], 1, 10);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let ev = SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from("e-local"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Local,
            },
            payload: SemanticPayload::ExternalBytes(b"local code".to_vec()),
        };
        assert_eq!(rt.apply(ev), EventOutcome::Applied);
        let endorse = SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from("v-local"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Local,
            },
            payload: SemanticPayload::ToolResult {
                tool_name: "local".to_string(),
                accepted: true,
            },
        };
        assert!(matches!(rt.apply(endorse), EventOutcome::Finalized(_)));
        assert_eq!(rt.engine().selected_artifact(Epoch(0)), Some(b"local code".as_slice()));
    }

    #[test]
    fn unknown_source_type_rejected_in_proposal() {
        let config = DevelopmentEngineConfig::new([], 1, 10);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let ev = SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from("e-tool"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Tool("mcp-server".to_string()),
            },
            payload: SemanticPayload::ExternalBytes(b"code".to_vec()),
        };
        assert_eq!(rt.apply(ev), EventOutcome::Rejected(RejectReason::UnknownParticipant));
    }

    #[test]
    fn finalized_epoch_rejected_after_quorum() {
        let mut rt = engine_with(1, 10);
        propose_all(&mut rt, 0);
        rt.apply(vote("v1", 0, "claude", "claude"));
        rt.apply(vote("v2", 0, "copilot", "claude"));
        rt.apply(vote("v3", 0, "codex", "claude"));
        // Epoch 0 is finalized; late event must be rejected.
        let late = proposal("p-late", 0, "claude", b"fn late() {}");
        assert_eq!(
            rt.apply(late),
            EventOutcome::Rejected(RejectReason::FinalizedEpoch { epoch: Epoch(0) })
        );
    }

    #[test]
    fn a_proposal_alone_never_finalizes() {
        let config = DevelopmentEngineConfig::new([AgentId::from("claude")], 1, 0);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let outcome = rt.apply(proposal("p1", 0, "claude", b"fn code() {}"));
        assert_eq!(outcome, EventOutcome::Applied);
        let outcome = rt.apply(abstain("v1", 0, "claude"));
        assert!(matches!(outcome, EventOutcome::Finalized(ref s) if s.selected_value == 0));
    }

    #[test]
    fn tool_result_accepted_false_is_applied() {
        let config = DevelopmentEngineConfig::new([], 3, 10);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let ev = SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from("v-reject"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from("claude")),
            },
            payload: SemanticPayload::ToolResult {
                tool_name: "codex".to_string(),
                accepted: false,
            },
        };
        assert_eq!(rt.apply(ev), EventOutcome::Applied);
    }

    #[test]
    fn vote_with_non_peer_source_uses_local_id() {
        // A ToolResult vote from EventSource::Local should be accepted, using "local" as voter.
        let config = DevelopmentEngineConfig::new([], 3, 10);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let ev = SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from("v-local"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Local,
            },
            payload: SemanticPayload::ToolResult {
                tool_name: "claude".to_string(),
                accepted: true,
            },
        };
        assert_eq!(rt.apply(ev), EventOutcome::Applied);
    }

    #[test]
    fn rejects_stale_epoch_when_not_finalized() {
        // Engine starts at epoch 2; epoch 0 is not in finalized → StaleEpoch.
        let config = DevelopmentEngineConfig::new([AgentId::from("claude")], 1, 10);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(2), config));
        let ev = proposal("p1", 0, "claude", b"stale code");
        assert_eq!(
            rt.apply(ev),
            EventOutcome::Rejected(RejectReason::StaleEpoch { current: Epoch(2) })
        );
    }

    #[test]
    fn numeric_and_task_payloads_applied() {
        let config = DevelopmentEngineConfig::new([], 3, 10);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));

        let cases: Vec<(&str, SemanticPayload)> = vec![
            (
                "e-proposal",
                SemanticPayload::Proposal(crate::types::Proposal {
                    participant: AgentId::from("claude"),
                    value: 42,
                }),
            ),
            (
                "e-vote",
                SemanticPayload::Vote(crate::types::Vote {
                    participant: AgentId::from("copilot"),
                    value: 1,
                }),
            ),
            (
                "e-task",
                SemanticPayload::TaskResult {
                    task_id: "t-1".to_string(),
                    accepted: true,
                },
            ),
            (
                "e-sens",
                SemanticPayload::Sensitivity(crate::types::Sensitivity {
                    participant: AgentId::from("codex"),
                    delta: -1,
                }),
            ),
        ];

        for (event_id, payload) in cases {
            let ev = SemanticEvent {
                pattern: PatternKind::Development,
                metadata: EventMetadata {
                    event_id: EventId::from(event_id),
                    correlation_id: None,
                    epoch: Epoch(0),
                    source: EventSource::Peer(AgentId::from("claude")),
                },
                payload,
            };
            assert_eq!(rt.apply(ev), EventOutcome::Applied, "failed for event {event_id}");
        }
    }
}
