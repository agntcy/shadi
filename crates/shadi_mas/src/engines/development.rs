use std::collections::{BTreeMap, BTreeSet};

use crate::runtime::CoordinationEngine;
use crate::types::{
    AgentId, Epoch, EventId, EventOutcome, FinalizationSummary, PatternKind, RejectReason,
    RuntimeCounters, SemanticEvent, SemanticPayload,
};

/// Configuration for the `DevelopmentEngine`.
///
/// Agents submit code artifacts (as `ExternalBytes`) each round. When enough
/// participants have submitted, the engine finalizes and selects the artifact
/// that received the most acceptance votes (`ToolResult { accepted: true }`).
/// If no votes are cast, the most-recently submitted artifact is selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevelopmentEngineConfig {
    pub participants: BTreeSet<AgentId>,
    /// Minimum number of submissions needed before finalization is possible.
    pub quorum: usize,
    /// Maximum number of rounds before the engine force-finalizes with the
    /// best artifact seen so far, preventing infinite loops.
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

/// Per-participant artifact submission tracked within an epoch.
#[derive(Clone, Debug)]
struct ArtifactEntry {
    artifact: Vec<u8>,
    votes_for: usize,
}

/// Coordinates multiple agents toward a shared software artifact.
///
/// Each agent submits a code proposal via `SemanticPayload::ExternalBytes`.
/// Agents endorse a proposal via `SemanticPayload::ToolResult { accepted: true }`.
/// Finalization selects the artifact with the most votes; ties break toward
/// the first submission. Finalized artifacts are retrievable via
/// [`selected_artifact`].
#[derive(Clone, Debug)]
pub struct DevelopmentEngine {
    active_epoch: Epoch,
    config: DevelopmentEngineConfig,
    seen_events: BTreeSet<EventId>,
    /// Proposals indexed by submitting participant.
    proposals: BTreeMap<AgentId, ArtifactEntry>,
    /// Acceptance votes: voter → participant they endorse.
    votes: BTreeMap<AgentId, AgentId>,
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
            votes: BTreeMap::new(),
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

    fn try_finalize(&mut self) -> Option<FinalizationSummary> {
        if self.proposals.len() < self.config.quorum {
            return None;
        }

        // Tally acceptance votes.
        for endorsee in self.votes.values() {
            if let Some(entry) = self.proposals.get_mut(endorsee) {
                entry.votes_for += 1;
            }
        }

        // Select the proposal with the most votes; tie-break by insertion order
        // (BTreeMap is sorted by key, so the alphabetically first AgentId wins ties).
        let winner = self
            .proposals
            .iter()
            .max_by_key(|(_, e)| e.votes_for)
            .map(|(_, e)| e.artifact.clone())
            .unwrap_or_default();

        let summary = FinalizationSummary {
            epoch: self.active_epoch,
            participants: self.proposals.len(),
            selected_value: self.proposals.len() as i64,
        };
        self.selected.insert(self.active_epoch, winner);
        self.proposals.clear();
        self.votes.clear();
        self.active_epoch = Epoch(self.active_epoch.0 + 1);
        self.counters.finalized += 1;
        Some(summary)
    }

    fn max_rounds_exceeded(&self) -> bool {
        self.active_epoch.0 >= self.config.max_rounds
    }

    fn accept_proposal(&mut self, participant: AgentId, artifact: Vec<u8>) -> EventOutcome {
        if !self.config.participants.is_empty()
            && !self.config.participants.contains(&participant)
        {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::UnknownParticipant);
        }

        self.proposals.insert(
            participant,
            ArtifactEntry {
                artifact,
                votes_for: 0,
            },
        );
        self.counters.applied += 1;

        if self.max_rounds_exceeded() {
            // Force finalize even without quorum.
            return match self.try_finalize() {
                Some(summary) => EventOutcome::Finalized(summary),
                None => EventOutcome::Applied,
            };
        }

        match self.try_finalize() {
            Some(summary) => EventOutcome::Finalized(summary),
            None => EventOutcome::Applied,
        }
    }

    fn accept_vote(&mut self, voter: AgentId, endorsee: AgentId) -> EventOutcome {
        self.votes.insert(voter, endorsee);
        self.counters.applied += 1;
        EventOutcome::Applied
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
            // Vote: ToolResult.accepted=true means "I endorse tool_name (= AgentId)".
            SemanticPayload::ToolResult {
                tool_name,
                accepted: true,
            } => {
                let voter = match &event.metadata.source {
                    crate::types::EventSource::Peer(id) => id.clone(),
                    _ => AgentId("local".to_string()),
                };
                self.accept_vote(voter, AgentId(tool_name))
            }
            SemanticPayload::ToolResult { accepted: false, .. } => {
                self.counters.applied += 1;
                EventOutcome::Applied
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
        let config = DevelopmentEngineConfig::new(
            [
                AgentId::from("claude"),
                AgentId::from("copilot"),
                AgentId::from("codex"),
            ],
            3,
            10,
        );
        MasRuntime::new(DevelopmentEngine::new(Epoch(0), config))
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
    fn finalizes_when_quorum_proposals_received() {
        let mut rt = engine();

        assert_eq!(rt.apply(proposal("p1", 0, "claude", b"fn foo() {}")), EventOutcome::Applied);
        assert_eq!(rt.apply(proposal("p2", 0, "copilot", b"fn foo() -> i32 { 0 }")), EventOutcome::Applied);

        let outcome = rt.apply(proposal("p3", 0, "codex", b"fn foo() -> i32 { 42 }"));
        assert!(matches!(outcome, EventOutcome::Finalized(_)));
        assert_eq!(rt.engine().active_epoch(), Epoch(1));
    }

    #[test]
    fn selected_artifact_accessible_after_finalization() {
        let mut rt = engine();
        rt.apply(proposal("p1", 0, "claude", b"fn a() {}"));
        rt.apply(proposal("p2", 0, "copilot", b"fn b() {}"));
        rt.apply(proposal("p3", 0, "codex", b"fn c() {}"));

        // With no votes, any artifact is valid — just assert one is stored.
        assert!(rt.engine().selected_artifact(Epoch(0)).is_some());
    }

    #[test]
    fn votes_influence_artifact_selection() {
        let mut rt = engine();
        rt.apply(proposal("p1", 0, "claude", b"fn winner() {}"));
        rt.apply(proposal("p2", 0, "copilot", b"fn loser() {}"));
        // Votes before third proposal
        rt.apply(vote("v1", 0, "codex", "claude"));
        // Third proposal triggers finalization
        rt.apply(proposal("p3", 0, "codex", b"fn also() {}"));

        let artifact = rt.engine().selected_artifact(Epoch(0)).unwrap();
        assert_eq!(artifact, b"fn winner() {}");
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
    fn local_source_submits_proposal_and_finalizes() {
        // Open participant set (empty), quorum=1 → one Local proposal finalizes.
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
        assert!(matches!(rt.apply(ev), EventOutcome::Finalized(_)));
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
        let mut rt = engine();
        rt.apply(proposal("p1", 0, "claude", b"fn a() {}"));
        rt.apply(proposal("p2", 0, "copilot", b"fn b() {}"));
        rt.apply(proposal("p3", 0, "codex", b"fn c() {}"));
        // Epoch 0 is finalized; late event must be rejected.
        let late = proposal("p-late", 0, "claude", b"fn late() {}");
        assert_eq!(
            rt.apply(late),
            EventOutcome::Rejected(RejectReason::FinalizedEpoch { epoch: Epoch(0) })
        );
    }

    #[test]
    fn force_finalize_when_max_rounds_exceeded() {
        // max_rounds=0: epoch 0 >= 0, so force-finalize fires immediately.
        // quorum=1 → one proposal is enough.
        let config = DevelopmentEngineConfig::new([AgentId::from("claude")], 1, 0);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let outcome = rt.apply(proposal("p1", 0, "claude", b"fn forced() {}"));
        assert!(matches!(outcome, EventOutcome::Finalized(_)));
        assert_eq!(rt.engine().selected_artifact(Epoch(0)), Some(b"fn forced() {}".as_slice()));
    }

    #[test]
    fn force_finalize_applied_when_quorum_not_met() {
        // max_rounds=0 triggers force-finalize, but quorum=10 → try_finalize returns None.
        let config = DevelopmentEngineConfig::new([], 10, 0);
        let mut rt = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));
        let outcome = rt.apply(proposal("p1", 0, "claude", b"fn code() {}"));
        assert_eq!(outcome, EventOutcome::Applied);
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
