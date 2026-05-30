use std::collections::{BTreeMap, BTreeSet};

use crate::runtime::CoordinationEngine;
use crate::types::{
    AgentId, Epoch, EventId, EventOutcome, FinalizationSummary, PatternKind, RejectReason,
    RuntimeCounters, SemanticEvent, SemanticPayload,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferenceEngineConfig {
    pub participants: BTreeSet<AgentId>,
    pub quorum: usize,
}

impl PreferenceEngineConfig {
    pub fn new<I>(participants: I, quorum: usize) -> Self
    where
        I: IntoIterator<Item = AgentId>,
    {
        Self {
            participants: participants.into_iter().collect(),
            quorum,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreferenceEngine {
    active_epoch: Epoch,
    config: PreferenceEngineConfig,
    seen_events: BTreeSet<EventId>,
    proposals: BTreeMap<AgentId, i64>,
    finalized: BTreeMap<Epoch, FinalizationSummary>,
    counters: RuntimeCounters,
}

impl PreferenceEngine {
    pub fn new(active_epoch: Epoch, config: PreferenceEngineConfig) -> Self {
        Self {
            active_epoch,
            config,
            seen_events: BTreeSet::new(),
            proposals: BTreeMap::new(),
            finalized: BTreeMap::new(),
            counters: RuntimeCounters::default(),
        }
    }

    pub fn active_epoch(&self) -> Epoch {
        self.active_epoch
    }

    pub fn finalized_summary(&self, epoch: Epoch) -> Option<&FinalizationSummary> {
        self.finalized.get(&epoch)
    }

    fn finalize_if_ready(&mut self) -> Option<FinalizationSummary> {
        if self.proposals.len() < self.config.quorum {
            return None;
        }

        let mut values: Vec<i64> = self.proposals.values().copied().collect();
        values.sort_unstable();
        let median = values[values.len() / 2];
        let summary = FinalizationSummary {
            epoch: self.active_epoch,
            participants: self.proposals.len(),
            selected_value: median,
        };
        self.finalized.insert(self.active_epoch, summary.clone());
        self.proposals.clear();
        self.active_epoch = Epoch(self.active_epoch.0 + 1);
        self.counters.finalized += 1;
        Some(summary)
    }

    fn accept_value(&mut self, participant: AgentId, value: i64) -> EventOutcome {
        if !self.config.participants.is_empty() && !self.config.participants.contains(&participant) {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::UnknownParticipant);
        }

        self.proposals.insert(participant, value);
        self.counters.applied += 1;

        match self.finalize_if_ready() {
            Some(summary) => EventOutcome::Finalized(summary),
            None => EventOutcome::Applied,
        }
    }
}

impl CoordinationEngine for PreferenceEngine {
    fn pattern(&self) -> PatternKind {
        PatternKind::Preference
    }

    fn apply(&mut self, event: SemanticEvent) -> EventOutcome {
        if event.pattern != PatternKind::Preference {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::IncompatiblePattern);
        }

        if self.finalized.contains_key(&event.metadata.epoch) {
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
            SemanticPayload::Proposal(proposal) => {
                self.accept_value(proposal.participant, proposal.value)
            }
            SemanticPayload::Vote(vote) => self.accept_value(vote.participant, vote.value),
            SemanticPayload::Sensitivity(_) => {
                self.counters.applied += 1;
                EventOutcome::Applied
            }
            SemanticPayload::ToolResult { .. }
            | SemanticPayload::TaskResult { .. }
            | SemanticPayload::ExternalBytes(_) => {
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
    use crate::types::{
        EventMetadata, EventSource, PatternKind, Proposal, RejectReason, SemanticEvent,
        SemanticPayload, Sensitivity, Vote,
    };

    fn proposal_event(id: &str, epoch: u64, participant: &str, value: i64) -> SemanticEvent {
        SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from(id),
                correlation_id: None,
                epoch: Epoch(epoch),
                source: EventSource::Peer(AgentId::from(participant)),
            },
            payload: SemanticPayload::Proposal(Proposal {
                participant: AgentId::from(participant),
                value,
            }),
        }
    }

    fn vote_event(id: &str, epoch: u64, participant: &str, value: i64) -> SemanticEvent {
        SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from(id),
                correlation_id: None,
                epoch: Epoch(epoch),
                source: EventSource::Peer(AgentId::from(participant)),
            },
            payload: SemanticPayload::Vote(Vote {
                participant: AgentId::from(participant),
                value,
            }),
        }
    }

    fn runtime() -> MasRuntime<PreferenceEngine> {
        let config = PreferenceEngineConfig::new(
            [AgentId::from("alice"), AgentId::from("bob"), AgentId::from("carol")],
            3,
        );
        MasRuntime::new(PreferenceEngine::new(Epoch(0), config))
    }

    #[test]
    fn finalizes_when_quorum_is_met() {
        let mut runtime = runtime();

        assert_eq!(runtime.apply(proposal_event("e1", 0, "alice", 10)), EventOutcome::Applied);
        assert_eq!(runtime.apply(proposal_event("e2", 0, "bob", 30)), EventOutcome::Applied);

        let outcome = runtime.apply(proposal_event("e3", 0, "carol", 20));
        assert_eq!(
            outcome,
            EventOutcome::Finalized(FinalizationSummary {
                epoch: Epoch(0),
                participants: 3,
                selected_value: 20,
            })
        );
        assert_eq!(runtime.engine().active_epoch(), Epoch(1));
    }

    #[test]
    fn rejects_duplicate_event_ids() {
        let mut runtime = runtime();
        let event = proposal_event("e1", 0, "alice", 10);

        assert_eq!(runtime.apply(event.clone()), EventOutcome::Applied);
        assert_eq!(
            runtime.apply(event),
            EventOutcome::Rejected(RejectReason::DuplicateEvent)
        );
    }

    #[test]
    fn rejects_late_vote_after_epoch_finalization() {
        let mut runtime = runtime();
        runtime.apply(proposal_event("e1", 0, "alice", 10));
        runtime.apply(proposal_event("e2", 0, "bob", 30));
        runtime.apply(proposal_event("e3", 0, "carol", 20));

        let late = proposal_event("e4", 0, "alice", 25);
        assert_eq!(
            runtime.apply(late),
            EventOutcome::Rejected(RejectReason::FinalizedEpoch { epoch: Epoch(0) })
        );
    }

    #[test]
    fn defers_future_epoch_event_until_epoch_is_active() {
        let mut runtime = runtime();

        let future = proposal_event("e-future", 1, "alice", 15);
        assert_eq!(
            runtime.apply(future.clone()),
            EventOutcome::Deferred {
                expected: Epoch(0),
                received: Epoch(1),
            }
        );

        runtime.apply(proposal_event("e1", 0, "alice", 10));
        runtime.apply(proposal_event("e2", 0, "bob", 30));
        runtime.apply(proposal_event("e3", 0, "carol", 20));

        assert_eq!(runtime.engine().active_epoch(), Epoch(1));
        assert_eq!(runtime.apply(future), EventOutcome::Applied);
    }

    #[test]
    fn rejects_stale_epoch_before_finalization_lookup() {
        let mut runtime = runtime();
        runtime.apply(proposal_event("e1", 0, "alice", 10));
        runtime.apply(proposal_event("e2", 0, "bob", 30));
        runtime.apply(proposal_event("e3", 0, "carol", 20));

        let stale = vote_event("e-stale", 0, "bob", 30);
        assert_eq!(
            runtime.apply(stale),
            EventOutcome::Rejected(RejectReason::FinalizedEpoch { epoch: Epoch(0) })
        );
    }

    #[test]
    fn rejects_unknown_participant_in_active_epoch() {
        let mut runtime = runtime();

        assert_eq!(
            runtime.apply(proposal_event("e-unknown", 0, "mallory", 99)),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );
    }

    #[test]
    fn accepts_vote_payloads_and_finalizes_on_median() {
        let mut runtime = runtime();

        assert_eq!(runtime.apply(vote_event("v1", 0, "alice", 11)), EventOutcome::Applied);
        assert_eq!(runtime.apply(vote_event("v2", 0, "bob", 27)), EventOutcome::Applied);
        assert_eq!(
            runtime.apply(vote_event("v3", 0, "carol", 19)),
            EventOutcome::Finalized(FinalizationSummary {
                epoch: Epoch(0),
                participants: 3,
                selected_value: 19,
            })
        );
    }

    #[test]
    fn runtime_counters_track_theory_relevant_outcomes() {
        let mut runtime = runtime();

        let future = proposal_event("future", 1, "alice", 1);
        assert_eq!(
            runtime.apply(future.clone()),
            EventOutcome::Deferred {
                expected: Epoch(0),
                received: Epoch(1),
            }
        );
        assert_eq!(runtime.apply(proposal_event("ok-1", 0, "alice", 10)), EventOutcome::Applied);
        assert_eq!(runtime.apply(proposal_event("ok-2", 0, "bob", 20)), EventOutcome::Applied);
        assert_eq!(
            runtime.apply(proposal_event("dup", 0, "bob", 20)),
            EventOutcome::Applied
        );
        assert_eq!(
            runtime.apply(proposal_event("dup", 0, "bob", 20)),
            EventOutcome::Rejected(RejectReason::DuplicateEvent)
        );
        assert_eq!(
            runtime.apply(proposal_event("ok-3", 0, "carol", 30)),
            EventOutcome::Finalized(FinalizationSummary {
                epoch: Epoch(0),
                participants: 3,
                selected_value: 20,
            })
        );
        assert_eq!(runtime.apply(future), EventOutcome::Applied);

        let counters = runtime.engine().counters();
        assert_eq!(counters.deferred, 1);
        assert_eq!(counters.duplicates, 1);
        assert_eq!(counters.finalized, 1);
        assert_eq!(counters.rejected, 1);
        assert_eq!(counters.applied, 5);
    }

    #[test]
    fn pattern_returns_preference() {
        let config = PreferenceEngineConfig::new([], 1);
        let engine = PreferenceEngine::new(Epoch(0), config);
        assert_eq!(engine.pattern(), PatternKind::Preference);
    }

    #[test]
    fn finalized_summary_returns_none_before_finalization() {
        let config = PreferenceEngineConfig::new([AgentId::from("alice")], 1);
        let engine = PreferenceEngine::new(Epoch(0), config);
        assert!(engine.finalized_summary(Epoch(0)).is_none());
    }

    #[test]
    fn finalized_summary_returns_correct_summary_after_finalization() {
        let mut runtime = runtime();
        runtime.apply(proposal_event("e1", 0, "alice", 10));
        runtime.apply(proposal_event("e2", 0, "bob", 30));
        runtime.apply(proposal_event("e3", 0, "carol", 20));

        let summary = runtime.engine().finalized_summary(Epoch(0)).unwrap();
        assert_eq!(summary.epoch, Epoch(0));
        assert_eq!(summary.selected_value, 20); // median of [10, 20, 30]
    }

    #[test]
    fn rejects_incompatible_pattern() {
        let mut runtime = runtime();
        let ev = SemanticEvent {
            pattern: PatternKind::Development,
            metadata: EventMetadata {
                event_id: EventId::from("e-bad"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Local,
            },
            payload: SemanticPayload::ExternalBytes(b"code".to_vec()),
        };
        assert_eq!(runtime.apply(ev), EventOutcome::Rejected(RejectReason::IncompatiblePattern));
    }

    #[test]
    fn rejects_stale_epoch_when_not_finalized() {
        // Engine starts at epoch 2; events for epoch 0 (not in finalized map) are stale.
        let config = PreferenceEngineConfig::new(
            [AgentId::from("alice"), AgentId::from("bob"), AgentId::from("carol")],
            3,
        );
        let mut runtime = MasRuntime::new(PreferenceEngine::new(Epoch(2), config));
        assert_eq!(
            runtime.apply(proposal_event("e1", 0, "alice", 10)),
            EventOutcome::Rejected(RejectReason::StaleEpoch { current: Epoch(2) })
        );
    }

    #[test]
    fn sensitivity_and_external_payload_types_applied() {
        let mut runtime = runtime();

        let ev_sens = SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from("e-sens"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from("alice")),
            },
            payload: SemanticPayload::Sensitivity(Sensitivity {
                participant: AgentId::from("alice"),
                delta: 5,
            }),
        };
        assert_eq!(runtime.apply(ev_sens), EventOutcome::Applied);

        let ev_bytes = SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from("e-bytes"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from("bob")),
            },
            payload: SemanticPayload::ExternalBytes(b"raw".to_vec()),
        };
        assert_eq!(runtime.apply(ev_bytes), EventOutcome::Applied);

        let ev_task = SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from("e-task"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from("carol")),
            },
            payload: SemanticPayload::TaskResult {
                task_id: "t-1".to_string(),
                accepted: true,
            },
        };
        assert_eq!(runtime.apply(ev_task), EventOutcome::Applied);

        let ev_tool = SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from("e-tool"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Local,
            },
            payload: SemanticPayload::ToolResult {
                tool_name: "some-tool".to_string(),
                accepted: false,
            },
        };
        assert_eq!(runtime.apply(ev_tool), EventOutcome::Applied);
    }
}