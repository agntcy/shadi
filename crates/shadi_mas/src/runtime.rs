use crate::types::{EventId, EventOutcome, PatternKind, RuntimeCounters, SemanticEvent};

pub trait CoordinationEngine: Send + Sync {
    fn pattern(&self) -> PatternKind;
    fn apply(&mut self, event: SemanticEvent) -> EventOutcome;
    fn counters(&self) -> RuntimeCounters;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedTransition {
    pub event_id: EventId,
    pub outcome: EventOutcome,
}

#[derive(Debug)]
pub struct MasRuntime<E> {
    engine: E,
    history: Vec<AppliedTransition>,
}

impl<E> MasRuntime<E>
where
    E: CoordinationEngine,
{
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            history: Vec::new(),
        }
    }

    pub fn apply(&mut self, event: SemanticEvent) -> EventOutcome {
        let event_id = event.metadata.event_id.clone();
        let outcome = self.engine.apply(event);
        self.history.push(AppliedTransition {
            event_id,
            outcome: outcome.clone(),
        });
        outcome
    }

    pub fn engine(&self) -> &E {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    pub fn history(&self) -> &[AppliedTransition] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::preference::{PreferenceEngine, PreferenceEngineConfig};
    use crate::types::{
        AgentId, Epoch, EventId, EventMetadata, EventOutcome, EventSource, Proposal, SemanticEvent,
        SemanticPayload,
    };

    fn make_runtime() -> MasRuntime<PreferenceEngine> {
        let config = PreferenceEngineConfig::new(
            [AgentId::from("a"), AgentId::from("b")],
            2,
        );
        MasRuntime::new(PreferenceEngine::new(Epoch(0), config))
    }

    fn proposal(id: &str, participant: &str, value: i64) -> SemanticEvent {
        SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from(id),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from(participant)),
            },
            payload: SemanticPayload::Proposal(Proposal {
                participant: AgentId::from(participant),
                value,
            }),
        }
    }

    #[test]
    fn engine_mut_returns_mutable_reference() {
        let mut rt = make_runtime();
        // Verify engine_mut returns a usable mutable reference.
        let engine = rt.engine_mut();
        assert_eq!(engine.active_epoch(), Epoch(0));
    }

    #[test]
    fn history_accumulates_all_transitions() {
        let mut rt = make_runtime();
        rt.apply(proposal("e1", "a", 10));
        rt.apply(proposal("e2", "b", 20));

        let h = rt.history();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].event_id, EventId::from("e1"));
        assert_eq!(h[0].outcome, EventOutcome::Applied);
        assert_eq!(h[1].event_id, EventId::from("e2"));
        assert!(matches!(h[1].outcome, EventOutcome::Finalized(_)));
    }

    #[test]
    fn history_is_empty_on_new_runtime() {
        let rt = make_runtime();
        assert!(rt.history().is_empty());
    }
}
