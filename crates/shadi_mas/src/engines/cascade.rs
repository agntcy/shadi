// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Supply-chain CONVERGE engine. Agents announce last order; the engine
//! applies the paper order-up-to + smoothing update.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::engines::converge::{scalar_announce, ConvergeSurface};
use crate::runtime::CoordinationEngine;
use crate::types::{
    AgentId, Epoch, EventId, EventOutcome, EventSource, FinalizationSummary, PatternKind,
    RejectReason, RuntimeCounters, ScalarProposal, SemanticEvent, SemanticPayload,
};

pub const LEAD: usize = 2;
pub const TARGET_I: f64 = 8.0;
pub const I0: f64 = 8.0;
pub const HOLD_COST: f64 = 1.0;
pub const BACKLOG_COST: f64 = 2.0;
pub const SMOOTH: f64 = 0.5;
pub const RHO: f64 = 1.0;
pub const PAPER_DEMAND: [f64; 8] = [4.0, 4.0, 4.0, 8.0, 8.0, 8.0, 4.0, 4.0];

#[derive(Clone, Debug, PartialEq)]
pub struct CascadeEngineConfig {
    pub participants: Vec<AgentId>,
    pub lead: usize,
    pub target_i: f64,
    pub demand: Vec<f64>,
    pub hold_cost: f64,
    pub backlog_cost: f64,
    pub smooth: f64,
    pub rho: f64,
}

impl CascadeEngineConfig {
    pub fn scaled(participants: Vec<AgentId>) -> Result<Self, String> {
        if participants.len() < 2 {
            return Err("cascade needs at least two stages".to_string());
        }
        Ok(Self {
            participants,
            lead: LEAD,
            target_i: TARGET_I,
            demand: PAPER_DEMAND.to_vec(),
            hold_cost: HOLD_COST,
            backlog_cost: BACKLOG_COST,
            smooth: SMOOTH,
            rho: RHO,
        })
    }

    pub fn index_of(&self, id: &AgentId) -> Option<usize> {
        self.participants.iter().position(|p| p == id)
    }

    pub fn paper_horizon(&self) -> u64 {
        self.demand.len() as u64
    }
}

#[derive(Clone, Debug)]
pub struct CascadeEngine {
    active_epoch: Epoch,
    config: CascadeEngineConfig,
    inventory: Vec<f64>,
    last_q: Vec<f64>,
    pipeline: Vec<VecDeque<f64>>,
    last_demand: Vec<f64>,
    cost: f64,
    t: usize,
    announced: BTreeMap<usize, f64>,
    seen_events: BTreeSet<EventId>,
    counters: RuntimeCounters,
}

impl CascadeEngine {
    pub fn new(active_epoch: Epoch, config: CascadeEngineConfig) -> Self {
        let n = config.participants.len();
        let lead = config.lead.max(1);
        Self {
            active_epoch,
            inventory: vec![I0; n],
            last_q: vec![4.0; n],
            pipeline: (0..n).map(|_| VecDeque::from(vec![4.0; lead])).collect(),
            last_demand: vec![4.0; n],
            cost: 0.0,
            t: 0,
            announced: BTreeMap::new(),
            seen_events: BTreeSet::new(),
            counters: RuntimeCounters::default(),
            config,
        }
    }

    pub fn active_epoch(&self) -> Epoch {
        self.active_epoch
    }

    pub fn config(&self) -> &CascadeEngineConfig {
        &self.config
    }

    pub fn cost(&self) -> f64 {
        self.cost
    }

    pub fn last_q(&self) -> &[f64] {
        &self.last_q
    }

    pub fn inventory(&self) -> &[f64] {
        &self.inventory
    }

    fn observed_demand(&self, index: usize) -> f64 {
        let n = self.config.participants.len();
        if index + 1 == n {
            self.config.demand[self.t.min(self.config.demand.len().saturating_sub(1))]
        } else {
            self.last_q[index + 1]
        }
    }

    fn pipeline_sum(&self, index: usize) -> f64 {
        self.pipeline[index].iter().sum()
    }

    fn qbar(&self, index: usize) -> f64 {
        let n = self.config.participants.len();
        if index + 1 < n {
            self.last_q[index + 1]
        } else {
            self.last_demand[index]
        }
    }

    pub fn formula_value(&self, index: usize) -> f64 {
        let dhat = self.observed_demand(index);
        let q_hat = (self.config.target_i + self.config.lead as f64 * dhat
            - self.inventory[index]
            - self.pipeline_sum(index))
        .max(0.0);
        (q_hat + self.config.rho * self.qbar(index)) / (1.0 + self.config.rho)
    }

    fn apply_orders(&mut self, orders: Vec<f64>) {
        let n = self.config.participants.len();
        let customer = self.config.demand[self.t.min(self.config.demand.len().saturating_sub(1))];
        for i in 0..n {
            let arriving = self.pipeline[i].pop_front().unwrap_or(0.0);
            let demand = if i + 1 == n { customer } else { orders[i + 1] };
            self.inventory[i] += arriving - demand;
            let hold = self.config.hold_cost * self.inventory[i].max(0.0);
            let backlog = self.config.backlog_cost * (-self.inventory[i]).max(0.0);
            let smooth = self.config.smooth * (orders[i] - self.last_q[i]).powi(2);
            self.cost += hold + backlog + smooth;
            self.last_demand[i] = demand;
            self.pipeline[i].push_back(orders[i]);
            self.last_q[i] = orders[i];
        }
        self.t += 1;
    }

    fn participant_from_event(
        &self,
        event: &SemanticEvent,
        payload: &ScalarProposal,
    ) -> Option<usize> {
        let from_payload = self.config.index_of(&payload.participant)?;
        match &event.metadata.source {
            EventSource::Peer(id) => self.config.index_of(id).filter(|&i| i == from_payload),
            EventSource::Local => Some(from_payload),
            EventSource::Tool(name) => self
                .config
                .index_of(&AgentId::from(name.as_str()))
                .filter(|&i| i == from_payload),
            EventSource::Task(_) | EventSource::Recovery => None,
        }
    }

    fn try_finalize(&mut self) -> Option<FinalizationSummary> {
        let n = self.config.participants.len();
        if self.announced.len() < n {
            return None;
        }
        let orders: Vec<f64> = (0..n).map(|i| self.formula_value(i)).collect();
        self.apply_orders(orders);
        self.announced.clear();
        let summary = FinalizationSummary {
            epoch: self.active_epoch,
            participants: n,
            selected_value: n as i64,
        };
        self.active_epoch = Epoch(self.active_epoch.0 + 1);
        self.counters.finalized += 1;
        Some(summary)
    }
}

impl CoordinationEngine for CascadeEngine {
    fn pattern(&self) -> PatternKind {
        PatternKind::Cascade
    }

    fn apply(&mut self, event: SemanticEvent) -> EventOutcome {
        if event.pattern != PatternKind::Cascade {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::IncompatiblePattern);
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
        if !self.seen_events.insert(event.metadata.event_id.clone()) {
            self.counters.rejected += 1;
            self.counters.duplicates += 1;
            return EventOutcome::Rejected(RejectReason::DuplicateEvent);
        }
        let SemanticPayload::ScalarProposal(ref payload) = event.payload else {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::IncompatiblePayload);
        };
        let Some(idx) = self.participant_from_event(&event, payload) else {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::UnknownParticipant);
        };
        if !payload.value.is_finite() || self.announced.contains_key(&idx) {
            self.counters.rejected += 1;
            if self.announced.contains_key(&idx) {
                self.counters.duplicates += 1;
                return EventOutcome::Rejected(RejectReason::DuplicateEvent);
            }
            return EventOutcome::Rejected(RejectReason::IncompatiblePayload);
        }
        self.announced.insert(idx, payload.value);
        self.counters.applied += 1;
        match self.try_finalize() {
            Some(summary) => EventOutcome::Finalized(summary),
            None => EventOutcome::Applied,
        }
    }

    fn counters(&self) -> RuntimeCounters {
        self.counters.clone()
    }
}

impl ConvergeSurface for CascadeEngine {
    fn current_value(&self, id: &AgentId) -> Option<f64> {
        self.config.index_of(id).map(|i| self.last_q[i])
    }

    fn metric(&self) -> f64 {
        self.cost
    }

    fn lower_is_better(&self) -> bool {
        true
    }

    fn local_view(&self, id: &AgentId) -> String {
        let Some(i) = self.config.index_of(id) else {
            return String::new();
        };
        format!(
            "agent={}\nI_i={:.6}\npipeline_sum={:.6}\nlast_order={:.6}\nobserved_demand={:.6}",
            id.0,
            self.inventory[i],
            self.pipeline_sum(i),
            self.last_q[i],
            self.observed_demand(i)
        )
    }

    fn announce_event(
        &self,
        id: &AgentId,
        epoch: u64,
        value: f64,
        event_id: &str,
    ) -> SemanticEvent {
        scalar_announce(PatternKind::Cascade, id, epoch, value, event_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::MasRuntime;

    fn ids(n: usize) -> Vec<AgentId> {
        (0..n)
            .map(|i| AgentId::from(format!("goose-{i}").as_str()))
            .collect()
    }

    fn announce_all(rt: &mut MasRuntime<CascadeEngine>, epoch: u64) -> EventOutcome {
        let n = rt.engine().config().participants.len();
        let mut last = EventOutcome::Applied;
        for i in 0..n {
            let id = rt.engine().config().participants[i].clone();
            let value = rt.engine().last_q()[i];
            last =
                rt.apply(
                    rt.engine()
                        .announce_event(&id, epoch, value, &format!("c{epoch}-{i}")),
                );
        }
        last
    }

    #[test]
    fn paper_instance_accumulates_cost() {
        let cfg = CascadeEngineConfig::scaled(ids(4)).expect("cfg");
        let mut rt = MasRuntime::new(CascadeEngine::new(Epoch(0), cfg));
        for epoch in 0..8 {
            assert!(matches!(
                announce_all(&mut rt, epoch),
                EventOutcome::Finalized(_)
            ));
        }
        assert!(rt.engine().cost() > 0.0);
        assert_eq!(rt.engine().active_epoch(), Epoch(8));
    }

    #[test]
    fn stale_epoch_rejected() {
        let cfg = CascadeEngineConfig::scaled(ids(2)).expect("cfg");
        let mut rt = MasRuntime::new(CascadeEngine::new(Epoch(0), cfg));
        assert!(matches!(
            announce_all(&mut rt, 0),
            EventOutcome::Finalized(_)
        ));
        let id = rt.engine().config().participants[0].clone();
        let ev = rt.engine().announce_event(&id, 0, 1.0, "late");
        assert_eq!(
            rt.apply(ev),
            EventOutcome::Rejected(RejectReason::StaleEpoch { current: Epoch(1) })
        );
    }

    #[test]
    fn wrong_pattern_is_rejected() {
        let cfg = CascadeEngineConfig::scaled(ids(2)).expect("cfg");
        let mut rt = MasRuntime::new(CascadeEngine::new(Epoch(0), cfg));
        let id = rt.engine().config().participants[0].clone();
        let mut ev = rt.engine().announce_event(&id, 0, 1.0, "wrong");
        ev.pattern = PatternKind::Preference;
        assert_eq!(
            rt.apply(ev),
            EventOutcome::Rejected(RejectReason::IncompatiblePattern)
        );
    }

    #[test]
    fn scaled_rejects_a_single_stage() {
        assert!(CascadeEngineConfig::scaled(ids(1)).is_err());
    }

    #[test]
    fn reject_paths_and_source_aliases() {
        use crate::types::{EventMetadata, EventSource, SemanticPayload};

        let cfg = CascadeEngineConfig::scaled(ids(2)).expect("cfg");
        let mut rt = MasRuntime::new(CascadeEngine::new(Epoch(0), cfg));
        let id0 = rt.engine().config().participants[0].clone();
        let id1 = rt.engine().config().participants[1].clone();

        assert_eq!(
            rt.apply(rt.engine().announce_event(&id0, 3, 1.0, "future")),
            EventOutcome::Deferred {
                expected: Epoch(0),
                received: Epoch(3)
            }
        );

        let first = rt.engine().announce_event(&id0, 0, 1.0, "dup");
        assert_eq!(rt.apply(first.clone()), EventOutcome::Applied);
        assert_eq!(
            rt.apply(first),
            EventOutcome::Rejected(RejectReason::DuplicateEvent)
        );
        assert_eq!(
            rt.apply(rt.engine().announce_event(&id0, 0, 2.0, "again")),
            EventOutcome::Rejected(RejectReason::DuplicateEvent)
        );

        let mut ghost = rt.engine().announce_event(&id0, 0, 1.0, "ghost");
        ghost.payload = SemanticPayload::ScalarProposal(ScalarProposal {
            participant: AgentId::from("ghost"),
            value: 1.0,
        });
        ghost.metadata.source = EventSource::Peer(AgentId::from("ghost"));
        assert_eq!(
            rt.apply(ghost),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );

        let bytes = SemanticEvent {
            pattern: PatternKind::Cascade,
            metadata: EventMetadata {
                event_id: EventId::from("bytes"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(id1.clone()),
            },
            payload: SemanticPayload::ExternalBytes(b"nope".to_vec()),
        };
        assert_eq!(
            rt.apply(bytes),
            EventOutcome::Rejected(RejectReason::IncompatiblePayload)
        );

        let nan = rt.engine().announce_event(&id1, 0, f64::NAN, "nan");
        assert_eq!(
            rt.apply(nan),
            EventOutcome::Rejected(RejectReason::IncompatiblePayload)
        );

        let mut local = rt.engine().announce_event(&id1, 0, 4.0, "local");
        local.metadata.source = EventSource::Local;
        assert_eq!(
            rt.apply(local),
            EventOutcome::Finalized(FinalizationSummary {
                epoch: Epoch(0),
                participants: 2,
                selected_value: 2,
            })
        );

        let mut tool = rt.engine().announce_event(&id0, 1, 4.0, "tool");
        tool.metadata.source = EventSource::Tool(id0.0.clone());
        assert_eq!(rt.apply(tool), EventOutcome::Applied);
        let mut task = rt.engine().announce_event(&id1, 1, 4.0, "task");
        task.metadata.source = EventSource::Task("t".into());
        assert_eq!(
            rt.apply(task),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );
        let mut recovery = rt.engine().announce_event(&id1, 1, 4.0, "rec");
        recovery.metadata.source = EventSource::Recovery;
        assert_eq!(
            rt.apply(recovery),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );
    }

    #[test]
    fn surface_and_formula_are_defined() {
        let cfg = CascadeEngineConfig::scaled(ids(3)).expect("cfg");
        let engine = CascadeEngine::new(Epoch(0), cfg);
        let id = engine.config().participants[0].clone();
        let unknown = AgentId::from("ghost");
        assert_eq!(engine.pattern(), PatternKind::Cascade);
        assert!(engine.lower_is_better());
        assert_eq!(engine.current_value(&id), Some(4.0));
        assert_eq!(engine.current_value(&unknown), None);
        assert!(engine.local_view(&id).contains("last_order="));
        assert!(engine.local_view(&unknown).is_empty());
        assert_eq!(engine.inventory().len(), 3);
        assert_eq!(engine.last_q().len(), 3);
        assert!(engine.formula_value(0) >= 0.0);
        assert!(engine.formula_value(2) >= 0.0);
        assert_eq!(engine.config().paper_horizon(), 8);
        assert_eq!(engine.counters().applied, 0);
    }
}
