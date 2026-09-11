// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Resource CONVERGE engine. Agents announce last extraction; the engine
//! applies the paper dual step and plant update.

use std::collections::{BTreeMap, BTreeSet};

use crate::engines::converge::{scalar_announce, ConvergeSurface};
use crate::runtime::CoordinationEngine;
use crate::types::{
    AgentId, Epoch, EventId, EventOutcome, EventSource, FinalizationSummary, PatternKind,
    RejectReason, RuntimeCounters, ScalarProposal, SemanticEvent, SemanticPayload,
};

pub const R0: f64 = 24.0;
pub const CAPACITY: f64 = 30.0;
pub const REGEN: f64 = 0.2;
pub const QUOTA_FRAC: f64 = 0.25;
pub const ALPHA: f64 = 0.35;
pub const ETA: f64 = 0.4;
pub const R_MIN: f64 = 1.0;
pub const PAPER_ROUNDS: u64 = 12;

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceEngineConfig {
    pub participants: Vec<AgentId>,
    pub desired: Vec<f64>,
    pub alpha: f64,
    pub eta: f64,
    pub paper_horizon: u64,
}

impl ResourceEngineConfig {
    pub fn scaled(participants: Vec<AgentId>) -> Result<Self, String> {
        let n = participants.len();
        if n < 2 {
            return Err("resource needs at least two agents".to_string());
        }
        let desired = (0..n).map(|i| if i % 3 == 1 { 2.5 } else { 2.0 }).collect();
        Ok(Self {
            participants,
            desired,
            alpha: ALPHA,
            eta: ETA,
            paper_horizon: PAPER_ROUNDS,
        })
    }

    pub fn uncontrolled(participants: Vec<AgentId>) -> Result<Self, String> {
        let mut cfg = Self::scaled(participants)?;
        cfg.alpha = 0.0;
        Ok(cfg)
    }

    pub fn index_of(&self, id: &AgentId) -> Option<usize> {
        self.participants.iter().position(|p| p == id)
    }
}

#[derive(Clone, Debug)]
pub struct ResourceEngine {
    active_epoch: Epoch,
    config: ResourceEngineConfig,
    r: f64,
    lam: f64,
    e: Vec<f64>,
    breaches: u32,
    announced: BTreeMap<usize, f64>,
    seen_events: BTreeSet<EventId>,
    counters: RuntimeCounters,
}

impl ResourceEngine {
    pub fn new(active_epoch: Epoch, config: ResourceEngineConfig) -> Self {
        let e = config.desired.clone();
        Self {
            active_epoch,
            r: R0,
            lam: 0.0,
            e,
            breaches: 0,
            announced: BTreeMap::new(),
            seen_events: BTreeSet::new(),
            counters: RuntimeCounters::default(),
            config,
        }
    }

    pub fn active_epoch(&self) -> Epoch {
        self.active_epoch
    }

    pub fn config(&self) -> &ResourceEngineConfig {
        &self.config
    }

    pub fn stock(&self) -> f64 {
        self.r
    }

    pub fn lambda(&self) -> f64 {
        self.lam
    }

    pub fn extractions(&self) -> &[f64] {
        &self.e
    }

    pub fn breaches(&self) -> u32 {
        self.breaches
    }

    fn cap(&self) -> f64 {
        QUOTA_FRAC * self.r
    }

    pub fn formula_value(&self, index: usize) -> f64 {
        let raw = self.e[index]
            + self.config.eta * ((self.config.desired[index] - self.e[index]) - self.lam);
        raw.clamp(0.0, self.r.max(0.0))
    }

    fn apply_extractions(&mut self, extracted: Vec<f64>) {
        self.e = extracted;
        let total: f64 = self.e.iter().sum();
        self.lam = (self.lam + self.config.alpha * (total - self.cap())).max(0.0);
        let grown = self.r + REGEN * self.r * (1.0 - self.r / CAPACITY);
        self.r = (grown - total).max(0.0);
        if self.r < R_MIN {
            self.breaches += 1;
        }
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
        let next: Vec<f64> = (0..n).map(|i| self.formula_value(i)).collect();
        self.apply_extractions(next);
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

impl CoordinationEngine for ResourceEngine {
    fn pattern(&self) -> PatternKind {
        PatternKind::Resource
    }

    fn apply(&mut self, event: SemanticEvent) -> EventOutcome {
        if event.pattern != PatternKind::Resource {
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

impl ConvergeSurface for ResourceEngine {
    fn current_value(&self, id: &AgentId) -> Option<f64> {
        self.config.index_of(id).map(|i| self.e[i])
    }

    fn metric(&self) -> f64 {
        self.r
    }

    fn lower_is_better(&self) -> bool {
        false
    }

    fn local_view(&self, id: &AgentId) -> String {
        let Some(i) = self.config.index_of(id) else {
            return String::new();
        };
        format!(
            "agent={}\nlast_e_i={:.6}\nR={:.6}\nlambda={:.6}\nC_R={:.6}",
            id.0,
            self.e[i],
            self.r,
            self.lam,
            self.cap()
        )
    }

    fn announce_event(
        &self,
        id: &AgentId,
        epoch: u64,
        value: f64,
        event_id: &str,
    ) -> SemanticEvent {
        scalar_announce(PatternKind::Resource, id, epoch, value, event_id)
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

    fn announce_all(rt: &mut MasRuntime<ResourceEngine>, epoch: u64) -> EventOutcome {
        let n = rt.engine().config().participants.len();
        let mut last = EventOutcome::Applied;
        for i in 0..n {
            let id = rt.engine().config().participants[i].clone();
            let value = rt.engine().extractions()[i];
            last =
                rt.apply(
                    rt.engine()
                        .announce_event(&id, epoch, value, &format!("r{epoch}-{i}")),
                );
        }
        last
    }

    #[test]
    fn coordinated_retains_more_stock_than_greedy() {
        let coord_cfg = ResourceEngineConfig::scaled(ids(3)).expect("coord");
        let greedy_cfg = ResourceEngineConfig::uncontrolled(ids(3)).expect("greedy");
        let mut coord = MasRuntime::new(ResourceEngine::new(Epoch(0), coord_cfg));
        let mut greedy = MasRuntime::new(ResourceEngine::new(Epoch(0), greedy_cfg));
        for epoch in 0..12 {
            assert!(matches!(
                announce_all(&mut coord, epoch),
                EventOutcome::Finalized(_)
            ));
            assert!(matches!(
                announce_all(&mut greedy, epoch),
                EventOutcome::Finalized(_)
            ));
        }
        assert!(coord.engine().stock() > greedy.engine().stock());
    }

    #[test]
    fn stale_epoch_rejected() {
        let cfg = ResourceEngineConfig::scaled(ids(2)).expect("cfg");
        let mut rt = MasRuntime::new(ResourceEngine::new(Epoch(0), cfg));
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
}
