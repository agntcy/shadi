// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Synchronous Jacobi preference engine (theorem preference-linear).
//!
//! Each epoch, every participant announces its current `z_i` as a
//! [`ScalarProposal`](crate::types::ScalarProposal). When the full round set
//! is present, the engine applies
//!
//! `z_i ← (c_i + 2β Σ_{j∈N_i} z_j) / (1 + 2β d_i)`
//!
//! simultaneously (Jacobi, not Gauss–Seidel) and finalizes the epoch.
//! Untagged / wrong-epoch / replayed / unknown announcements are rejected.
//! This is not a median vote.

use std::collections::{BTreeMap, BTreeSet};

use crate::engines::converge::{scalar_announce, ConvergeSurface};
use crate::runtime::CoordinationEngine;
use crate::types::{
    AgentId, Epoch, EventId, EventOutcome, EventSource, FinalizationSummary, PatternKind,
    RejectReason, RuntimeCounters, ScalarProposal, SemanticEvent, SemanticPayload,
};

const SINGULAR: f64 = 1e-15;

/// Line (or general graph) quadratic-preference instance.
#[derive(Clone, Debug, PartialEq)]
pub struct PreferenceEngineConfig {
    pub participants: Vec<AgentId>,
    pub neighbors: Vec<Vec<usize>>,
    pub preferences: Vec<f64>,
    pub beta: f64,
    pub z_star: Vec<f64>,
}

impl PreferenceEngineConfig {
    /// Build a config. `z*` is `(I + 2β L)^{-1} c`.
    pub fn new(
        participants: Vec<AgentId>,
        neighbors: Vec<Vec<usize>>,
        preferences: Vec<f64>,
        beta: f64,
    ) -> Result<Self, String> {
        let n = participants.len();
        if n == 0 {
            return Err("preference instance needs at least one participant".to_string());
        }
        if neighbors.len() != n || preferences.len() != n {
            return Err(
                "participants, neighbors, and preferences must have the same length".to_string(),
            );
        }
        if beta <= 0.0 || !beta.is_finite() {
            return Err("beta must be a positive finite number".to_string());
        }
        for (i, nb) in neighbors.iter().enumerate() {
            for &j in nb {
                if j >= n || j == i {
                    return Err(format!("invalid neighbor {j} of node {i}"));
                }
            }
        }
        let z_star = solve_z_star(&neighbors, &preferences, beta)?;
        Ok(Self {
            participants,
            neighbors,
            preferences,
            beta,
            z_star,
        })
    }

    /// Path graph with uniformly spaced preferences, paper β = 0.75.
    pub fn line(n: usize, c_span: f64, beta: f64) -> Result<Self, String> {
        let participants = (0..n)
            .map(|i| AgentId::from(i.to_string().as_str()))
            .collect();
        Self::line_with_participants(participants, c_span, beta)
    }

    /// Path graph with caller-supplied participant ids.
    pub fn line_with_participants(
        participants: Vec<AgentId>,
        c_span: f64,
        beta: f64,
    ) -> Result<Self, String> {
        let n = participants.len();
        if n < 2 {
            return Err("line needs n >= 2".to_string());
        }
        let preferences = (0..n).map(|i| c_span * i as f64 / (n - 1) as f64).collect();
        let mut neighbors = vec![Vec::new(); n];
        for i in 0..n {
            if i > 0 {
                neighbors[i].push(i - 1);
            }
            if i + 1 < n {
                neighbors[i].push(i + 1);
            }
        }
        Self::new(participants, neighbors, preferences, beta)
    }

    pub fn index_of(&self, id: &AgentId) -> Option<usize> {
        self.participants.iter().position(|p| p == id)
    }

    pub fn degree(&self, i: usize) -> usize {
        self.neighbors[i].len()
    }

    /// Local Jacobi step from a neighbor inbox (values at the *previous* iterate).
    pub fn jacobi(&self, node: usize, inbox: &BTreeMap<usize, f64>) -> Result<f64, String> {
        let mut total = 0.0;
        for &j in &self.neighbors[node] {
            let Some(value) = inbox.get(&j) else {
                return Err(format!("missing neighbor {j} for node {node}"));
            };
            total += *value;
        }
        let d = self.degree(node) as f64;
        Ok((self.preferences[node] + 2.0 * self.beta * total) / (1.0 + 2.0 * self.beta * d))
    }

    pub fn corollary_bound(&self, victim: usize, neighbor_delta: f64) -> f64 {
        let d = self.degree(victim) as f64;
        (2.0 * self.beta / (1.0 + 2.0 * self.beta * d)) * neighbor_delta.abs()
    }
}

/// Epoch-disciplined Jacobi coordinator.
#[derive(Clone, Debug)]
pub struct PreferenceEngine {
    active_epoch: Epoch,
    config: PreferenceEngineConfig,
    z: Vec<f64>,
    announced: BTreeMap<usize, f64>,
    /// Test helper: replace one announced value before the Jacobi sweep.
    stale_overrides: BTreeMap<usize, f64>,
    seen_events: BTreeSet<EventId>,
    counters: RuntimeCounters,
}

impl PreferenceEngine {
    /// Start at the preferred scores `c`.
    pub fn new(active_epoch: Epoch, config: PreferenceEngineConfig) -> Self {
        let z = config.preferences.clone();
        Self::with_state(active_epoch, config, z)
    }

    pub fn with_state(active_epoch: Epoch, config: PreferenceEngineConfig, z: Vec<f64>) -> Self {
        assert_eq!(z.len(), config.participants.len());
        Self {
            active_epoch,
            config,
            z,
            announced: BTreeMap::new(),
            stale_overrides: BTreeMap::new(),
            seen_events: BTreeSet::new(),
            counters: RuntimeCounters::default(),
        }
    }

    pub fn active_epoch(&self) -> Epoch {
        self.active_epoch
    }

    pub fn config(&self) -> &PreferenceEngineConfig {
        &self.config
    }

    pub fn z(&self) -> &[f64] {
        &self.z
    }

    pub fn z_star(&self) -> &[f64] {
        &self.config.z_star
    }

    pub fn distance_to_z_star(&self) -> f64 {
        l2_to(&self.z, &self.config.z_star)
    }

    /// Force a neighbor's announced value for the current epoch (violate cell).
    pub fn inject_stale(&mut self, neighbor: usize, value: f64) {
        self.stale_overrides.insert(neighbor, value);
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

    fn inbox(&self) -> BTreeMap<usize, f64> {
        let mut inbox = self.announced.clone();
        for (&j, value) in &self.stale_overrides {
            inbox.insert(j, *value);
        }
        inbox
    }

    fn try_finalize(&mut self) -> Option<FinalizationSummary> {
        let n = self.config.participants.len();
        if self.announced.len() < n {
            return None;
        }
        let inbox = self.inbox();
        let mut nxt = vec![0.0; n];
        for i in 0..n {
            nxt[i] = self
                .config
                .jacobi(i, &inbox)
                .expect("full announcement set implies a complete inbox");
        }
        self.z = nxt;
        self.announced.clear();
        self.stale_overrides.clear();
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

impl CoordinationEngine for PreferenceEngine {
    fn pattern(&self) -> PatternKind {
        PatternKind::Preference
    }

    fn apply(&mut self, event: SemanticEvent) -> EventOutcome {
        if event.pattern != PatternKind::Preference {
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

        if !payload.value.is_finite() {
            self.counters.rejected += 1;
            return EventOutcome::Rejected(RejectReason::IncompatiblePayload);
        }

        if self.announced.contains_key(&idx) {
            self.counters.rejected += 1;
            self.counters.duplicates += 1;
            return EventOutcome::Rejected(RejectReason::DuplicateEvent);
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

impl ConvergeSurface for PreferenceEngine {
    fn current_value(&self, id: &AgentId) -> Option<f64> {
        self.config.index_of(id).map(|i| self.z[i])
    }

    fn metric(&self) -> f64 {
        self.distance_to_z_star()
    }

    fn lower_is_better(&self) -> bool {
        true
    }

    fn local_view(&self, id: &AgentId) -> String {
        let Some(i) = self.config.index_of(id) else {
            return String::new();
        };
        let inbound: Vec<String> = self.config.neighbors[i]
            .iter()
            .filter_map(|&j| {
                Some(format!(
                    "{}={:.6}",
                    self.config.participants.get(j)?.0,
                    self.z.get(j)?
                ))
            })
            .collect();
        format!(
            "agent={}\nz_i={:.6}\nc_i={:.6}\nbeta={:.6}\nd_i={}\ninbound={}",
            id.0,
            self.z[i],
            self.config.preferences[i],
            self.config.beta,
            self.config.degree(i),
            inbound.join(",")
        )
    }

    fn announce_event(
        &self,
        id: &AgentId,
        epoch: u64,
        value: f64,
        event_id: &str,
    ) -> SemanticEvent {
        scalar_announce(PatternKind::Preference, id, epoch, value, event_id)
    }
}

fn l2_to(values: &[f64], target: &[f64]) -> f64 {
    values
        .iter()
        .zip(target)
        .map(|(v, t)| (v - t).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn solve_z_star(neighbors: &[Vec<usize>], c: &[f64], beta: f64) -> Result<Vec<f64>, String> {
    let n = c.len();
    let mut mat = vec![vec![0.0; n]; n];
    for i in 0..n {
        let d = neighbors[i].len() as f64;
        mat[i][i] = 1.0 + 2.0 * beta * d;
        for &j in &neighbors[i] {
            mat[i][j] -= 2.0 * beta;
        }
    }
    solve(mat, c.to_vec())
}

fn solve(mut mat: Vec<Vec<f64>>, rhs: Vec<f64>) -> Result<Vec<f64>, String> {
    let n = rhs.len();
    let mut a: Vec<Vec<f64>> = mat
        .drain(..)
        .enumerate()
        .map(|(i, mut row)| {
            row.push(rhs[i]);
            row
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n)
            .max_by(|r, s| a[*r][col].abs().total_cmp(&a[*s][col].abs()))
            .ok_or_else(|| "empty preference system".to_string())?;
        if a[pivot][col].abs() < SINGULAR {
            return Err("singular preference Laplacian system".to_string());
        }
        a.swap(col, pivot);
        let scale = a[col][col];
        for j in col..=n {
            a[col][j] /= scale;
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = a[row][col];
            for j in col..=n {
                a[row][j] -= factor * a[col][j];
            }
        }
    }
    Ok((0..n).map(|i| a[i][n]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::MasRuntime;
    use crate::types::{EventMetadata, EventSource};

    const BETA: f64 = 0.75;
    const Z_STAR: [f64; 3] = [2.4, 4.0, 5.6];

    fn paper_line() -> PreferenceEngineConfig {
        PreferenceEngineConfig::line(3, 8.0, BETA).expect("paper line")
    }

    fn engine_from(z: Vec<f64>) -> MasRuntime<PreferenceEngine> {
        MasRuntime::new(PreferenceEngine::with_state(Epoch(0), paper_line(), z))
    }

    fn announce(id: &str, epoch: u64, agent: usize, value: f64) -> SemanticEvent {
        SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from(id),
                correlation_id: None,
                epoch: Epoch(epoch),
                source: EventSource::Peer(AgentId::from(agent.to_string().as_str())),
            },
            payload: SemanticPayload::ScalarProposal(ScalarProposal {
                participant: AgentId::from(agent.to_string().as_str()),
                value,
            }),
        }
    }

    fn announce_all(
        rt: &mut MasRuntime<PreferenceEngine>,
        epoch: u64,
        prefix: &str,
    ) -> EventOutcome {
        let z = rt.engine().z().to_vec();
        let mut last = EventOutcome::Applied;
        for i in 0..z.len() {
            last = rt.apply(announce(&format!("{prefix}-{i}"), epoch, i, z[i]));
        }
        last
    }

    #[test]
    fn paper_fixed_point() {
        let cfg = paper_line();
        for (got, want) in cfg.z_star.iter().zip(Z_STAR) {
            assert!((got - want).abs() < 1e-12, "{got} vs {want}");
        }
    }

    #[test]
    fn one_step_from_c_reaches_z_star() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        let outcome = announce_all(&mut rt, 0, "r0");
        assert!(matches!(outcome, EventOutcome::Finalized(_)));
        for (got, want) in rt.engine().z().iter().zip(Z_STAR) {
            assert!((got - want).abs() < 1e-12, "{got} vs {want}");
        }
        assert!(rt.engine().distance_to_z_star() < 1e-12);
        assert_eq!(rt.engine().active_epoch(), Epoch(1));
    }

    #[test]
    fn contracts_toward_z_star_from_zero() {
        let mut rt = engine_from(vec![0.0, 0.0, 0.0]);
        let mut prev = rt.engine().distance_to_z_star();
        assert!(prev > 1.0);
        for epoch in 0..40 {
            let outcome = announce_all(&mut rt, epoch, &format!("e{epoch}"));
            assert!(matches!(outcome, EventOutcome::Finalized(_)));
            let now = rt.engine().distance_to_z_star();
            assert!(now <= prev + 1e-15, "distance {now} should be <= {prev}");
            prev = now;
        }
        assert!(rt.engine().distance_to_z_star() < 1e-6);
    }

    #[test]
    fn stale_epoch_is_rejected_and_hold_inbox_is_used() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        assert!(matches!(
            announce_all(&mut rt, 0, "r0"),
            EventOutcome::Finalized(_)
        ));
        let hold = rt.engine().z().to_vec();
        let stale = rt.apply(announce("late", 0, 1, 99.0));
        assert_eq!(
            stale,
            EventOutcome::Rejected(RejectReason::StaleEpoch { current: Epoch(1) })
        );
        assert_eq!(rt.engine().z(), hold.as_slice());
        assert!(matches!(
            announce_all(&mut rt, 1, "r1"),
            EventOutcome::Finalized(_)
        ));
        for (got, want) in rt.engine().z().iter().zip(Z_STAR) {
            assert!((got - want).abs() < 1e-12);
        }
    }

    #[test]
    fn replayed_event_id_is_rejected() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        let first = announce("same", 0, 0, 0.0);
        assert_eq!(rt.apply(first.clone()), EventOutcome::Applied);
        assert_eq!(
            rt.apply(first),
            EventOutcome::Rejected(RejectReason::DuplicateEvent)
        );
    }

    #[test]
    fn second_announcement_from_same_agent_is_replay() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        assert_eq!(rt.apply(announce("a", 0, 0, 0.0)), EventOutcome::Applied);
        assert_eq!(
            rt.apply(announce("b", 0, 0, 1.0)),
            EventOutcome::Rejected(RejectReason::DuplicateEvent)
        );
    }

    #[test]
    fn unknown_participant_rejected() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        let ev = SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from("x"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from("ghost")),
            },
            payload: SemanticPayload::ScalarProposal(ScalarProposal {
                participant: AgentId::from("ghost"),
                value: 1.0,
            }),
        };
        assert_eq!(
            rt.apply(ev),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );
    }

    #[test]
    fn stale_inject_obeys_corollary_bound() {
        let cfg = paper_line();
        let z = vec![1.0, 3.0, 7.0];
        let mut hold_inbox = BTreeMap::new();
        hold_inbox.insert(0, z[0]);
        hold_inbox.insert(2, z[2]);
        let hold = cfg.jacobi(1, &hold_inbox).unwrap();
        let mut stale_inbox = hold_inbox;
        let stale_neighbor = 0.0;
        stale_inbox.insert(0, stale_neighbor);
        let stale = cfg.jacobi(1, &stale_inbox).unwrap();
        let delta = (stale - hold).abs();
        let bound = cfg.corollary_bound(1, stale_neighbor - z[0]);
        assert!(delta <= bound + 1e-12, "{delta} > {bound}");
        assert!(delta > 0.0);

        let mut engine = PreferenceEngine::with_state(Epoch(0), cfg, z.clone());
        engine.inject_stale(0, stale_neighbor);
        let mut rt = MasRuntime::new(engine);
        assert!(matches!(
            announce_all(&mut rt, 0, "inj"),
            EventOutcome::Finalized(_)
        ));
        let moved = (rt.engine().z()[1] - hold).abs();
        assert!((moved - delta).abs() < 1e-12);
        assert!(moved <= bound + 1e-12);
    }

    #[test]
    fn future_epoch_is_deferred() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        assert_eq!(
            rt.apply(announce("future", 3, 0, 0.0)),
            EventOutcome::Deferred {
                expected: Epoch(0),
                received: Epoch(3)
            }
        );
    }

    #[test]
    fn wrong_pattern_and_payload_rejected() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        let mut ev = announce("p", 0, 0, 0.0);
        ev.pattern = PatternKind::Development;
        assert_eq!(
            rt.apply(ev),
            EventOutcome::Rejected(RejectReason::IncompatiblePattern)
        );
        let ev = SemanticEvent {
            pattern: PatternKind::Preference,
            metadata: EventMetadata {
                event_id: EventId::from("bytes"),
                correlation_id: None,
                epoch: Epoch(0),
                source: EventSource::Peer(AgentId::from("0")),
            },
            payload: SemanticPayload::ExternalBytes(b"nope".to_vec()),
        };
        assert_eq!(
            rt.apply(ev),
            EventOutcome::Rejected(RejectReason::IncompatiblePayload)
        );
    }

    #[test]
    fn config_rejects_invalid_instances() {
        assert!(PreferenceEngineConfig::new(vec![], vec![], vec![], BETA).is_err());
        assert!(PreferenceEngineConfig::line(1, 8.0, BETA).is_err());
        assert!(PreferenceEngineConfig::line(3, 8.0, 0.0).is_err());
        let ids = vec![AgentId::from("0"), AgentId::from("1")];
        assert!(
            PreferenceEngineConfig::new(ids.clone(), vec![vec![1], vec![0]], vec![0.0], BETA)
                .is_err()
        );
        assert!(
            PreferenceEngineConfig::new(ids, vec![vec![5], vec![0]], vec![0.0, 1.0], BETA).is_err()
        );
        let mut inbox = BTreeMap::new();
        inbox.insert(0, 1.0);
        let cfg = paper_line();
        assert!(cfg.jacobi(1, &inbox).is_err());
    }

    #[test]
    fn nan_local_tool_and_recovery_sources() {
        let mut rt = engine_from(vec![0.0, 4.0, 8.0]);
        assert_eq!(
            rt.apply(announce("nan", 0, 0, f64::NAN)),
            EventOutcome::Rejected(RejectReason::IncompatiblePayload)
        );

        let mut local = announce("local", 0, 0, 0.0);
        local.metadata.source = EventSource::Local;
        assert_eq!(rt.apply(local), EventOutcome::Applied);

        let mut tool = announce("tool", 0, 1, 4.0);
        tool.metadata.source = EventSource::Tool("1".into());
        assert_eq!(rt.apply(tool), EventOutcome::Applied);

        let mut task = announce("task", 0, 2, 8.0);
        task.metadata.source = EventSource::Task("t".into());
        assert_eq!(
            rt.apply(task),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );
        let mut recovery = announce("rec", 0, 2, 8.0);
        recovery.metadata.source = EventSource::Recovery;
        assert_eq!(
            rt.apply(recovery),
            EventOutcome::Rejected(RejectReason::UnknownParticipant)
        );
    }

    #[test]
    fn surface_exposes_local_view() {
        let engine = PreferenceEngine::new(Epoch(0), paper_line());
        let id = AgentId::from("0");
        let unknown = AgentId::from("ghost");
        assert_eq!(engine.pattern(), PatternKind::Preference);
        assert!(engine.lower_is_better());
        assert_eq!(engine.current_value(&id), Some(0.0));
        assert_eq!(engine.current_value(&unknown), None);
        assert!(engine.local_view(&id).contains("z_i="));
        assert!(engine.local_view(&unknown).is_empty());
        assert_eq!(engine.z_star().len(), 3);
        assert_eq!(engine.config().participants.len(), 3);
        assert_eq!(engine.counters().applied, 0);
        let ev = engine.announce_event(&id, 0, 0.0, "s");
        assert_eq!(ev.pattern, PatternKind::Preference);
    }
}
