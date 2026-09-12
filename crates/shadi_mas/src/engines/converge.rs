// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! CONVERGE halt: improvement signal, STOP/CONTINUE, plateau, paper horizon.

use std::collections::BTreeMap;

use crate::runtime::CoordinationEngine;
use crate::types::{
    AgentId, ConvergeBallot, ConvergeDecision, ConvergeHalt, ConvergeSignal, Epoch, PatternKind,
    ScalarProposal, SemanticEvent,
};

const IMPROVE_EPS: f64 = 1e-9;

/// Tracks CONVERGE progress after each engine-finalized epoch.
#[derive(Clone, Debug)]
pub struct ConvergeController {
    pub participants: Vec<AgentId>,
    pub plateau_k: u32,
    pub paper_horizon: u64,
    pub lower_is_better: bool,
    last_metric: Option<f64>,
    non_improving: u32,
    epochs_done: u64,
    votes: BTreeMap<AgentId, ConvergeDecision>,
    halt: Option<ConvergeHalt>,
}

impl ConvergeController {
    pub fn new(
        participants: Vec<AgentId>,
        paper_horizon: u64,
        lower_is_better: bool,
        plateau_k: u32,
    ) -> Self {
        Self {
            participants,
            plateau_k: plateau_k.max(1),
            paper_horizon: paper_horizon.max(1),
            lower_is_better,
            last_metric: None,
            non_improving: 0,
            epochs_done: 0,
            votes: BTreeMap::new(),
            halt: None,
        }
    }

    pub fn halt(&self) -> Option<ConvergeHalt> {
        self.halt
    }

    pub fn begin_epoch(&mut self) {
        self.votes.clear();
    }

    pub fn mark_unmapped(&mut self) {
        self.halt = Some(ConvergeHalt::Unmapped);
    }

    pub fn record_metric(&mut self, epoch: Epoch, metric: f64) -> ConvergeSignal {
        let previous = self.last_metric;
        let delta = previous.map(|p| metric - p).unwrap_or(0.0);
        let improved = match previous {
            None => true,
            Some(prev) if self.lower_is_better => metric < prev - IMPROVE_EPS,
            Some(prev) => metric > prev + IMPROVE_EPS,
        };
        if improved {
            self.non_improving = 0;
        } else if previous.is_some() {
            self.non_improving += 1;
        }
        self.last_metric = Some(metric);
        self.epochs_done += 1;
        if self.epochs_done >= self.paper_horizon {
            self.halt = Some(ConvergeHalt::PaperHorizon);
        } else if self.non_improving >= self.plateau_k {
            self.halt = Some(if previous.is_some() && !improved && self.epochs_done > 1 {
                ConvergeHalt::NoSolution
            } else {
                ConvergeHalt::Plateau
            });
        }
        ConvergeSignal {
            epoch,
            metric,
            previous,
            delta,
            improved,
        }
    }

    pub fn vote(&mut self, ballot: ConvergeBallot) {
        if self.participants.iter().any(|p| p == &ballot.participant) {
            self.votes.insert(ballot.participant, ballot.decision);
        }
    }

    pub fn conclude_votes(&mut self) -> Option<ConvergeHalt> {
        if self.halt.is_some() {
            return self.halt;
        }
        let n = self.participants.len().max(1);
        let stops = self
            .votes
            .values()
            .filter(|d| **d == ConvergeDecision::Stop)
            .count();
        if stops * 2 > n {
            self.halt = Some(ConvergeHalt::MajorityStop);
        }
        self.halt
    }
}

pub fn parse_announce(text: &str) -> Option<f64> {
    for line in text.lines() {
        let trimmed = line.trim();
        let rest = trimmed
            .strip_prefix("ANNOUNCE value=")
            .or_else(|| trimmed.strip_prefix("ANNOUNCE "))
            .or_else(|| trimmed.strip_prefix("COMMIT proposal="))?;
        let token = rest.split(|c: char| c.is_whitespace() || c == ',').next()?;
        if let Ok(value) = token.parse::<f64>() {
            if value.is_finite() {
                return Some(value);
            }
        }
    }
    None
}

pub fn parse_converge_vote(text: &str) -> Option<ConvergeDecision> {
    for line in text.lines() {
        let upper = line.trim().to_ascii_uppercase();
        if upper.starts_with("VOTE STOP") || upper == "STOP" {
            return Some(ConvergeDecision::Stop);
        }
        if upper.starts_with("VOTE CONTINUE") || upper == "CONTINUE" {
            return Some(ConvergeDecision::Continue);
        }
    }
    None
}

/// Surface a CONVERGE engine exposes to `coordinate` / tests.
pub trait ConvergeSurface: CoordinationEngine {
    fn current_value(&self, id: &AgentId) -> Option<f64>;
    fn metric(&self) -> f64;
    fn lower_is_better(&self) -> bool;
    fn local_view(&self, id: &AgentId) -> String;
    fn announce_event(&self, id: &AgentId, epoch: u64, value: f64, event_id: &str)
        -> SemanticEvent;
}

pub fn scalar_announce(
    pattern: PatternKind,
    id: &AgentId,
    epoch: u64,
    value: f64,
    event_id: &str,
) -> SemanticEvent {
    use crate::types::{EventId, EventMetadata, EventSource, SemanticPayload};

    SemanticEvent {
        pattern,
        metadata: EventMetadata {
            event_id: EventId::from(event_id),
            correlation_id: None,
            epoch: Epoch(epoch),
            source: EventSource::Peer(id.clone()),
        },
        payload: SemanticPayload::ScalarProposal(ScalarProposal {
            participant: id.clone(),
            value,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Vec<AgentId> {
        vec![AgentId::from("a"), AgentId::from("b"), AgentId::from("c")]
    }

    #[test]
    fn majority_stop_halts() {
        let mut ctl = ConvergeController::new(ids(), 8, true, 3);
        ctl.record_metric(Epoch(0), 1.0);
        ctl.vote(ConvergeBallot {
            participant: AgentId::from("a"),
            decision: ConvergeDecision::Stop,
        });
        ctl.vote(ConvergeBallot {
            participant: AgentId::from("b"),
            decision: ConvergeDecision::Stop,
        });
        ctl.vote(ConvergeBallot {
            participant: AgentId::from("c"),
            decision: ConvergeDecision::Continue,
        });
        assert_eq!(ctl.conclude_votes(), Some(ConvergeHalt::MajorityStop));
    }

    #[test]
    fn paper_horizon_halts() {
        let mut ctl = ConvergeController::new(ids(), 2, true, 8);
        ctl.record_metric(Epoch(0), 2.0);
        assert_eq!(ctl.halt(), None);
        ctl.record_metric(Epoch(1), 1.0);
        assert_eq!(ctl.halt(), Some(ConvergeHalt::PaperHorizon));
    }

    #[test]
    fn plateau_without_improvement_is_no_solution() {
        let mut ctl = ConvergeController::new(ids(), 20, true, 2);
        ctl.record_metric(Epoch(0), 1.0);
        ctl.record_metric(Epoch(1), 1.0);
        ctl.record_metric(Epoch(2), 1.0);
        assert_eq!(ctl.halt(), Some(ConvergeHalt::NoSolution));
    }

    #[test]
    fn parse_announce_and_vote_lines() {
        assert_eq!(
            parse_announce("ANNOUNCE value=1.5 agent=goose-0"),
            Some(1.5)
        );
        assert_eq!(parse_announce("COMMIT proposal=2.25 agent=a"), Some(2.25));
        assert_eq!(parse_announce("ANNOUNCE nan"), None);
        assert_eq!(
            parse_converge_vote("VOTE CONTINUE\nNEXT goose-1"),
            Some(ConvergeDecision::Continue)
        );
        assert_eq!(
            parse_converge_vote("VOTE STOP"),
            Some(ConvergeDecision::Stop)
        );
        assert_eq!(parse_converge_vote("STOP"), Some(ConvergeDecision::Stop));
        assert_eq!(parse_converge_vote("NEXT goose-1"), None);
        assert_eq!(parse_announce("ANNOUNCE 3.25 extra"), Some(3.25));
        assert_eq!(
            parse_converge_vote("CONTINUE"),
            Some(ConvergeDecision::Continue)
        );
    }

    #[test]
    fn unmapped_and_higher_is_better() {
        let mut ctl = ConvergeController::new(ids(), 8, false, 3);
        ctl.mark_unmapped();
        assert_eq!(ctl.halt(), Some(ConvergeHalt::Unmapped));
        assert_eq!(ctl.conclude_votes(), Some(ConvergeHalt::Unmapped));

        let mut stock = ConvergeController::new(ids(), 8, false, 3);
        stock.begin_epoch();
        let first = stock.record_metric(Epoch(0), 10.0);
        assert!(first.improved);
        let second = stock.record_metric(Epoch(1), 12.0);
        assert!(second.improved);
        stock.vote(ConvergeBallot {
            participant: AgentId::from("ghost"),
            decision: ConvergeDecision::Stop,
        });
        assert_eq!(stock.conclude_votes(), None);
        stock.begin_epoch();
        stock.vote(ConvergeBallot {
            participant: AgentId::from("a"),
            decision: ConvergeDecision::Continue,
        });
        assert_eq!(stock.conclude_votes(), None);
    }
}
