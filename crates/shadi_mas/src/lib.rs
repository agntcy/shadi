// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod adapters;
mod assembly;
pub mod experiments;
mod runtime;
mod types;

pub mod engines;

pub use adapters::{
    MessagingAdapter, TaskAdapter, TaskEnvelope, ToolAdapter, ToolCall, ToolProvider, ToolResult,
};
pub use assembly::{infer_pattern, AssemblySession};
pub use engines::converge::{
    parse_announce, parse_converge_vote, ConvergeController, ConvergeSurface,
};
pub use runtime::{AppliedTransition, CoordinationEngine, MasRuntime};
pub use types::{
    AgentId, ConvergeBallot, ConvergeDecision, ConvergeHalt, ConvergeSignal, Epoch, EventId,
    EventMetadata, EventOutcome, EventSource, FinalizationSummary, PatternKind, ProtocolPhase,
    RejectReason, RuntimeCounters, ScalarProposal, SemanticEvent, SemanticPayload,
};

pub mod integrations {
    pub use agent_transport_slim;
    pub use shadi_a2a;
}
