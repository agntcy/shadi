// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod adapters;
pub mod experiments;
mod runtime;
mod types;

pub mod engines;

pub use adapters::{
    MessagingAdapter, TaskAdapter, TaskEnvelope, ToolAdapter, ToolCall, ToolProvider,
    ToolResult,
};
pub use runtime::{AppliedTransition, CoordinationEngine, MasRuntime};
pub use types::{
    AgentId, Epoch, EventId, EventMetadata, EventOutcome, EventSource, FinalizationSummary,
    PatternKind, RejectReason, RuntimeCounters, SemanticEvent, SemanticPayload,
};

pub mod integrations {
    pub use agent_transport_slim;
    pub use shadi_a2a;
}
