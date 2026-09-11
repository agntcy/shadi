// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

pub mod adapter;
pub mod adapters;
pub mod context;
pub mod dir_registry;
pub mod local_registry;
pub mod member_source;
pub mod subprocess;

pub use shadi_mas;

pub use adapter::{prompt_tool_call, CliAdapter, CliAdapterError, CliToolAdapter};
pub use adapters::profile::{
    bundled_profile_ids, load_profile, open_profile_adapter, CliProfile, ProfileAdapter,
};
pub use context::{ArtifactPayload, CodeContext, ContextPacket, ConversationMessage, FileSnapshot};
pub use subprocess::TrackedSubprocess;

/// Re-export the shadi_mas coordination primitives most commonly used with
/// agentbridge so callers have a single dependency.
pub mod mas {
    pub use shadi_mas::{
        engines::cascade::{CascadeEngine, CascadeEngineConfig},
        engines::development::{DevelopmentEngine, DevelopmentEngineConfig},
        engines::preference::{PreferenceEngine, PreferenceEngineConfig},
        engines::resource::{ResourceEngine, ResourceEngineConfig},
        infer_pattern, parse_announce, parse_converge_vote, AgentId, AssemblySession,
        ConvergeBallot, ConvergeController, ConvergeDecision, ConvergeHalt, ConvergeSignal,
        ConvergeSurface, CoordinationEngine, Epoch, EventId, EventMetadata, EventOutcome,
        EventSource, MasRuntime, PatternKind, ProtocolPhase, ScalarProposal, SemanticEvent,
        SemanticPayload,
    };
}
