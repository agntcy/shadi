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

/// Serializes every test in this crate that mutates the process environment.
///
/// `std::env::set_var` rewrites a process-global table, so a module-local
/// lock only stops its own tests from racing: a concurrent `set_var` in
/// another module can still make an unrelated `var()` lookup miss while
/// glibc reallocates the environment block. One lock for the whole crate is
/// the only thing that actually serializes them.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

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

#[cfg(test)]
mod tests {
    #[test]
    fn every_module_shares_one_env_lock() {
        assert!(
            std::ptr::eq(super::env_lock(), crate::dir_registry::dirctl_env_lock()),
            "a second env lock would let two modules mutate the environment at once"
        );
    }
}
