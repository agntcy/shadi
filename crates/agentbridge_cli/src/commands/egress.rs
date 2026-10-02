//! The one check a message passes before it leaves agentbridge: the reply to
//! a task, the automatic `NEXT` handoff, and `delegate`, `handoff` and
//! `coordinate`.

use std::sync::Arc;

use a2a::Message;
use agent_secrets::{AgentVerifier, SessionContext};
use shadi_mas::experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig};

/// The policy every outbound message passes. There is none yet: #367 and #368
/// add the rules, so until then nothing is refused.
pub(crate) fn policy() -> Option<Arc<dyn AgentVerifier>> {
    None
}

/// A live adapter whose every send passes [`policy`].
pub(crate) fn live_adapter(config: LiveA2ATaskAdapterConfig) -> LiveA2ATaskAdapter {
    let adapter = LiveA2ATaskAdapter::new(config);
    match policy() {
        Some(policy) => adapter.with_verifier(policy),
        None => adapter,
    }
}

/// Check a message sent without an A2A channel, which is a listener's reply.
/// `Err` is the reason it may not leave.
pub(crate) fn check(
    policy: &dyn AgentVerifier,
    session: &SessionContext,
    message: &Message,
) -> Result<(), String> {
    let request = shadi_a2a::request_context(message, policy.wants_content());
    policy.verify_request(session, &request).map_err(|err| {
        tracing::warn!(
            evaluation_id = request.evaluation_id(),
            %err,
            "egress policy refused a message"
        );
        format!("withheld by egress policy: {err}")
    })
}
