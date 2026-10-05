//! The one check a message passes before it leaves agentbridge: the reply to
//! a task, the automatic `NEXT` handoff, and `delegate`, `handoff` and
//! `coordinate`.

use std::sync::Arc;

use a2a::Message;
use agent_secrets::{AgentVerifier, SecretResult, SessionContext};
use shadi_mas::experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig};

/// Allows every message: the policy until #367 and #368 add rules.
struct NoRules;

impl AgentVerifier for NoRules {
    fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
        Ok(())
    }
}

/// The policy every outbound message passes.
pub(crate) fn policy() -> Arc<dyn AgentVerifier> {
    Arc::new(NoRules)
}

/// A live adapter whose every send passes [`policy`].
pub(crate) fn live_adapter(config: LiveA2ATaskAdapterConfig) -> LiveA2ATaskAdapter {
    LiveA2ATaskAdapter::new(config).with_verifier(policy())
}

/// Check a message sent without an A2A channel, which is a listener's reply.
/// `Err` is the reason it may not leave, carrying the evaluation id the
/// refusal is logged under.
pub(crate) fn check(
    policy: &dyn AgentVerifier,
    session: &SessionContext,
    message: &Message,
) -> Result<(), String> {
    let request = shadi_a2a::request_context(message, policy.wants_content());
    let evaluation_id = request.evaluation_id();
    match policy.verify_request(session, &request) {
        Ok(()) => {
            tracing::info!(evaluation_id, "egress policy allowed a message");
            Ok(())
        }
        Err(err) => {
            tracing::warn!(evaluation_id, %err, "egress policy refused a message");
            Err(format!(
                "withheld by egress policy ({evaluation_id}): {err}"
            ))
        }
    }
}
