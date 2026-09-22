//! Optional host-owned gates. Once installed, only an explicit Allow proceeds.
//! The bridge owns the hook; an agent cannot disable it or supply its decision.

use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, time::Duration};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediationPoint {
    Sender,
    Receiver,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MediationRequest {
    pub evaluation_id: String,
    pub point: MediationPoint,
    pub message_id: String,
    pub task_id: Option<String>,
    pub correlation_id: Option<String>,
    pub local_agent: String,
    pub peer: Option<String>,
    /// Present only on receive, after verification of the application's DID proof.
    pub verified_sender_did: Option<String>,
    /// Sender gates deliberately export metadata only. Receiver gates may export
    /// the verified plaintext to a trusted policy service.
    pub payload: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum MediationDecision {
    Allow {},
    Deny { reason: String },
}

pub trait MediationHook: Send + Sync {
    fn evaluate<'a>(
        &'a self,
        request: &'a MediationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<MediationDecision, String>> + Send + 'a>>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum MediationFailure {
    Denied(String),
    Unavailable(String),
}

impl std::fmt::Display for MediationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "mediation denied: {reason}"),
            Self::Unavailable(reason) => write!(f, "mediation unavailable: {reason}"),
        }
    }
}

/// No fallback, implicit allow, or observe mode. Dropping a timed-out future
/// cancels evaluation and must never resume the protected operation.
pub async fn require_allow(
    hook: &dyn MediationHook,
    request: &MediationRequest,
) -> Result<(), MediationFailure> {
    require_allow_with_timeout(hook, request, Duration::from_secs(5)).await
}

async fn require_allow_with_timeout(
    hook: &dyn MediationHook,
    request: &MediationRequest,
    timeout: Duration,
) -> Result<(), MediationFailure> {
    let result = match tokio::time::timeout(timeout, hook.evaluate(request)).await {
        Ok(Ok(MediationDecision::Allow {})) => Ok(()),
        Ok(Ok(MediationDecision::Deny { reason })) => Err(MediationFailure::Denied(reason)),
        Ok(Err(error)) => Err(MediationFailure::Unavailable(error)),
        Err(_) => Err(MediationFailure::Unavailable("deadline exceeded".into())),
    };
    tracing::info!(evaluation_id = %request.evaluation_id, message_id = %request.message_id,
        point = ?request.point, result = ?result, "mediation completed");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Answer(Option<Result<MediationDecision, String>>);
    impl MediationHook for Answer {
        fn evaluate<'a>(
            &'a self,
            _: &'a MediationRequest,
        ) -> Pin<Box<dyn Future<Output = Result<MediationDecision, String>> + Send + 'a>> {
            Box::pin(async move {
                match &self.0 {
                    Some(value) => value.clone(),
                    None => std::future::pending().await,
                }
            })
        }
    }
    #[test]
    fn explicit_allow_is_the_only_success() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let request = MediationRequest {
            evaluation_id: "e".into(),
            point: MediationPoint::Sender,
            message_id: "m".into(),
            task_id: None,
            correlation_id: None,
            local_agent: "a".into(),
            peer: None,
            verified_sender_did: None,
            payload: None,
        };
        for (answer, allowed) in [
            (Some(Ok(MediationDecision::Allow {})), true),
            (
                Some(Ok(MediationDecision::Deny {
                    reason: "policy".into(),
                })),
                false,
            ),
            (Some(Err("offline".into())), false),
            (None, false),
        ] {
            assert_eq!(
                rt.block_on(require_allow_with_timeout(
                    &Answer(answer),
                    &request,
                    Duration::from_millis(1)
                ))
                .is_ok(),
                allowed
            );
        }
    }
    #[test]
    fn malformed_decisions_are_not_allow() {
        for input in [
            r#"{}"#,
            r#"{"decision":"observe"}"#,
            r#"{"decision":"allow","extra":true}"#,
        ] {
            assert!(serde_json::from_str::<MediationDecision>(input).is_err());
        }
    }
}
