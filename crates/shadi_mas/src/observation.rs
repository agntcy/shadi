//! Optional response telemetry. Observers cannot grant or deny an operation.
use crate::mediation::MediationRequest;
use a2a::{new_message_id, Part, SendMessageResponse, TaskState};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ResponseEvent {
    #[serde(rename = "response.produced")]
    Produced,
    #[serde(rename = "response.received")]
    Received,
    #[serde(rename = "call.failed")]
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseObservation {
    pub observation_id: String,
    pub event: ResponseEvent,
    pub observed_at_ms: u64,
    pub request_message_id: String,
    pub correlation_id: Option<String>,
    pub local_agent: String,
    pub peer: Option<String>,
    pub response_message_id: Option<String>,
    pub task_id: Option<String>,
    pub task_state: Option<TaskState>,
    pub response: Option<String>,
    pub error: Option<String>,
    pub truncated: bool,
    pub latency_ms: u64,
}

impl ResponseObservation {
    pub fn new(
        event: ResponseEvent,
        request: &MediationRequest,
        elapsed: Duration,
        result: Result<&SendMessageResponse, &str>,
    ) -> Self {
        let mut observation = Self {
            observation_id: new_message_id(),
            event,
            observed_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            request_message_id: request.message_id.clone(),
            correlation_id: request.correlation_id.clone(),
            local_agent: request.local_agent.clone(),
            peer: request.peer.clone(),
            response_message_id: None,
            task_id: None,
            task_state: None,
            response: None,
            error: None,
            truncated: false,
            latency_ms: elapsed.as_millis() as u64,
        };
        let message = match result {
            Ok(SendMessageResponse::Message(message)) => Some(message),
            Ok(SendMessageResponse::Task(task)) => {
                observation.task_id = Some(task.id.clone());
                observation.task_state = Some(task.status.state.clone());
                if matches!(
                    task.status.state,
                    TaskState::Failed | TaskState::Rejected | TaskState::Canceled
                ) {
                    observation.error = Some(format!("A2A task {:?}", task.status.state));
                }
                if task.status.message.is_none() {
                    observation.response = task
                        .artifacts
                        .as_ref()
                        .and_then(|artifacts| serde_json::to_string(artifacts).ok());
                }
                task.status.message.as_ref()
            }
            Err(error) => {
                observation.error = Some(error.to_owned());
                None
            }
        };
        if let Some(message) = message {
            observation.response_message_id = Some(message.message_id.clone());
            let text: Vec<_> = message.parts.iter().filter_map(Part::as_text).collect();
            observation.response = Some(if text.len() == message.parts.len() {
                text.join("\n")
            } else {
                serde_json::to_string(&message.parts).unwrap_or_default()
            });
        }
        // Bound each queued observation; never export request history or credentials.
        for value in [&mut observation.response, &mut observation.error]
            .into_iter()
            .flatten()
        {
            if value.len() > 16 * 1024 {
                value.truncate(value.floor_char_boundary(16 * 1024));
                observation.truncated = true;
            }
        }
        observation
    }
}

pub trait ResponseObserver: Send + Sync {
    /// Enqueue without blocking. Delivery, redaction and drop accounting belong to the host.
    fn observe(&self, observation: ResponseObservation);
}

pub fn publish(observer: &dyn ResponseObserver, observation: ResponseObservation) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observer.observe(observation)
    }))
    .is_err()
    {
        tracing::warn!("response observer panicked; application result unchanged");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::MediationPoint;
    use a2a::{Message, Role, Task, TaskStatus};

    fn request() -> MediationRequest {
        MediationRequest {
            evaluation_id: "gate".into(),
            point: MediationPoint::Receiver,
            message_id: "original-request".into(),
            task_id: None,
            correlation_id: Some("trace".into()),
            local_agent: "b".into(),
            peer: Some("a".into()),
            verified_sender_did: None,
            payload: None,
        }
    }

    #[test]
    fn correlates_reply_without_reusing_observation_or_response_ids() {
        let response =
            SendMessageResponse::Message(Message::new(Role::Agent, vec![Part::text("answer")]));
        let produced = ResponseObservation::new(
            ResponseEvent::Produced,
            &request(),
            Duration::from_millis(10),
            Ok(&response),
        );
        let received = ResponseObservation::new(
            ResponseEvent::Received,
            &request(),
            Duration::from_millis(20),
            Ok(&response),
        );
        assert_eq!(produced.request_message_id, "original-request");
        assert_eq!(produced.response_message_id, received.response_message_id);
        assert_ne!(
            produced.response_message_id.as_deref(),
            Some("original-request")
        );
        assert_ne!(produced.observation_id, received.observation_id);
        assert_eq!(produced.correlation_id.as_deref(), Some("trace"));
        assert_eq!(produced.response.as_deref(), Some("answer"));
        assert_eq!(received.latency_ms, 20);
    }

    #[test]
    fn keeps_task_failures_distinct_from_transport_failures() {
        let response = SendMessageResponse::Task(Task {
            id: "task".into(),
            context_id: "context".into(),
            status: TaskStatus {
                state: TaskState::Rejected,
                message: Some(Message::new(Role::Agent, vec![Part::text("policy denied")])),
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        });
        let observed = ResponseObservation::new(
            ResponseEvent::Received,
            &request(),
            Duration::ZERO,
            Ok(&response),
        );
        assert_eq!(observed.task_state, Some(TaskState::Rejected));
        assert_eq!(observed.response.as_deref(), Some("policy denied"));
        assert!(observed.error.is_some());
        let failed = ResponseObservation::new(
            ResponseEvent::Failed,
            &request(),
            Duration::ZERO,
            Err("connection closed"),
        );
        assert!(failed.response.is_none());
        assert!(failed.response_message_id.is_none());
        assert_eq!(failed.error.as_deref(), Some("connection closed"));
    }

    #[test]
    fn truncates_utf8_before_queueing_and_contains_observer_panics() {
        let response = SendMessageResponse::Message(Message::new(
            Role::Agent,
            vec![Part::text("\u{20ac}".repeat(10000))],
        ));
        let observed = ResponseObservation::new(
            ResponseEvent::Received,
            &request(),
            Duration::ZERO,
            Ok(&response),
        );
        assert!(observed.truncated);
        assert!(observed.response.as_ref().unwrap().len() <= 16384);
        struct Broken;
        impl ResponseObserver for Broken {
            fn observe(&self, _: ResponseObservation) {
                panic!("observer failed");
            }
        }
        publish(&Broken, observed);
    }
}
