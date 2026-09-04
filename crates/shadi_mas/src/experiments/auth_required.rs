// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Client handling for A2A `TASK_STATE_AUTH_REQUIRED`.
//!
//! A remote task can park until the caller re-proves the agent DID or an
//! operator escalates. This module decides what to do; it does not talk to
//! SLIM. Timeout and repeat bounds deny the task with a reason so the
//! coordinate/delegate loop cannot hang.

use std::time::Duration;

use a2a::{SendMessageResponse, TaskState};

/// How many times the client will re-prove or escalate before denying.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 2;
/// Wall-clock budget for an escalate prompt. Expired escalate is a deny.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRequiredPolicy {
    /// Re-sign from the agent DID. Default.
    ReProve,
    /// Ask the local harness (`CliAdapter::execute_prompt` / stdin).
    Ask,
    /// Fail immediately with a reason.
    Deny,
}

impl AuthRequiredPolicy {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ask" => Self::Ask,
            "deny" => Self::Deny,
            _ => Self::ReProve,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequiredConfig {
    pub policy: AuthRequiredPolicy,
    pub max_attempts: u32,
    pub timeout: Duration,
}

impl Default for AuthRequiredConfig {
    fn default() -> Self {
        Self {
            policy: AuthRequiredPolicy::ReProve,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl AuthRequiredConfig {
    pub fn from_env() -> Self {
        let policy = std::env::var("SHADI_AUTH_REQUIRED_POLICY")
            .map(|raw| AuthRequiredPolicy::parse(&raw))
            .unwrap_or(AuthRequiredPolicy::ReProve);
        let max_attempts = std::env::var("SHADI_AUTH_REQUIRED_MAX_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_ATTEMPTS);
        let timeout = std::env::var("SHADI_AUTH_REQUIRED_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .filter(|n: &u64| *n > 0)
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_TIMEOUT);
        Self {
            policy,
            max_attempts,
            timeout,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthRequiredAction {
    /// Sign the same payload again from the agent DID.
    ReProve,
    /// Append operator input and retry. `note` is the escalate answer.
    Escalate { note: String },
    /// Stop. `reason` is safe to print (no secrets).
    Deny { reason: String },
}

/// Decide the next step after a parked `AUTH_REQUIRED` task.
///
/// `attempt` is 1-based (the first park is attempt 1).
pub fn decide_auth_required(attempt: u32, config: &AuthRequiredConfig) -> AuthRequiredAction {
    if attempt > config.max_attempts {
        return AuthRequiredAction::Deny {
            reason: format!(
                "AUTH_REQUIRED denied: exceeded {} attempts",
                config.max_attempts
            ),
        };
    }
    match config.policy {
        AuthRequiredPolicy::Deny => AuthRequiredAction::Deny {
            reason: "AUTH_REQUIRED denied by policy".to_string(),
        },
        AuthRequiredPolicy::ReProve => AuthRequiredAction::ReProve,
        AuthRequiredPolicy::Ask => {
            if attempt == 1 {
                AuthRequiredAction::ReProve
            } else {
                AuthRequiredAction::Escalate {
                    note: String::new(),
                }
            }
        }
    }
}

pub fn is_auth_required(response: &SendMessageResponse) -> bool {
    matches!(
        response,
        SendMessageResponse::Task(task) if task.status.state == TaskState::AuthRequired
    )
}

/// Drive send attempts until the task leaves `AUTH_REQUIRED` or is denied.
///
/// `send` is called for every attempt (including the first). `escalate` runs
/// only when policy is `Ask` and the first re-prove was not enough.
pub fn run_auth_required_loop<S, E>(
    mut send: S,
    config: &AuthRequiredConfig,
    mut escalate: E,
) -> Result<SendMessageResponse, String>
where
    S: FnMut() -> Result<SendMessageResponse, String>,
    E: FnMut() -> Result<String, String>,
{
    let mut attempt = 0u32;
    loop {
        let response = send()?;
        if !is_auth_required(&response) {
            return Ok(response);
        }
        attempt += 1;
        let action = decide_auth_required(attempt, config);
        audit_auth_required(attempt, &action);
        match action {
            AuthRequiredAction::ReProve => {}
            AuthRequiredAction::Escalate { .. } => {
                let started = std::time::Instant::now();
                let note = escalate().map_err(|err| {
                    format!("AUTH_REQUIRED denied: escalate failed: {err}")
                })?;
                if started.elapsed() > config.timeout {
                    return Err(format!(
                        "AUTH_REQUIRED denied: escalate timed out after {}ms",
                        config.timeout.as_millis()
                    ));
                }
                let _ = note;
            }
            AuthRequiredAction::Deny { reason } => return Err(reason),
        }
    }
}

/// Record the decision without secrets or raw tokens.
pub fn audit_auth_required(attempt: u32, action: &AuthRequiredAction) {
    match action {
        AuthRequiredAction::ReProve => {
            tracing::info!(attempt, decision = "reprove", "AUTH_REQUIRED");
        }
        AuthRequiredAction::Escalate { .. } => {
            tracing::info!(attempt, decision = "escalate", "AUTH_REQUIRED");
        }
        AuthRequiredAction::Deny { reason } => {
            tracing::info!(attempt, decision = "deny", reason, "AUTH_REQUIRED");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a2a::{Message, Part, Role, Task, TaskStatus};

    #[test]
    fn policy_parse_defaults_to_reprove() {
        assert_eq!(AuthRequiredPolicy::parse("ask"), AuthRequiredPolicy::Ask);
        assert_eq!(AuthRequiredPolicy::parse("DENY"), AuthRequiredPolicy::Deny);
        assert_eq!(
            AuthRequiredPolicy::parse("anything"),
            AuthRequiredPolicy::ReProve
        );
    }

    #[test]
    fn decide_denies_after_max_attempts() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::ReProve,
            max_attempts: 2,
            timeout: Duration::from_secs(1),
        };
        assert_eq!(decide_auth_required(1, &cfg), AuthRequiredAction::ReProve);
        assert_eq!(decide_auth_required(2, &cfg), AuthRequiredAction::ReProve);
        match decide_auth_required(3, &cfg) {
            AuthRequiredAction::Deny { reason } => {
                assert!(reason.contains("exceeded"));
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn ask_policy_reproves_then_escalates() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::Ask,
            max_attempts: 2,
            timeout: Duration::from_secs(1),
        };
        assert_eq!(decide_auth_required(1, &cfg), AuthRequiredAction::ReProve);
        assert!(matches!(
            decide_auth_required(2, &cfg),
            AuthRequiredAction::Escalate { .. }
        ));
    }

    #[test]
    fn deny_policy_fails_with_reason() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::Deny,
            max_attempts: 2,
            timeout: Duration::from_secs(1),
        };
        match decide_auth_required(1, &cfg) {
            AuthRequiredAction::Deny { reason } => {
                assert!(reason.contains("policy"));
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn detects_auth_required_task() {
        let task = Task {
            id: "t1".to_string(),
            context_id: "c1".to_string(),
            status: TaskStatus {
                state: TaskState::AuthRequired,
                message: Some(Message::new(
                    Role::Agent,
                    vec![Part::text("prove DID".to_string())],
                )),
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        assert!(is_auth_required(&SendMessageResponse::Task(task)));
        let done = Message::new(Role::Agent, vec![Part::text("ok".to_string())]);
        assert!(!is_auth_required(&SendMessageResponse::Message(done)));
    }

    fn parked_task() -> SendMessageResponse {
        SendMessageResponse::Task(Task {
            id: "parked".to_string(),
            context_id: "ctx".to_string(),
            status: TaskStatus {
                state: TaskState::AuthRequired,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        })
    }

    fn completed_message() -> SendMessageResponse {
        SendMessageResponse::Message(Message::new(
            Role::Agent,
            vec![Part::text("done after re-auth".to_string())],
        ))
    }

    #[test]
    fn parked_task_completes_after_reprove() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::ReProve,
            max_attempts: 2,
            timeout: Duration::from_secs(1),
        };
        let mut n = 0;
        let response = run_auth_required_loop(
            || {
                n += 1;
                if n == 1 {
                    Ok(parked_task())
                } else {
                    Ok(completed_message())
                }
            },
            &cfg,
            || Ok(String::new()),
        )
        .expect("re-prove should complete");
        assert!(!is_auth_required(&response));
        assert_eq!(n, 2);
    }

    #[test]
    fn denied_task_fails_with_reason_and_does_not_hang() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::ReProve,
            max_attempts: 1,
            timeout: Duration::from_millis(10),
        };
        let err = run_auth_required_loop(|| Ok(parked_task()), &cfg, || Ok(String::new()))
            .expect_err("must deny after max attempts");
        assert!(err.contains("AUTH_REQUIRED denied"));
        assert!(err.contains("exceeded"));
    }
}
