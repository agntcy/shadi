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

/// Outermost bound on a challenge. The query inside it has its own, smaller
/// cap where it is parsed; this one keeps an oversized envelope from ever
/// being held.
pub const MAX_CHALLENGE_BYTES: usize = 32 * 1024;
/// How many times the client will re-prove or escalate before denying.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 2;
/// Wall-clock budget for an escalate prompt, and the most one send sits out
/// in listener retry-after waits. Past either is a deny.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Most retry-after waits one send sits out before denying. A wait is not a
/// failed proof, so it does not count against `max_attempts`.
pub const MAX_RETRY_AFTER_WAITS: u32 = 3;

const LISTENER_BUSY: &str = "AUTH_REQUIRED denied: listener busy: challenge capacity exhausted";

/// What a parked task hands the next send attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthChallenge {
    /// The parked task, so the retry lands on it instead of minting a new one.
    pub task_id: String,
    /// Opaque challenge the listener attached, if it attached one.
    pub challenge: Option<String>,
    /// How long the listener asked to be left alone before the next send,
    /// when it was too busy to issue a challenge.
    pub retry_after: Option<Duration>,
}

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
/// `send` is called for every attempt (including the first, which gets `None`;
/// later ones get what the previous parked response carried). `escalate` runs
/// only when policy is `Ask` and the first re-prove was not enough. A park with
/// a retry-after is waited out on this thread before the next send.
pub fn run_auth_required_loop<S, E>(
    send: S,
    config: &AuthRequiredConfig,
    escalate: E,
) -> Result<SendMessageResponse, String>
where
    S: FnMut(Option<&AuthChallenge>) -> Result<SendMessageResponse, String>,
    E: FnMut() -> Result<String, String>,
{
    run_auth_required_loop_with_sleep(send, config, escalate, std::thread::sleep)
}

/// As [`run_auth_required_loop`], with `sleep` doing the retry-after waits.
pub fn run_auth_required_loop_with_sleep<S, E, W>(
    mut send: S,
    config: &AuthRequiredConfig,
    mut escalate: E,
    mut sleep: W,
) -> Result<SendMessageResponse, String>
where
    S: FnMut(Option<&AuthChallenge>) -> Result<SendMessageResponse, String>,
    E: FnMut() -> Result<String, String>,
    W: FnMut(Duration),
{
    let mut attempt = 0u32;
    let mut waits = 0u32;
    let mut waited = Duration::ZERO;
    let mut parked: Option<AuthChallenge> = None;
    loop {
        let response = send(parked.as_ref())?;
        if !is_auth_required(&response) {
            return Ok(response);
        }
        parked = parked_challenge(&response)?;
        // A deny policy denies a busy park like any other.
        if let Some(wait) = parked
            .as_ref()
            .and_then(|p| p.retry_after)
            .filter(|_| config.policy != AuthRequiredPolicy::Deny)
        {
            waits += 1;
            waited = waited.saturating_add(wait);
            if waits > MAX_RETRY_AFTER_WAITS || waited > config.timeout {
                let action = AuthRequiredAction::Deny {
                    reason: LISTENER_BUSY.to_string(),
                };
                audit_auth_required(attempt, &action);
                return Err(LISTENER_BUSY.to_string());
            }
            tracing::info!(
                waits,
                wait_secs = wait.as_secs(),
                decision = "wait",
                "AUTH_REQUIRED"
            );
            sleep(wait);
            continue;
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

fn parked_challenge(response: &SendMessageResponse) -> Result<Option<AuthChallenge>, String> {
    let SendMessageResponse::Task(task) = response else {
        return Ok(None);
    };
    let message = task.status.message.as_ref();
    let challenge = message.and_then(shadi_a2a::challenge_from_message);
    if challenge.is_some_and(|c| c.len() > MAX_CHALLENGE_BYTES) {
        return Err(format!(
            "AUTH_REQUIRED denied: challenge exceeds {MAX_CHALLENGE_BYTES} bytes"
        ));
    }
    Ok(Some(AuthChallenge {
        task_id: task.id.clone(),
        challenge: challenge.map(str::to_string),
        retry_after: message
            .and_then(shadi_a2a::retry_after_from_message)
            .map(Duration::from_secs),
    }))
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

    fn parked_task_with_challenge(challenge: &str) -> SendMessageResponse {
        let SendMessageResponse::Task(mut task) = parked_task() else {
            unreachable!()
        };
        task.status.message = Some(shadi_a2a::insert_challenge(
            Message::new(Role::Agent, vec![Part::text("prove".to_string())]),
            challenge,
        ));
        SendMessageResponse::Task(task)
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
            |_| {
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
        let err = run_auth_required_loop(|_| Ok(parked_task()), &cfg, || Ok(String::new()))
            .expect_err("must deny after max attempts");
        assert!(err.contains("AUTH_REQUIRED denied"));
        assert!(err.contains("exceeded"));
    }

    #[test]
    fn default_config_matches_published_bounds() {
        let cfg = AuthRequiredConfig::default();
        assert_eq!(cfg.policy, AuthRequiredPolicy::ReProve);
        assert_eq!(cfg.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(cfg.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn from_env_reads_policy_attempts_and_timeout() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SHADI_AUTH_REQUIRED_POLICY");
        std::env::remove_var("SHADI_AUTH_REQUIRED_MAX_ATTEMPTS");
        std::env::remove_var("SHADI_AUTH_REQUIRED_TIMEOUT_MS");
        let defaults = AuthRequiredConfig::from_env();
        assert_eq!(defaults.policy, AuthRequiredPolicy::ReProve);
        assert_eq!(defaults.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(defaults.timeout, DEFAULT_TIMEOUT);

        std::env::set_var("SHADI_AUTH_REQUIRED_POLICY", "ask");
        std::env::set_var("SHADI_AUTH_REQUIRED_MAX_ATTEMPTS", "5");
        std::env::set_var("SHADI_AUTH_REQUIRED_TIMEOUT_MS", "250");
        let parsed = AuthRequiredConfig::from_env();
        assert_eq!(parsed.policy, AuthRequiredPolicy::Ask);
        assert_eq!(parsed.max_attempts, 5);
        assert_eq!(parsed.timeout, Duration::from_millis(250));

        std::env::set_var("SHADI_AUTH_REQUIRED_POLICY", "deny");
        std::env::set_var("SHADI_AUTH_REQUIRED_MAX_ATTEMPTS", "0");
        std::env::set_var("SHADI_AUTH_REQUIRED_TIMEOUT_MS", "0");
        let fallback = AuthRequiredConfig::from_env();
        assert_eq!(fallback.policy, AuthRequiredPolicy::Deny);
        assert_eq!(fallback.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(fallback.timeout, DEFAULT_TIMEOUT);

        std::env::remove_var("SHADI_AUTH_REQUIRED_POLICY");
        std::env::remove_var("SHADI_AUTH_REQUIRED_MAX_ATTEMPTS");
        std::env::remove_var("SHADI_AUTH_REQUIRED_TIMEOUT_MS");
    }

    #[test]
    fn send_error_propagates_without_retry() {
        let cfg = AuthRequiredConfig::default();
        let err = run_auth_required_loop(|_| Err("transport down".into()), &cfg, || Ok(String::new()))
            .expect_err("send failure must surface");
        assert_eq!(err, "transport down");
    }

    #[test]
    fn ask_policy_escalates_then_completes() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::Ask,
            max_attempts: 2,
            timeout: Duration::from_secs(1),
        };
        let mut n = 0;
        let mut escalated = 0;
        let response = run_auth_required_loop(
            |_| {
                n += 1;
                if n < 3 {
                    Ok(parked_task())
                } else {
                    Ok(completed_message())
                }
            },
            &cfg,
            || {
                escalated += 1;
                Ok("operator-ok".to_string())
            },
        )
        .expect("escalate should complete");
        assert!(!is_auth_required(&response));
        assert_eq!(n, 3);
        assert_eq!(escalated, 1);
    }

    #[test]
    fn escalate_failure_denies() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::Ask,
            max_attempts: 2,
            timeout: Duration::from_secs(1),
        };
        let mut n = 0;
        let err = run_auth_required_loop(
            |_| {
                n += 1;
                Ok(parked_task())
            },
            &cfg,
            || Err("no operator".into()),
        )
        .expect_err("escalate failure must deny");
        assert!(err.contains("escalate failed"));
        assert!(err.contains("no operator"));
    }

    #[test]
    fn escalate_timeout_denies() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::Ask,
            max_attempts: 2,
            timeout: Duration::from_millis(5),
        };
        let err = run_auth_required_loop(
            |_| Ok(parked_task()),
            &cfg,
            || {
                std::thread::sleep(Duration::from_millis(20));
                Ok("late".into())
            },
        )
        .expect_err("slow escalate must time out");
        assert!(err.contains("timed out"));
    }

    #[test]
    fn parked_challenge_and_task_id_reach_the_next_attempt() {
        let cfg = AuthRequiredConfig::default();
        let mut seen = Vec::new();
        run_auth_required_loop(
            |previous| {
                seen.push(previous.cloned());
                if seen.len() == 1 {
                    Ok(parked_task_with_challenge("{\"nonce\":\"n1\"}"))
                } else {
                    Ok(completed_message())
                }
            },
            &cfg,
            || Ok(String::new()),
        )
        .expect("second attempt completes");
        assert_eq!(seen[0], None);
        let second = seen[1].as_ref().expect("challenge reaches attempt two");
        assert_eq!(second.task_id, "parked");
        assert_eq!(second.challenge.as_deref(), Some("{\"nonce\":\"n1\"}"));
    }

    #[test]
    fn oversized_challenge_denies_with_the_limit() {
        let cfg = AuthRequiredConfig::default();
        let big = "x".repeat(MAX_CHALLENGE_BYTES + 1);
        let err = run_auth_required_loop(
            |_| Ok(parked_task_with_challenge(&big)),
            &cfg,
            || Ok(String::new()),
        )
        .expect_err("oversized challenge must deny");
        assert!(err.contains("AUTH_REQUIRED denied"));
        assert!(err.contains(&MAX_CHALLENGE_BYTES.to_string()));
    }

    fn parked_task_with_retry_after(secs: u64) -> SendMessageResponse {
        let SendMessageResponse::Task(mut task) = parked_task() else {
            unreachable!()
        };
        task.status.message = Some(shadi_a2a::insert_retry_after(
            Message::new(Role::Agent, vec![Part::text("busy".to_string())]),
            secs,
        ));
        SendMessageResponse::Task(task)
    }

    fn reprove(max_attempts: u32, timeout: Duration) -> AuthRequiredConfig {
        AuthRequiredConfig {
            policy: AuthRequiredPolicy::ReProve,
            max_attempts,
            timeout,
        }
    }

    /// Runs the loop over `responses` in order, recording what each send saw
    /// and every wait instead of sleeping.
    fn run_scripted(
        responses: Vec<SendMessageResponse>,
        cfg: &AuthRequiredConfig,
    ) -> (
        Result<SendMessageResponse, String>,
        Vec<Option<AuthChallenge>>,
        Vec<Duration>,
    ) {
        let mut responses = responses.into_iter();
        let mut seen = Vec::new();
        let mut slept = Vec::new();
        let result = run_auth_required_loop_with_sleep(
            |previous| {
                seen.push(previous.cloned());
                Ok(responses.next().expect("no send past the script"))
            },
            cfg,
            || Ok(String::new()),
            |wait| slept.push(wait),
        );
        (result, seen, slept)
    }

    #[test]
    fn a_retry_after_wait_then_a_challenge_completes() {
        let (result, seen, slept) = run_scripted(
            vec![
                parked_task_with_retry_after(5),
                parked_task_with_challenge("{\"nonce\":\"n1\"}"),
                completed_message(),
            ],
            &reprove(2, DEFAULT_TIMEOUT),
        );
        assert!(!is_auth_required(&result.expect("completes")));
        assert_eq!(slept, [Duration::from_secs(5)]);
        let after_wait = seen[1].as_ref().expect("the wait reaches attempt two");
        assert_eq!(after_wait.task_id, "parked");
        assert_eq!(after_wait.retry_after, Some(Duration::from_secs(5)));
        assert_eq!(after_wait.challenge, None);
        assert_eq!(
            seen[2].as_ref().and_then(|p| p.challenge.as_deref()),
            Some("{\"nonce\":\"n1\"}")
        );
    }

    #[test]
    fn retry_after_waits_do_not_spend_attempts() {
        let mut script: Vec<_> = (0..MAX_RETRY_AFTER_WAITS)
            .map(|_| parked_task_with_retry_after(1))
            .collect();
        script.push(parked_task_with_challenge("{\"nonce\":\"n1\"}"));
        script.push(completed_message());
        let (result, _, slept) = run_scripted(script, &reprove(1, DEFAULT_TIMEOUT));
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(slept.len(), MAX_RETRY_AFTER_WAITS as usize);
    }

    #[test]
    fn retry_after_waits_past_the_timeout_deny_as_busy() {
        let (result, seen, slept) = run_scripted(
            vec![
                parked_task_with_retry_after(20),
                parked_task_with_retry_after(20),
            ],
            &reprove(2, Duration::from_secs(30)),
        );
        let err = result.expect_err("40s of waits exceed a 30s budget");
        assert!(err.contains("listener busy"), "{err}");
        assert!(err.contains("challenge capacity exhausted"), "{err}");
        assert_eq!(slept, [Duration::from_secs(20)]);
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn a_retry_after_longer_than_the_timeout_denies_without_waiting() {
        let (result, _, slept) = run_scripted(
            vec![parked_task_with_retry_after(50)],
            &reprove(2, Duration::from_secs(30)),
        );
        assert!(result.expect_err("too long").contains("listener busy"));
        assert!(slept.is_empty());
    }

    #[test]
    fn more_retry_after_waits_than_the_cap_deny_as_busy() {
        let script = (0..=MAX_RETRY_AFTER_WAITS)
            .map(|_| parked_task_with_retry_after(1))
            .collect();
        let (result, seen, slept) = run_scripted(script, &reprove(2, DEFAULT_TIMEOUT));
        assert!(result.expect_err("capped").contains("listener busy"));
        assert_eq!(slept.len(), MAX_RETRY_AFTER_WAITS as usize);
        assert_eq!(seen.len(), MAX_RETRY_AFTER_WAITS as usize + 1);
    }

    #[test]
    fn a_park_without_retry_after_never_waits() {
        let (result, seen, slept) = run_scripted(
            vec![parked_task(), parked_task()],
            &reprove(1, DEFAULT_TIMEOUT),
        );
        let err = result.expect_err("must deny after max attempts");
        assert!(err.contains("exceeded"), "{err}");
        assert!(slept.is_empty());
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].as_ref().and_then(|p| p.retry_after), None);
    }

    #[test]
    fn a_deny_policy_denies_a_busy_park_without_waiting() {
        let cfg = AuthRequiredConfig {
            policy: AuthRequiredPolicy::Deny,
            max_attempts: 2,
            timeout: DEFAULT_TIMEOUT,
        };
        let (result, _, slept) = run_scripted(vec![parked_task_with_retry_after(5)], &cfg);
        assert!(result.expect_err("deny").contains("policy"));
        assert!(slept.is_empty());
    }
}
