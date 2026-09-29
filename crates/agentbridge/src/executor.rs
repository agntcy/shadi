// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Reusable A2A executor shared by the CLI and hosts embedding AgentBridge.

use crate::{local_registry::LocalAdapterRegistry, CliAdapter};
use a2a::event::StreamResponse;
use a2a::*;
use a2a_server::AgentExecutor;
use async_trait::async_trait;
use futures::{stream::BoxStream, StreamExt};
use shadi_a2a::A2ABinding;
use shadi_mas::{
    experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig},
    mediation::{require_allow, MediationFailure, MediationHook, MediationPoint, MediationRequest},
    observation::{publish, ResponseEvent, ResponseObservation, ResponseObserver},
    Epoch, PatternKind, TaskAdapter, TaskEnvelope,
};
use std::sync::Arc;

pub struct AgentBridgeExecutor {
    adapter: Arc<dyn CliAdapter>,
    agent_did: Option<String>,
    slim_endpoint: Option<String>,
    verbose: bool,
    mediation: Option<Arc<dyn MediationHook>>,
    observer: Option<Arc<dyn ResponseObserver>>,
}

impl AgentBridgeExecutor {
    pub fn new(
        adapter: Arc<dyn CliAdapter>,
        agent_did: Option<String>,
        slim_endpoint: Option<String>,
        verbose: bool,
    ) -> Self {
        Self {
            adapter,
            agent_did,
            slim_endpoint,
            verbose,
            mediation: None,
            observer: None,
        }
    }

    pub fn with_mediation(mut self, hook: Arc<dyn MediationHook>) -> Self {
        self.mediation = Some(hook);
        self
    }

    pub fn with_observer(mut self, observer: Arc<dyn ResponseObserver>) -> Self {
        self.observer = Some(observer);
        self
    }
}

fn preview(s: &str, max: usize) -> String {
    let first_line = s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s);
    if first_line.len() > max {
        let end = first_line.floor_char_boundary(max);
        format!("{}…", &first_line[..end])
    } else {
        first_line.to_string()
    }
}

/// Print a request/response body inside the `┌─ .../└─` box: every line
/// when `verbose`, a single truncated preview line otherwise.
fn print_body(s: &str, max: usize, verbose: bool) {
    if verbose {
        for line in s.lines() {
            println!("│  {line}");
        }
    } else {
        println!("│  {}", preview(s, max));
    }
}

/// Opt-in: the collab demo sets this so a listener that just ran a coding
/// turn can A2A-dispatch to the peer named in `NEXT <id>`. Off by default
/// so one-shot `delegate` demos do not sprout extra client sends.
fn a2a_forward_enabled() -> bool {
    matches!(
        std::env::var("AGENTBRIDGE_A2A_FORWARD").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

fn allowed_a2a_peers() -> Vec<String> {
    std::env::var("AGENTBRIDGE_A2A_PEERS")
        .unwrap_or_else(|_| "claude-code,copilot,codex,cursor-agent".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Last `NEXT <id>` in the CLI reply. `DONE` or an error reply means no hop.
fn parse_next_peer(reply: &str) -> Option<String> {
    if reply.contains("agentbridge error:") {
        return None;
    }
    let mut chosen = None;
    for line in reply.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (head, rest) = line
            .split_once(char::is_whitespace)
            .map(|(h, r)| (h, r.trim()))
            .unwrap_or((line, ""));
        if head.eq_ignore_ascii_case("DONE") {
            return None;
        }
        if head.eq_ignore_ascii_case("NEXT") && !rest.is_empty() {
            chosen = Some(rest.split_whitespace().next().unwrap_or(rest).to_string());
        }
    }
    chosen
}

fn is_handoff_or_summary_prompt(prompt: &str) -> bool {
    let start = prompt.trim_start();
    start.starts_with("HANDOFF from ")
        || start.starts_with("You are continuing a coding session")
        || start.starts_with("Summarize this session for handoff")
        || start.contains("Acknowledge you have received the handoff")
}

fn is_peer_handoff_packet(prompt: &str) -> bool {
    prompt.trim_start().starts_with("HANDOFF from ")
}

fn section_after<'a>(text: &'a str, marker: &str, until: Option<&str>) -> &'a str {
    let rest = match text.split_once(marker) {
        Some((_, rest)) => rest,
        None => return "",
    };
    let rest = rest.trim_start_matches('\n');
    match until {
        Some(end) => rest
            .split_once(end)
            .map(|(head, _)| head)
            .unwrap_or(rest)
            .trim(),
        None => rest.trim(),
    }
}

/// Shared turn text for the next peer: last reply, goal, file, tests.
/// Not an "acknowledge" prompt — that was empty context and wasted a CLI turn.
fn render_peer_handoff(from: &str, to: &str, inbound: &str, reply: &str) -> String {
    let goal = section_after(inbound, "GOAL:", Some("HARD RULE:"));
    let goal = goal.lines().next().unwrap_or(goal).trim();
    let file = section_after(inbound, "Current src/lib.rs:", Some("Last cargo test:"));
    let tests = section_after(inbound, "Last cargo test:", None);
    format!(
        "HANDOFF from {from} to {to}\n\
         Do not write Rust. Store this turn; your next coding hop arrives separately.\n\n\
         ## Last reply from {from}\n{}\n\n\
         ## GOAL\n{goal}\n\n\
         ## src/lib.rs when they edited\n{file}\n\n\
         ## Last cargo test\n{tests}\n",
        reply.trim()
    )
}

fn next_peer_to_forward(self_id: &str, prompt: &str, reply: &str) -> Option<String> {
    if !a2a_forward_enabled() || is_handoff_or_summary_prompt(prompt) {
        return None;
    }
    let peer = parse_next_peer(reply)?;
    if peer == self_id {
        return None;
    }
    allowed_a2a_peers()
        .into_iter()
        .find(|allowed| allowed == &peer)
}

/// Where `NEXT <peer>` should go. DID is the name; URL / SLIM endpoint are locators.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HandoffTarget {
    peer_agent_id: String,
    peer_did: Option<String>,
    a2a_url: Option<String>,
    a2a_binding: Option<A2ABinding>,
    slim_endpoint: Option<String>,
}

/// Resolve a `NEXT` peer from on-host leases. Prefer the unicast locator when
/// the lease has one so an HTTP-only collab can token-pass without a SLIM node.
fn resolve_handoff_target(
    to: &str,
    slim_fallback: Option<&str>,
    registry: &LocalAdapterRegistry,
) -> Result<HandoffTarget, String> {
    match registry.resolve_live(to) {
        Ok(record) => {
            let a2a_url = if record.a2a_url.is_empty() {
                None
            } else {
                Some(record.a2a_url)
            };
            let a2a_binding = a2a_url.as_ref().map(|_| record.a2a_binding);
            let slim_endpoint = if !record.slim_endpoint.is_empty() {
                Some(record.slim_endpoint)
            } else {
                slim_fallback.map(str::to_string)
            };
            if a2a_url.is_none() && slim_endpoint.is_none() {
                return Err(format!(
                    "live adapter '{to}' has no A2A locator or SLIM endpoint"
                ));
            }
            Ok(HandoffTarget {
                peer_agent_id: record.name,
                peer_did: if record.did.is_empty() {
                    None
                } else {
                    Some(record.did)
                },
                a2a_url,
                a2a_binding,
                slim_endpoint,
            })
        }
        Err(err) if err.contains("ambiguous") => Err(err),
        Err(_) => match slim_fallback {
            Some(endpoint) => Ok(HandoffTarget {
                peer_agent_id: to.to_string(),
                peer_did: None,
                a2a_url: None,
                a2a_binding: None,
                slim_endpoint: Some(endpoint.to_string()),
            }),
            None => Err(format!(
                "no live locator for '{to}'; peer must appear in `list --local` \
                 (A2A locator or SLIM endpoint) so NEXT can be dispatched without a SLIM node"
            )),
        },
    }
}

/// Send an A2A inject to `to` while proving as `from`.
///
/// gRPC uses the peer's current lease URL and DID. SLIM uses a distinct
/// local name (`…-a2a-client`) so this process does not subscribe as its
/// own listener (`…-a2a`) and deadlock.
fn dispatch_peer_handoff(
    from: &str,
    to: &str,
    slim_fallback: Option<&str>,
    inbound_prompt: &str,
    reply: &str,
    mediation: Option<Arc<dyn MediationHook>>,
    observer: Option<Arc<dyn ResponseObserver>>,
) -> Result<(), String> {
    let registry = LocalAdapterRegistry::from_env();
    let target = resolve_handoff_target(to, slim_fallback, &registry)?;
    let adapter = LiveA2ATaskAdapter::new(LiveA2ATaskAdapterConfig {
        endpoint: target.slim_endpoint.clone().unwrap_or_default(),
        agent_id: from.to_string(),
        local_name: Some(format!("agntcy/shadi/{from}-a2a-client")),
        peer_agent_id: target.peer_agent_id.clone(),
        destination: Some(format!("agntcy/shadi/{}-a2a", target.peer_agent_id)),
        a2a_url: target.a2a_url,
        a2a_binding: target.a2a_binding,
        peer_did: target.peer_did,
    });
    let adapter = match mediation {
        Some(hook) => adapter.with_mediation(hook),
        None => adapter,
    };
    let adapter = match observer {
        Some(observer) => adapter.with_observer(observer),
        None => adapter,
    };
    let prompt = render_peer_handoff(from, to, inbound_prompt, reply);
    adapter.dispatch(TaskEnvelope {
        task_id: format!("next-{}", uuid::Uuid::new_v4()),
        pattern: PatternKind::Development,
        epoch: Epoch(0),
        correlation_id: Some(format!("agentbridge-next-{from}-{to}")),
        body: prompt.into_bytes(),
    })
}

#[async_trait]
impl AgentExecutor for AgentBridgeExecutor {
    fn execute(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        // Admission happens here rather than in send_message so the task the
        // client is told about is one the task store knows: the handler has
        // already created it by the time the executor runs, so a parked task
        // can be fetched, cancelled and resumed like any other.
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        if let Some(message) = ctx.message.as_ref() {
            if let Some(reason) = wrong_destination_reason(self.agent_did.as_deref(), message) {
                return terminal_task(task_id, context_id, TaskState::Rejected, reason);
            }
        }
        let (raw, sender_did) = match ctx.message.as_ref().map(admit_message) {
            Some(MessageAdmission::Proven {
                did,
                human_did,
                payload,
            }) => {
                match &human_did {
                    Some(human) => tracing::info!(
                        %did, %human,
                        "admitted A2A message from an agent bound to a human"
                    ),
                    None => tracing::info!(%did, "admitted A2A message with proven agent DID"),
                }
                (payload, Some(did))
            }
            Some(MessageAdmission::AuthRequired { reason }) => {
                // Non-terminal: the client re-proves and sends again with this
                // task id, and the stored task carries on from here.
                return terminal_task(task_id, context_id, TaskState::AuthRequired, reason);
            }
            Some(MessageAdmission::Forged { reason }) => {
                return terminal_task(task_id, context_id, TaskState::Rejected, reason);
            }
            None if self.mediation.is_some() => {
                return terminal_task(
                    task_id,
                    context_id,
                    TaskState::Rejected,
                    "mediation requires a verified message".into(),
                );
            }
            None => ("(no prompt)".to_string(), None),
        };

        let mediation = self.mediation.clone();
        let mediation_request = ctx.message.as_ref().map(|message| MediationRequest {
            evaluation_id: format!("receiver-{}", message.message_id),
            point: MediationPoint::Receiver,
            message_id: message.message_id.clone(),
            task_id: Some(task_id.clone()),
            correlation_id: message
                .metadata
                .as_ref()
                .and_then(|m| m.get("shadi-correlation-id"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            local_agent: self.adapter.agent_id().0.clone(),
            peer: sender_did.clone(),
            verified_sender_did: sender_did,
            payload: Some(raw.clone()),
        });

        // Extract the body from the task envelope rendered by render_task_message().
        let prompt = raw
            .split_once("\nbody:\n")
            .map(|(_, body)| body)
            .unwrap_or(&raw)
            .to_string();

        let agent_id = self.adapter.agent_id().0.clone();
        println!("\n┌─ A2A recv [{agent_id}] task {}", ctx.task_id);
        print_body(&prompt, 120, self.verbose);
        println!("└─────────────────────────────────────────────────────────");

        let adapter = Arc::clone(&self.adapter);
        let slim_endpoint = self.slim_endpoint.clone();
        let verbose = self.verbose;
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        let history = ctx.message.clone().map(|m| vec![m]);
        let inbound_prompt = prompt.clone();

        let observation_request = mediation_request.clone();
        let observer = self.observer.clone();
        let handoff_observer = observer.clone();
        let response_started = std::time::Instant::now();
        let execution_error = Arc::new(std::sync::OnceLock::new());
        let captured_error = execution_error.clone();
        let respond = async move {
            if let (Some(hook), Some(request)) = (&mediation, &mediation_request) {
                if let Err(failure) = require_allow(hook.as_ref(), request).await {
                    let state = match failure {
                        MediationFailure::Denied(_) => TaskState::Rejected,
                        MediationFailure::Unavailable(_) => TaskState::Failed,
                    };
                    return terminal_task(task_id, context_id, state, failure.to_string())
                        .collect::<Vec<_>>()
                        .await;
                }
            }
            let started = std::time::Instant::now();
            let response_text = if is_peer_handoff_packet(&prompt) {
                // Do not run the coding CLI on a peer handoff. The last run
                // asked the model to "acknowledge" empty context; Claude
                // died on stdin and Copilot said no files were shared.
                format!("stored handoff ({})", preview(&prompt, 80))
            } else {
                let prompt_for_cli = prompt;
                let conversation = context_id.clone();
                match tokio::task::spawn_blocking(move || {
                    adapter.execute_prompt_in(&conversation, &prompt_for_cli)
                })
                .await
                {
                    Ok(Ok(text)) => text,
                    Ok(Err(e)) => {
                        let _ = captured_error.set(e.to_string());
                        format!("agentbridge error: {e}")
                    }
                    Err(join_err) => {
                        let _ = captured_error.set(join_err.to_string());
                        format!("agentbridge error: adapter task panicked: {join_err}")
                    }
                }
            };
            let elapsed_ms = started.elapsed().as_millis();

            println!("\n┌─ A2A send [{agent_id}] ({} ms)", elapsed_ms);
            print_body(&response_text, 120, verbose);
            println!("└─────────────────────────────────────────────────────────\n");

            if let Some(peer) = next_peer_to_forward(&agent_id, &inbound_prompt, &response_text) {
                let from = agent_id.clone();
                let to = peer.clone();
                let inbound = inbound_prompt.clone();
                let reply = response_text.clone();
                let slim_fallback = slim_endpoint.clone();
                let forwarded = tokio::task::spawn_blocking(move || {
                    dispatch_peer_handoff(
                        &from,
                        &to,
                        slim_fallback.as_deref(),
                        &inbound,
                        &reply,
                        mediation,
                        handoff_observer,
                    )
                })
                .await;
                match forwarded {
                    Ok(Ok(())) => println!(
                        "┌─ A2A client [{agent_id}] → {peer}\n│  NEXT dispatched by this listener\n└─────────────────────────────────────────────────────────\n"
                    ),
                    Ok(Err(err)) => println!(
                        "┌─ A2A client [{agent_id}] → {peer}\n│  dispatch failed: {err}\n└─────────────────────────────────────────────────────────\n"
                    ),
                    Err(join_err) => println!(
                        "┌─ A2A client [{agent_id}] → {peer}\n│  dispatch panicked: {join_err}\n└─────────────────────────────────────────────────────────\n"
                    ),
                }
            }

            let response = Message {
                message_id: new_message_id(),
                context_id: Some(context_id.clone()),
                task_id: Some(task_id.clone()),
                role: Role::Agent,
                parts: vec![Part::text(response_text)],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            };

            vec![
                Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                    task_id: task_id.clone(),
                    context_id: context_id.clone(),
                    status: TaskStatus {
                        state: TaskState::Working,
                        message: None,
                        timestamp: None,
                    },
                    metadata: None,
                })),
                Ok(StreamResponse::Task(Task {
                    id: task_id,
                    context_id,
                    status: TaskStatus {
                        state: TaskState::Completed,
                        message: Some(response),
                        timestamp: None,
                    },
                    artifacts: None,
                    history,
                    metadata: None,
                })),
            ]
        };

        Box::pin(
            futures::stream::once(respond)
                .flat_map(futures::stream::iter)
                .map(move |event| {
                    if let (Some(observer), Some(request), Ok(StreamResponse::Task(task))) =
                        (&observer, &observation_request, &event)
                    {
                        let mut observation = ResponseObservation::new(
                            ResponseEvent::Produced,
                            request,
                            response_started.elapsed(),
                            Ok(&SendMessageResponse::Task(task.clone())),
                        );
                        if let Some(error) = execution_error.get() {
                            observation.error = Some(error.chars().take(4096).collect());
                            observation.truncated |= error.chars().count() > 4096;
                        }
                        publish(observer.as_ref(), observation);
                    }
                    event
                }),
        )
    }

    fn cancel(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        Box::pin(futures::stream::once(async move {
            Ok(StreamResponse::Task(Task {
                id: ctx.task_id,
                context_id: ctx.context_id,
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            }))
        }))
    }
}

fn terminal_task(
    task_id: String,
    context_id: String,
    state: TaskState,
    reason: String,
) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
    let task = Task {
        id: task_id,
        context_id,
        status: TaskStatus {
            state,
            message: Some(Message::new(Role::Agent, vec![Part::text(reason)])),
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    Box::pin(futures::stream::once(async move {
        Ok(StreamResponse::Task(task))
    }))
}

/// Admission decided from the message alone, so the executor can reach it.
enum MessageAdmission {
    Proven {
        did: String,
        /// The human this agent is bound to, when the message carried a
        /// binding certificate. `None` means the agent proved only itself.
        human_did: Option<String>,
        payload: String,
    },
    AuthRequired {
        reason: String,
    },
    Forged {
        reason: String,
    },
}

/// Human DIDs whose agents this listener admits, from
/// `SHADI_MEMBER_HUMAN_DIDS`.
///
/// Unset means bindings stay optional: one that is present is still verified,
/// but an agent may prove only itself, which is the behaviour before bindings
/// existed. Set, and every message must carry a binding from a listed human.
fn allowed_human_dids() -> Vec<String> {
    std::env::var("SHADI_MEMBER_HUMAN_DIDS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Application-layer gate: the payload must be signed by the claimed agent DID.
///
/// A mesh member that presents another agent's DID fails here — the public key
/// comes from the claimed `did:key`, not from the caller.
fn admit_message(message: &Message) -> MessageAdmission {
    let text = extract_text(message);
    if text == "(no text parts)" || !shadi_identity::looks_like_did_proof(text.as_bytes()) {
        return MessageAdmission::AuthRequired {
            reason: "DID proof required on the message".to_string(),
        };
    }
    let verified = match shadi_identity::unwrap_signed_message(text.as_bytes()) {
        Ok(verified) => verified,
        Err(shadi_identity::IdentityError::Proof(msg)) if msg.contains("forged DID") => {
            return MessageAdmission::Forged { reason: msg };
        }
        Err(_) => {
            return MessageAdmission::AuthRequired {
                reason: "DID proof required on the message".to_string(),
            };
        }
    };
    admit_binding(
        verified.did,
        &verified.payload,
        &allowed_human_dids(),
        now_unix(),
    )
}

/// Second gate: whose agent is this?
///
/// The binding rides inside the agent's own signed payload, so a peer cannot
/// attach one the agent did not carry. It is checked against the agent DID the
/// outer proof established — presenting another agent's certificate fails.
fn admit_binding(
    did: String,
    payload: &[u8],
    allowed_humans: &[String],
    now: u64,
) -> MessageAdmission {
    if !shadi_identity::looks_like_binding(payload) {
        if allowed_humans.is_empty() {
            return MessageAdmission::Proven {
                did,
                human_did: None,
                payload: String::from_utf8_lossy(payload).into_owned(),
            };
        }
        return MessageAdmission::AuthRequired {
            reason: "agent binding required: this listener admits agents by human DID".to_string(),
        };
    }

    let (certificate, rest) = match shadi_identity::split_binding(payload) {
        Ok(split) => split,
        Err(err) => {
            return MessageAdmission::AuthRequired {
                reason: format!("agent binding is malformed: {err}"),
            };
        }
    };
    let binding = match shadi_identity::verify_binding(certificate, now) {
        Ok(binding) => binding,
        Err(err) => {
            return MessageAdmission::Forged {
                reason: format!("agent binding rejected: {err}"),
            };
        }
    };
    if binding.agent_did != did {
        return MessageAdmission::Forged {
            reason: format!(
                "agent binding is for {}, but the message was signed by {did}",
                binding.agent_did
            ),
        };
    }
    if !allowed_humans.is_empty() && !allowed_humans.iter().any(|h| *h == binding.human_did) {
        return MessageAdmission::Forged {
            reason: format!(
                "human {} is not admitted by this listener",
                binding.human_did
            ),
        };
    }

    tracing::info!(agent = %did, human = %binding.human_did, "admitted a bound agent");
    MessageAdmission::Proven {
        did,
        human_did: Some(binding.human_did),
        payload: String::from_utf8_lossy(rest).into_owned(),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The URL is not the name. If the caller addressed a DID, only that agent
/// may execute — even when several agents are reachable at the same locator.
fn wrong_destination_reason(listener_did: Option<&str>, message: &Message) -> Option<String> {
    let dest = shadi_a2a::dest_did_from_message(message)?;
    match listener_did {
        Some(mine) if mine == dest => None,
        Some(mine) => Some(format!(
            "destination DID {dest} is not this agent ({mine}); URL is only a locator"
        )),
        None => Some(format!(
            "destination DID {dest} set but this listener has no agent DID"
        )),
    }
}

fn extract_text(message: &Message) -> String {
    let text = message
        .parts
        .iter()
        .filter_map(Part::as_text)
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        "(no text parts)".to_string()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_registry::LocalAdapterRecord;
    use a2a_server::{DefaultRequestHandler, InMemoryTaskStore, RequestHandler, ServiceParams};
    use shadi_mas::mediation::MediationDecision;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use std::{fs, path::PathBuf};

    struct CountAdapter(shadi_mas::AgentId, Arc<AtomicUsize>);
    impl CliAdapter for CountAdapter {
        fn agent_id(&self) -> &shadi_mas::AgentId {
            &self.0
        }
        fn snapshot_context(&self) -> Result<crate::ContextPacket, crate::CliAdapterError> {
            unreachable!()
        }
        fn inject_context(&self, _: &crate::ContextPacket) -> Result<(), crate::CliAdapterError> {
            unreachable!()
        }
        fn execute_prompt(&self, _: &str) -> Result<String, crate::CliAdapterError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            assert_ne!(self.0 .0, "panicking", "adapter panicked");
            if self.0 .0 == "broken" {
                return Err(crate::CliAdapterError::Protocol("execution failed".into()));
            }
            Ok("executed".into())
        }
    }
    struct TestHook {
        answer: Result<MediationDecision, String>,
        seen: Mutex<Vec<MediationRequest>>,
    }
    #[derive(Default)]
    struct TestObserver(Mutex<Vec<ResponseObservation>>);
    impl ResponseObserver for TestObserver {
        fn observe(&self, observation: ResponseObservation) {
            self.0.lock().unwrap().push(observation);
        }
    }
    impl MediationHook for TestHook {
        fn evaluate<'a>(
            &'a self,
            request: &'a MediationRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<MediationDecision, String>> + Send + 'a>,
        > {
            self.seen.lock().unwrap().push(request.clone());
            Box::pin(std::future::ready(self.answer.clone()))
        }
    }
    #[tokio::test]
    async fn mediation_gates_execution_and_preserves_terminal_tasks() {
        let id = shadi_identity::AgentIdentity::generate().unwrap();
        for (answer, state, calls) in [
            (Ok(MediationDecision::Allow {}), TaskState::Completed, 1),
            (
                Ok(MediationDecision::Deny {
                    reason: "policy".into(),
                }),
                TaskState::Rejected,
                0,
            ),
            (Err("offline".into()), TaskState::Failed, 0),
        ] {
            let counter = Arc::new(AtomicUsize::new(0));
            let observer = Arc::new(TestObserver::default());
            let hook = Arc::new(TestHook {
                answer,
                seen: Mutex::new(Vec::new()),
            });
            let executor = AgentBridgeExecutor::new(
                Arc::new(CountAdapter(
                    shadi_mas::AgentId("b".into()),
                    counter.clone(),
                )),
                None,
                None,
                false,
            )
            .with_mediation(hook.clone())
            .with_observer(observer.clone());
            let handler = DefaultRequestHandler::new(executor, InMemoryTaskStore::new());
            let text = String::from_utf8(
                shadi_identity::wrap_signed_message(&id, b"verified prompt").unwrap(),
            )
            .unwrap();
            let mut request = sample_request(text);
            request.message.metadata = Some(
                serde_json::from_value(serde_json::json!({
                    "shadi-correlation-id": "correlated-task"
                }))
                .unwrap(),
            );
            let message_id = request.message.message_id.clone();
            let params = ServiceParams::default();
            let SendMessageResponse::Task(task) =
                handler.send_message(&params, request).await.unwrap()
            else {
                panic!("expected stored task")
            };
            assert_eq!(task.status.state, state);
            assert_eq!(counter.load(Ordering::SeqCst), calls);
            let observations = observer.0.lock().unwrap();
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].request_message_id, message_id);
            assert_eq!(
                observations[0].correlation_id.as_deref(),
                Some("correlated-task")
            );
            assert_eq!(observations[0].event, ResponseEvent::Produced);
            assert_eq!(observations[0].task_state, Some(state.clone()));
            assert_eq!(
                observations[0].response_message_id.as_deref(),
                task.status.message.as_ref().map(|m| m.message_id.as_str())
            );
            let stored = handler
                .get_task(
                    &params,
                    GetTaskRequest {
                        id: task.id,
                        history_length: None,
                        tenant: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(stored.status.state, state);
            let seen = hook.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].payload.as_deref(), Some("verified prompt"));
            assert_eq!(
                seen[0].verified_sender_did.as_deref(),
                Some(id.did().as_str())
            );
            assert_eq!(seen[0].message_id, message_id);
        }
    }

    #[tokio::test]
    async fn response_observation_records_execution_error_without_changing_the_reply() {
        for (adapter_id, expected_error) in
            [("broken", "execution failed"), ("panicking", "panicked")]
        {
            let id = shadi_identity::AgentIdentity::generate().unwrap();
            let observer = Arc::new(TestObserver::default());
            let handler = DefaultRequestHandler::new(
                AgentBridgeExecutor::new(
                    Arc::new(CountAdapter(
                        shadi_mas::AgentId(adapter_id.into()),
                        Arc::new(AtomicUsize::new(0)),
                    )),
                    None,
                    None,
                    false,
                )
                .with_observer(observer.clone()),
                InMemoryTaskStore::new(),
            );
            let text =
                String::from_utf8(shadi_identity::wrap_signed_message(&id, b"prompt").unwrap())
                    .unwrap();
            let SendMessageResponse::Task(task) = handler
                .send_message(&ServiceParams::default(), sample_request(text))
                .await
                .unwrap()
            else {
                panic!("expected task")
            };
            // Preserve the executor's existing wire result; only add telemetry.
            assert_eq!(task.status.state, TaskState::Completed);
            let events = observer.0.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert!(events[0].error.as_ref().unwrap().contains(expected_error));
            assert!(events[0]
                .response
                .as_ref()
                .unwrap()
                .starts_with("agentbridge error:"));
        }
    }

    #[tokio::test]
    async fn unverified_messages_never_reach_mediation() {
        let counter = Arc::new(AtomicUsize::new(0));
        let hook = Arc::new(TestHook {
            answer: Ok(MediationDecision::Allow {}),
            seen: Mutex::new(Vec::new()),
        });
        let handler = DefaultRequestHandler::new(
            AgentBridgeExecutor::new(
                Arc::new(CountAdapter(
                    shadi_mas::AgentId("b".into()),
                    counter.clone(),
                )),
                None,
                None,
                false,
            )
            .with_mediation(hook.clone()),
            InMemoryTaskStore::new(),
        );
        let id = shadi_identity::AgentIdentity::generate().unwrap();
        let signed = |payload: &[u8]| {
            String::from_utf8(shadi_identity::wrap_signed_message(&id, payload).unwrap()).unwrap()
        };
        let mut wrong_destination = sample_request(signed(b"prompt"));
        wrong_destination.message =
            shadi_a2a::insert_dest_did(wrong_destination.message, "did:key:zOther");
        for (request, state) in [
            (sample_request("unsigned"), TaskState::AuthRequired),
            (
                sample_request("SHADI-DID-PROOF/1\ninvalid"),
                TaskState::AuthRequired,
            ),
            (
                sample_request(signed(b"SHADI-AGENT-BINDING/1\ninvalid")),
                TaskState::AuthRequired,
            ),
            (
                sample_request(
                    String::from_utf8(bound_envelope(&id, &id, "b", 1, b"expired")).unwrap(),
                ),
                TaskState::Rejected,
            ),
            (wrong_destination, TaskState::Rejected),
        ] {
            let SendMessageResponse::Task(task) = handler
                .send_message(&ServiceParams::default(), request)
                .await
                .unwrap()
            else {
                panic!("expected admission task")
            };
            assert_eq!(task.status.state, state);
        }
        assert!(hook.seen.lock().unwrap().is_empty());
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    fn empty_context() -> a2a_server::ExecutorContext {
        a2a_server::ExecutorContext {
            message: None,
            task_id: "task".into(),
            stored_task: None,
            context_id: "context".into(),
            metadata: None,
            user: None,
            service_params: Default::default(),
            tenant: None,
        }
    }

    #[tokio::test]
    async fn missing_message_is_rejected_only_when_mediation_is_configured() {
        let counter = Arc::new(AtomicUsize::new(0));
        let executor = AgentBridgeExecutor::new(
            Arc::new(CountAdapter(
                shadi_mas::AgentId("b".into()),
                counter.clone(),
            )),
            None,
            None,
            true,
        );
        let events = executor.execute(empty_context()).collect::<Vec<_>>().await;
        assert!(
            matches!(&events[1], Ok(StreamResponse::Task(task)) if task.status.state == TaskState::Completed)
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        let hook = Arc::new(TestHook {
            answer: Ok(MediationDecision::Allow {}),
            seen: Mutex::new(Vec::new()),
        });
        let executor = executor.with_mediation(hook.clone());
        let events = executor.execute(empty_context()).collect::<Vec<_>>().await;
        assert!(
            matches!(&events[0], Ok(StreamResponse::Task(task)) if task.status.state == TaskState::Rejected)
        );
        assert!(hook.seen.lock().unwrap().is_empty());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        let events = executor.cancel(empty_context()).collect::<Vec<_>>().await;
        assert!(
            matches!(&events[0], Ok(StreamResponse::Task(task)) if task.status.state == TaskState::Canceled && task.id == "task" && task.context_id == "context")
        );
    }

    #[tokio::test]
    async fn bound_handoff_is_gated_but_does_not_execute_the_adapter() {
        let identity = shadi_identity::AgentIdentity::generate().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let hook = Arc::new(TestHook {
            answer: Ok(MediationDecision::Allow {}),
            seen: Mutex::new(Vec::new()),
        });
        let handler = DefaultRequestHandler::new(
            AgentBridgeExecutor::new(
                Arc::new(CountAdapter(
                    shadi_mas::AgentId("b".into()),
                    counter.clone(),
                )),
                None,
                None,
                false,
            )
            .with_mediation(hook.clone()),
            InMemoryTaskStore::new(),
        );
        let prompt = b"envelope\nbody:\nHANDOFF from a to b\nupdated context";
        let signed = bound_envelope(&identity, &identity, "a", now_unix() + 60, prompt);
        let SendMessageResponse::Task(task) = handler
            .send_message(
                &ServiceParams::default(),
                sample_request(String::from_utf8(signed).unwrap()),
            )
            .await
            .unwrap()
        else {
            panic!("expected handoff task")
        };
        assert_eq!(task.status.state, TaskState::Completed);
        assert!(extract_text(task.status.message.as_ref().unwrap()).starts_with("stored handoff"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        let seen = hook.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].payload.as_deref(),
            Some(std::str::from_utf8(prompt).unwrap())
        );
    }

    #[test]
    fn peer_handoff_inherits_sender_mediation_before_connecting() {
        let _guard = crate::env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("SHADI_TMP_DIR");
        std::env::set_var("SHADI_TMP_DIR", dir.path());
        let registry = LocalAdapterRegistry::from_env();
        let _lease = registry
            .publish(&handoff_record(
                "b",
                "did:key:zPeer",
                "",
                "http://127.0.0.1:9",
            ))
            .unwrap();
        let hook = Arc::new(TestHook {
            answer: Ok(MediationDecision::Deny {
                reason: "handoff denied".into(),
            }),
            seen: Mutex::new(Vec::new()),
        });
        let observer = Arc::new(TestObserver::default());
        let result = dispatch_peer_handoff(
            "a",
            "b",
            None,
            "prompt",
            "reply",
            Some(hook.clone()),
            Some(observer.clone()),
        );
        match previous {
            Some(value) => std::env::set_var("SHADI_TMP_DIR", value),
            None => std::env::remove_var("SHADI_TMP_DIR"),
        }
        assert!(result.unwrap_err().contains("handoff denied"));
        let seen = hook.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].point, MediationPoint::Sender);
        assert_eq!(seen[0].local_agent, "a");
        assert_eq!(seen[0].peer.as_deref(), Some("did:key:zPeer"));
        assert!(observer.0.lock().unwrap().is_empty());
    }
    fn sample_request(text: impl Into<String>) -> SendMessageRequest {
        SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text(text.into())]),
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }
    #[test]
    fn preview_truncates_to_first_nonblank_line() {
        assert_eq!(preview("\n\nhello world", 5), "hello…");
        assert_eq!(preview("short", 20), "short");
        assert_eq!(preview("été", 1), "…");
    }

    #[test]
    fn parse_next_peer_reads_last_next_and_ignores_done() {
        assert_eq!(
            parse_next_peer("REPLACE 5\nv\nNEXT copilot\n").as_deref(),
            Some("copilot")
        );
        assert_eq!(parse_next_peer("REPLACE 5\nv\nDONE\n"), None);
        assert_eq!(
            parse_next_peer("NEXT copilot\nNEXT cursor-agent\n").as_deref(),
            Some("cursor-agent")
        );
        assert_eq!(
            parse_next_peer("agentbridge error: boom\nNEXT copilot"),
            None
        );
    }

    #[test]
    fn next_peer_to_forward_is_opt_in_and_allow_listed() {
        let _guard = crate::env_lock().lock().unwrap();
        let prev_fwd = std::env::var("AGENTBRIDGE_A2A_FORWARD").ok();
        let prev_peers = std::env::var("AGENTBRIDGE_A2A_PEERS").ok();
        std::env::remove_var("AGENTBRIDGE_A2A_FORWARD");
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT copilot"),
            None
        );
        std::env::set_var("AGENTBRIDGE_A2A_FORWARD", "1");
        std::env::set_var("AGENTBRIDGE_A2A_PEERS", "claude-code,copilot,codex");
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT copilot").as_deref(),
            Some("copilot")
        );
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT claude-code"),
            None
        );
        assert_eq!(
            next_peer_to_forward("claude-code", "coding hop", "NEXT unknown"),
            None
        );
        assert_eq!(
            next_peer_to_forward(
                "claude-code",
                "You are continuing a coding session from copilot.",
                "NEXT codex"
            ),
            None
        );
        assert_eq!(
            next_peer_to_forward(
                "claude-code",
                "HANDOFF from copilot to claude-code\nDo not write Rust.",
                "NEXT codex"
            ),
            None
        );
        match prev_fwd {
            Some(v) => std::env::set_var("AGENTBRIDGE_A2A_FORWARD", v),
            None => std::env::remove_var("AGENTBRIDGE_A2A_FORWARD"),
        }
        match prev_peers {
            Some(v) => std::env::set_var("AGENTBRIDGE_A2A_PEERS", v),
            None => std::env::remove_var("AGENTBRIDGE_A2A_PEERS"),
        }
    }

    #[test]
    fn render_peer_handoff_shares_reply_file_and_tests() {
        let inbound = "\
You are claude-code on hop 1
GOAL: implement Fifo
HARD RULE: two lines
Current src/lib.rs:
 1| pub fn push() {}
Last cargo test:
test push ... FAILED
";
        let text = render_peer_handoff(
            "claude-code",
            "codex",
            inbound,
            "REPLACE 11\nself.items.push(_item);\nNEXT codex",
        );
        assert!(text.starts_with("HANDOFF from claude-code to codex"));
        assert!(text.contains("REPLACE 11"));
        assert!(text.contains("self.items.push(_item)"));
        assert!(text.contains("implement Fifo"));
        assert!(text.contains("pub fn push() {}"));
        assert!(text.contains("test push ... FAILED"));
        assert!(!text.contains("Acknowledge"));
    }

    #[test]
    fn wrong_destination_did_is_rejected_even_on_the_same_url() {
        let message = shadi_a2a::insert_dest_did(
            Message::new(Role::User, vec![Part::text("task".to_string())]),
            "did:key:zOther",
        );
        let reason = wrong_destination_reason(Some("did:key:zMine"), &message).expect("mismatch");
        assert!(reason.contains("did:key:zOther"), "{reason}");
        assert!(reason.contains("locator"), "{reason}");
        assert!(wrong_destination_reason(Some("did:key:zOther"), &message).is_none());
        let unlabeled = Message::new(Role::User, vec![Part::text("task".to_string())]);
        assert!(wrong_destination_reason(Some("did:key:zMine"), &unlabeled).is_none());
        let unlabeled_reason =
            wrong_destination_reason(None, &message).expect("dest DID with no listener DID");
        assert!(
            unlabeled_reason.contains("no agent DID"),
            "{unlabeled_reason}"
        );
    }

    fn scratch_registry() -> (PathBuf, LocalAdapterRegistry) {
        let dir = std::env::temp_dir().join(format!(
            "ab-handoff-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        (dir.clone(), LocalAdapterRegistry::with_dir(dir))
    }

    fn handoff_record(name: &str, did: &str, slim: &str, url: &str) -> LocalAdapterRecord {
        LocalAdapterRecord {
            name: name.to_string(),
            did: did.to_string(),
            slim_endpoint: slim.to_string(),
            a2a_url: url.to_string(),
            a2a_binding: A2ABinding::Grpc,
            pid: std::process::id(),
        }
    }

    #[test]
    fn resolve_handoff_target_prefers_grpc_url_from_lease() {
        let (dir, registry) = scratch_registry();
        let _lease = registry
            .publish(&handoff_record(
                "copilot",
                "did:key:zCopilot",
                "127.0.0.1:47357",
                "http://127.0.0.1:50151",
            ))
            .unwrap();
        let target =
            resolve_handoff_target("copilot", Some("127.0.0.1:9"), &registry).expect("lease");
        assert_eq!(target.peer_agent_id, "copilot");
        assert_eq!(target.peer_did.as_deref(), Some("did:key:zCopilot"));
        assert_eq!(target.a2a_url.as_deref(), Some("http://127.0.0.1:50151"));
        assert_eq!(target.slim_endpoint.as_deref(), Some("127.0.0.1:47357"));
        let by_did = resolve_handoff_target("did:key:zCopilot", None, &registry).expect("did");
        assert_eq!(by_did.a2a_url, target.a2a_url);
        drop(_lease);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_handoff_target_uses_grpc_only_lease_without_slim() {
        let (dir, registry) = scratch_registry();
        let _lease = registry
            .publish(&handoff_record(
                "codex",
                "did:key:zCodex",
                "",
                "http://127.0.0.1:50152",
            ))
            .unwrap();
        let target = resolve_handoff_target("codex", None, &registry).expect("grpc-only");
        assert_eq!(target.a2a_url.as_deref(), Some("http://127.0.0.1:50152"));
        assert_eq!(target.slim_endpoint, None);
        drop(_lease);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_handoff_target_falls_back_to_slim_when_peer_is_unlisted() {
        let (dir, registry) = scratch_registry();
        let target = resolve_handoff_target("claude-code", Some("127.0.0.1:47357"), &registry)
            .expect("slim fallback");
        assert_eq!(target.peer_agent_id, "claude-code");
        assert_eq!(target.a2a_url, None);
        assert_eq!(target.slim_endpoint.as_deref(), Some("127.0.0.1:47357"));
        let err = resolve_handoff_target("claude-code", None, &registry).unwrap_err();
        assert!(err.contains("list --local"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    fn bound_envelope(
        human: &shadi_identity::AgentIdentity,
        agent: &shadi_identity::AgentIdentity,
        name: &str,
        not_after: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut inner = shadi_identity::issue_binding(human, &agent.did(), name, not_after)
            .expect("issue binding");
        inner.push(b'\n');
        inner.extend_from_slice(payload);
        shadi_identity::wrap_signed_message(agent, &inner).expect("wrap")
    }

    const BIND_NOW: u64 = 1_700_000_000;

    #[test]
    fn a_bound_agent_is_admitted_and_reports_its_human() {
        let human = shadi_identity::AgentIdentity::generate().unwrap();
        let agent = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = bound_envelope(&human, &agent, "claude-code", BIND_NOW + 60, b"real prompt");
        let verified = shadi_identity::unwrap_signed_message(&envelope).unwrap();

        match admit_binding(verified.did, &verified.payload, &[human.did()], BIND_NOW) {
            MessageAdmission::Proven {
                did,
                human_did,
                payload,
            } => {
                assert_eq!(did, agent.did());
                assert_eq!(human_did.as_deref(), Some(human.did().as_str()));
                assert_eq!(payload, "real prompt");
            }
            _ => panic!("a bound agent from an admitted human must be accepted"),
        }
    }

    #[test]
    fn a_binding_for_a_different_agent_is_rejected() {
        let human = shadi_identity::AgentIdentity::generate().unwrap();
        let agent = shadi_identity::AgentIdentity::generate().unwrap();
        let other = shadi_identity::AgentIdentity::generate().unwrap();

        // A real certificate for `other`, replayed by `agent` inside its own
        // signed payload.
        let mut inner =
            shadi_identity::issue_binding(&human, &other.did(), "copilot", BIND_NOW + 60).unwrap();
        inner.push(b'\n');
        inner.extend_from_slice(b"prompt");
        let envelope = shadi_identity::wrap_signed_message(&agent, &inner).unwrap();
        let verified = shadi_identity::unwrap_signed_message(&envelope).unwrap();

        match admit_binding(verified.did, &verified.payload, &[human.did()], BIND_NOW) {
            MessageAdmission::Forged { reason } => {
                assert!(
                    reason.contains("was signed by"),
                    "rejection should name the signing agent"
                );
            }
            _ => panic!("replaying another agent's binding must be refused"),
        }
    }

    #[test]
    fn a_binding_from_an_unlisted_human_is_rejected() {
        let stranger = shadi_identity::AgentIdentity::generate().unwrap();
        let admitted = shadi_identity::AgentIdentity::generate().unwrap();
        let agent = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = bound_envelope(&stranger, &agent, "claude-code", BIND_NOW + 60, b"p");
        let verified = shadi_identity::unwrap_signed_message(&envelope).unwrap();

        match admit_binding(verified.did, &verified.payload, &[admitted.did()], BIND_NOW) {
            MessageAdmission::Forged { reason } => {
                assert!(
                    reason.contains("not admitted"),
                    "rejection should say the human is not admitted"
                );
            }
            _ => panic!("an unlisted human must be refused"),
        }
    }

    #[test]
    fn an_expired_binding_is_rejected() {
        let human = shadi_identity::AgentIdentity::generate().unwrap();
        let agent = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = bound_envelope(&human, &agent, "claude-code", BIND_NOW - 1, b"p");
        let verified = shadi_identity::unwrap_signed_message(&envelope).unwrap();

        match admit_binding(verified.did, &verified.payload, &[human.did()], BIND_NOW) {
            MessageAdmission::Forged { reason } => {
                assert!(
                    reason.contains("expired"),
                    "rejection should say the binding expired"
                );
            }
            _ => panic!("an expired binding must be refused"),
        }
    }

    #[test]
    fn an_unbound_agent_is_admitted_only_while_no_human_is_listed() {
        let agent = shadi_identity::AgentIdentity::generate().unwrap();
        let human = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&agent, b"bare prompt").unwrap();
        let verified = shadi_identity::unwrap_signed_message(&envelope).unwrap();

        // No allow-list: today's behaviour, so this stays additive.
        match admit_binding(verified.did.clone(), &verified.payload, &[], BIND_NOW) {
            MessageAdmission::Proven {
                human_did, payload, ..
            } => {
                assert!(human_did.is_none());
                assert_eq!(payload, "bare prompt");
            }
            _ => panic!("an unbound agent must still be admitted when no human is listed"),
        }

        // Once humans are listed, proving only yourself is not enough.
        match admit_binding(verified.did, &verified.payload, &[human.did()], BIND_NOW) {
            MessageAdmission::AuthRequired { reason } => {
                assert!(
                    reason.contains("binding required"),
                    "challenge should ask for a binding"
                );
            }
            _ => panic!("an unbound agent must be challenged once humans are listed"),
        }
    }

    #[test]
    fn admit_unsigned_message_parks_auth_required() {
        match admit_message(&sample_request("plain task").message) {
            MessageAdmission::AuthRequired { reason } => {
                assert!(
                    reason.contains("DID proof required"),
                    "expected a DID proof challenge"
                );
            }
            MessageAdmission::Proven { .. } => panic!("unsigned text must not prove an identity"),
            MessageAdmission::Forged { .. } => panic!("unsigned text must be parked, not rejected"),
        }
    }

    #[test]
    fn admit_forged_did_is_rejected() {
        let honest = shadi_identity::AgentIdentity::generate().unwrap();
        let impostor = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&honest, b"task").unwrap();
        // Claim the impostor's DID while keeping the honest signature.
        let sig_line = {
            let text = String::from_utf8(envelope.clone()).unwrap();
            text.lines().nth(2).unwrap().to_string()
        };
        let forged = format!("SHADI-DID-PROOF/1\n{}\n{}\ntask", impostor.did(), sig_line);
        match admit_message(&sample_request(forged).message) {
            MessageAdmission::Forged { reason } => {
                assert!(
                    reason.contains("forged DID"),
                    "expected a forged DID rejection"
                );
            }
            MessageAdmission::AuthRequired { .. } => {
                panic!("forged DID must be rejected, not parked");
            }
            MessageAdmission::Proven { .. } => {
                panic!("forged DID must not prove an identity");
            }
        }
    }

    #[test]
    fn admit_honest_proof_unwraps_payload() {
        let id = shadi_identity::AgentIdentity::generate().unwrap();
        let envelope = shadi_identity::wrap_signed_message(&id, b"real prompt").unwrap();
        let text = String::from_utf8(envelope).unwrap();
        match admit_message(&sample_request(text).message) {
            MessageAdmission::Proven { did, payload, .. } => {
                assert_eq!(did, id.did());
                assert_eq!(payload, "real prompt");
            }
            _ => panic!("honest proof must be admitted"),
        }
    }

    #[test]
    fn extract_text_joins_parts_or_reports_empty() {
        let msg = Message::new(
            Role::User,
            vec![Part::text("a".to_string()), Part::text("b".to_string())],
        );
        assert_eq!(extract_text(&msg), "a b");
        let empty = Message::new(Role::User, vec![]);
        assert_eq!(extract_text(&empty), "(no text parts)");
    }
}
