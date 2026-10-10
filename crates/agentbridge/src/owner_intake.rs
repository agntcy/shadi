// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Agents ask a channel's owner over A2A to let someone in.
//!
//! A request is a `SHADI-CHANNEL-REQUEST/1` body, signed by the requesting
//! agent like any task, optionally behind the agent's human binding. The
//! owner's SHADI serves [`OwnerExecutor`] at [`owner_service_name`], decides
//! each request by its standing rules (see [`crate::owner`]), and answers
//! with one line. A granted request becomes an invite.

use std::sync::{Arc, Mutex};

use a2a::event::StreamResponse;
use a2a::*;
use a2a_server::{AgentExecutor, ExecutorContext};
use futures::stream::BoxStream;
use shadi_identity::GrantAction;

use crate::owner::{InviteRequest, Outcome, Owner};

const MAGIC: &str = "SHADI-CHANNEL-REQUEST/1";

/// The SLIM name an owner serves requests at, next to its own.
pub fn owner_service_name(owner_name: &str) -> String {
    format!("{owner_name}-owner")
}

/// The body an agent signs to ask for `invitee_name` (`invitee_did`) to be
/// let into `channel`.
pub fn render_request(channel: &str, invitee_name: &str, invitee_did: &str) -> String {
    format!("{MAGIC}\nchannel: {channel}\ninvitee: {invitee_name}\ninvitee_did: {invitee_did}")
}

/// Admit a request from the text a task carried: the DID proof names the
/// requester, and a binding inside it names the requester's human.
pub fn admit(signed: &[u8], now: u64) -> Result<InviteRequest, String> {
    if !shadi_identity::looks_like_did_proof(signed) {
        return Err("a channel request must carry the requester's DID proof".to_string());
    }
    let verified = shadi_identity::unwrap_signed_message(signed).map_err(|e| e.to_string())?;
    let (requester_human_did, payload) = if shadi_identity::looks_like_binding(&verified.payload) {
        let (certificate, rest) =
            shadi_identity::split_binding(&verified.payload).map_err(|e| e.to_string())?;
        let binding = shadi_identity::verify_binding(certificate, now)
            .map_err(|e| format!("agent binding rejected: {e}"))?;
        if binding.agent_did != verified.did {
            return Err(format!(
                "agent binding is for {}, but the request was signed by {}",
                binding.agent_did, verified.did
            ));
        }
        (Some(binding.human_did), rest.to_vec())
    } else {
        (None, verified.payload.clone())
    };
    let text = String::from_utf8(payload).map_err(|_| "request is not UTF-8".to_string())?;
    // A request sent as a task has the task header before its body.
    let body = text
        .split_once("\nbody:\n")
        .map_or(text.as_str(), |(_, body)| body);
    let (channel, invitee_name, invitee_did) = parse_request(body)?;
    Ok(InviteRequest {
        channel,
        invitee_name,
        invitee_did: Some(invitee_did),
        action: GrantAction::Add,
        requester: verified.did,
        requester_human_did,
    })
}

fn parse_request(body: &str) -> Result<(String, String, String), String> {
    let mut lines = body.lines();
    if lines.next() != Some(MAGIC) {
        return Err(format!("not a {MAGIC} request"));
    }
    let mut field = |key: &str| {
        lines
            .next()
            .and_then(|line| line.strip_prefix(key)?.strip_prefix(": "))
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("request is missing `{key}:`"))
    };
    let channel = field("channel")?;
    let invitee_name = field("invitee")?;
    let invitee_did = field("invitee_did")?;
    shadi_identity::parse_did_key(&invitee_did).map_err(|e| format!("invitee_did: {e}"))?;
    Ok((channel, invitee_name, invitee_did))
}

/// Sends the SLIM invite once the owner has signed a grant.
pub trait Inviter: Send + Sync {
    fn invite(&self, grant: &[u8], request: &InviteRequest) -> Result<(), String>;
}

/// Serves channel requests for one owner.
#[derive(Clone)]
pub struct OwnerExecutor {
    owner: Arc<Mutex<Owner>>,
    inviter: Arc<dyn Inviter>,
}

impl OwnerExecutor {
    pub fn new(owner: Arc<Mutex<Owner>>, inviter: Arc<dyn Inviter>) -> Self {
        Self { owner, inviter }
    }

    /// Decide one signed request, inviting when it is granted. Returns the
    /// state the requester's task ends in and the line it is told.
    pub fn handle(&self, signed: &[u8], now: u64) -> (TaskState, String) {
        let request = match admit(signed, now) {
            Ok(request) => request,
            Err(reason) => {
                tracing::warn!(%reason, "refused a channel request before the owner's policy");
                return (TaskState::Rejected, format!("refused: {reason}"));
            }
        };
        let outcome = self
            .owner
            .lock()
            .map_err(|_| "owner state is poisoned".to_string())
            .and_then(|mut owner| {
                owner
                    .request(request.clone(), now)
                    .map_err(|e| e.to_string())
            });
        match outcome {
            Ok(Outcome::Granted(grant)) => match self.inviter.invite(&grant, &request) {
                Ok(()) => (
                    TaskState::Completed,
                    format!(
                        "granted: {} invited to {}",
                        request.invitee_name, request.channel
                    ),
                ),
                Err(err) => (
                    TaskState::Failed,
                    format!("granted, but the invite failed: {err}"),
                ),
            },
            Ok(Outcome::Pending { ask_id, expires_at }) => (
                TaskState::Completed,
                format!("pending: the owner decides ask {ask_id} by {expires_at}"),
            ),
            Ok(Outcome::Refused(reason)) => (TaskState::Rejected, format!("refused: {reason}")),
            Err(err) => (TaskState::Failed, format!("error: {err}")),
        }
    }
}

impl AgentExecutor for OwnerExecutor {
    fn execute(
        &self,
        ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let text = ctx
            .message
            .as_ref()
            .map(|message| {
                let parts = message.parts.iter().filter_map(Part::as_text);
                parts.collect::<Vec<_>>().join("\n")
            })
            .unwrap_or_default();
        let executor = self.clone();
        Box::pin(futures::stream::once(async move {
            // Deciding may invite, and an invite blocks on SLIM's own runtime,
            // which can't be entered from an async worker.
            let decided =
                tokio::task::spawn_blocking(move || executor.handle(text.as_bytes(), now_unix()))
                    .await;
            let (state, reply) =
                decided.unwrap_or_else(|err| (TaskState::Failed, format!("error: {err}")));
            Ok(StreamResponse::Task(task(ctx, state, Some(reply))))
        }))
    }

    fn cancel(&self, ctx: ExecutorContext) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        task_stream(ctx, TaskState::Canceled, None)
    }
}

fn task_stream(
    ctx: ExecutorContext,
    state: TaskState,
    reply: Option<String>,
) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
    let task = task(ctx, state, reply);
    Box::pin(futures::stream::once(async move {
        Ok(StreamResponse::Task(task))
    }))
}

fn task(ctx: ExecutorContext, state: TaskState, reply: Option<String>) -> Task {
    Task {
        id: ctx.task_id,
        context_id: ctx.context_id,
        status: TaskStatus {
            state,
            message: reply.map(|text| Message::new(Role::Agent, vec![Part::text(text)])),
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::OwnerPolicy;
    use shadi_identity::{issue_binding, verify_grant, wrap_signed_message, AgentIdentity};

    const NOW: u64 = 1_700_000_000;
    const ROOM: &str = "agntcy/shadi/review-room";
    const PEER: &str = "agntcy/shadi/copilot";

    #[derive(Default)]
    struct Invites(Mutex<Vec<(Vec<u8>, InviteRequest)>>);

    impl Inviter for Invites {
        fn invite(&self, grant: &[u8], request: &InviteRequest) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((grant.to_vec(), request.clone()));
            Ok(())
        }
    }

    struct Failing;

    impl Inviter for Failing {
        fn invite(&self, _grant: &[u8], _request: &InviteRequest) -> Result<(), String> {
            Err("node unreachable".to_string())
        }
    }

    struct Setup {
        owner_did: String,
        agent: AgentIdentity,
        human: AgentIdentity,
        peer_did: String,
        executor: OwnerExecutor,
        invites: Arc<Invites>,
    }

    fn setup(policy: &str) -> Setup {
        let owner_key = AgentIdentity::generate().unwrap();
        let owner_did = owner_key.did();
        let mut owner = Owner::new(owner_key, OwnerPolicy::from_json(policy).unwrap(), None);
        owner.hold(ROOM);
        let invites = Arc::new(Invites::default());
        Setup {
            owner_did,
            agent: AgentIdentity::generate().unwrap(),
            human: AgentIdentity::generate().unwrap(),
            peer_did: AgentIdentity::generate().unwrap().did(),
            executor: OwnerExecutor::new(Arc::new(Mutex::new(owner)), invites.clone()),
            invites,
        }
    }

    fn signed(setup: &Setup, body: &str, bound: bool) -> Vec<u8> {
        let mut payload = Vec::new();
        if bound {
            payload =
                issue_binding(&setup.human, &setup.agent.did(), "claude-code", NOW + 60).unwrap();
            payload.push(b'\n');
        }
        payload.extend_from_slice(body.as_bytes());
        wrap_signed_message(&setup.agent, &payload).unwrap()
    }

    fn as_task(setup: &Setup, bound: bool) -> Vec<u8> {
        let body = render_request(ROOM, PEER, &setup.peer_did);
        signed(
            setup,
            &format!("task_id: t-1\npattern: Development\nepoch: 0\nbody:\n{body}"),
            bound,
        )
    }

    #[test]
    fn an_allowed_request_from_a_bound_agent_is_granted_and_invited() {
        let setup = setup("{}");
        let policy = format!(
            r#"{{"rules": [{{"channel": "*", "requested_by_human": "{}", "decision": "allow"}}]}}"#,
            setup.human.did()
        );
        setup
            .executor
            .owner
            .lock()
            .unwrap()
            .set_policy(OwnerPolicy::from_json(&policy).unwrap());

        let (state, reply) = setup.executor.handle(&as_task(&setup, true), NOW);
        assert_eq!(state, TaskState::Completed, "{reply}");
        assert_eq!(reply, format!("granted: {PEER} invited to {ROOM}"));

        let invites = setup.invites.0.lock().unwrap();
        let (grant, request) = &invites[0];
        assert_eq!(request.requester, setup.agent.did());
        assert_eq!(request.requester_human_did, Some(setup.human.did()));
        assert_eq!(
            (request.invitee_name.as_str(), &request.invitee_did),
            (PEER, &Some(setup.peer_did.clone()))
        );
        let grant = verify_grant(grant, &setup.owner_did, NOW).unwrap();
        assert_eq!(grant.invitee, PEER);
    }

    #[test]
    fn by_default_the_request_waits_for_the_owner() {
        let setup = setup("{}");
        let (state, reply) = setup.executor.handle(&as_task(&setup, false), NOW);
        assert_eq!(state, TaskState::Completed);
        assert!(
            reply.starts_with("pending: the owner decides ask 1 by "),
            "{reply}"
        );
        assert!(setup.invites.0.lock().unwrap().is_empty());
        assert_eq!(setup.executor.owner.lock().unwrap().pending().count(), 1);
    }

    #[test]
    fn a_blocked_request_or_a_failed_invite_is_reported() {
        let blocked = setup(r#"{"default": "block"}"#);
        let (state, reply) = blocked.executor.handle(&as_task(&blocked, false), NOW);
        assert_eq!(
            (state, reply.as_str()),
            (
                TaskState::Rejected,
                "refused: refused by the owner's policy"
            )
        );

        let mut failing = setup(r#"{"default": "allow"}"#);
        failing.executor.inviter = Arc::new(Failing);
        let (state, reply) = failing.executor.handle(&as_task(&failing, false), NOW);
        assert_eq!(state, TaskState::Failed);
        assert!(reply.contains("node unreachable"), "{reply}");
    }

    #[test]
    fn requests_that_prove_nothing_never_reach_the_policy() {
        let setup = setup(r#"{"default": "allow"}"#);
        let body = render_request(ROOM, PEER, &setup.peer_did);

        let impostor = AgentIdentity::generate().unwrap();
        let theirs = signed(&setup, &body, false);
        let forged = String::from_utf8(theirs)
            .unwrap()
            .replacen(&setup.agent.did(), &impostor.did(), 1)
            .into_bytes();
        let other_agent = AgentIdentity::generate().unwrap();
        let mut stolen = issue_binding(&setup.human, &other_agent.did(), "x", NOW + 60).unwrap();
        stolen.push(b'\n');
        stolen.extend_from_slice(body.as_bytes());
        let stolen = wrap_signed_message(&setup.agent, &stolen).unwrap();
        let mut lapsed = issue_binding(&setup.human, &setup.agent.did(), "x", NOW - 1).unwrap();
        lapsed.push(b'\n');
        lapsed.extend_from_slice(body.as_bytes());
        let lapsed = wrap_signed_message(&setup.agent, &lapsed).unwrap();

        for (bad, why) in [
            (body.as_bytes().to_vec(), "DID proof"),
            (forged, "forged"),
            (stolen, "binding is for"),
            (lapsed, "agent binding rejected"),
            (
                signed(&setup, "hello", false),
                "not a SHADI-CHANNEL-REQUEST/1",
            ),
            (
                signed(
                    &setup,
                    &format!("{MAGIC}\nchannel: {ROOM}\ninvitee: {PEER}"),
                    false,
                ),
                "invitee_did",
            ),
            (
                signed(&setup, &render_request(ROOM, PEER, "did:web:x"), false),
                "invitee_did:",
            ),
        ] {
            let (state, reply) = setup.executor.handle(&bad, NOW);
            assert_eq!(state, TaskState::Rejected, "{why}: {reply}");
            assert!(reply.contains(why), "{why}: {reply}");
        }
        assert!(setup.invites.0.lock().unwrap().is_empty());
        assert!(setup.executor.owner.lock().unwrap().audit().is_empty());
    }

    fn context(text: Option<String>) -> ExecutorContext {
        ExecutorContext {
            message: text.map(|text| Message::new(Role::User, vec![Part::text(text)])),
            task_id: "task-1".to_string(),
            stored_task: None,
            context_id: "ctx-1".to_string(),
            metadata: None,
            user: None,
            service_params: Default::default(),
            tenant: None,
        }
    }

    fn only_task(events: BoxStream<'static, Result<StreamResponse, A2AError>>) -> Task {
        use futures::StreamExt as _;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events: Vec<_> = runtime.block_on(events.collect());
        match events.as_slice() {
            [Ok(StreamResponse::Task(task))] => task.clone(),
            other => panic!("expected one task, got {other:?}"),
        }
    }

    #[test]
    fn a_cancelled_or_empty_request_ends_without_reaching_the_policy() {
        let setup = setup(r#"{"default": "allow"}"#);
        let cancelled = only_task(setup.executor.cancel(context(None)));
        assert_eq!(cancelled.status.state, TaskState::Canceled);
        assert!(cancelled.status.message.is_none());

        let empty = only_task(setup.executor.execute(context(None)));
        assert_eq!(empty.status.state, TaskState::Rejected);
        assert!(setup.executor.owner.lock().unwrap().audit().is_empty());
    }

    #[test]
    fn the_executor_answers_with_one_task_carrying_the_reply() {
        let setup = setup(r#"{"default": "block"}"#);
        let text = String::from_utf8(as_task(&setup, false)).unwrap();
        let task = only_task(setup.executor.execute(context(Some(text))));
        assert_eq!(task.status.state, TaskState::Rejected);
        assert_eq!(task.id, "task-1");
        let message = task.status.message.as_ref().expect("a reply");
        assert_eq!(
            message.parts[0].as_text(),
            Some("refused: refused by the owner's policy")
        );
        assert_eq!(
            owner_service_name("agntcy/shadi/avatar"),
            "agntcy/shadi/avatar-owner"
        );
    }
}
