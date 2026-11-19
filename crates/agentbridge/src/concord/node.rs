// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! One agent of a CONCORD run.
//!
//! A [`Node`] runs the `ioc-concord` state machine for one agent. It reads the
//! messages of the group from a [`Channel`], asks a [`Responder`] (a harness)
//! to write whatever the state machine says is due, and broadcasts what the
//! state machine hands back. The state stays with the node: every member of a
//! run holds its own copy, and they agree because they see the same messages.
//! A node that only opens the run and takes no part in it is a node whose
//! agent is not among the participants.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ioc_concord::agent::{Agent, Event, Step};
use ioc_concord::guidance::{render_delivery, RawAnchors, RUN_DESCRIPTION};
use ioc_concord::report::Report;
use ioc_concord::state::RunStatus;
use ioc_concord::tasks::Task;
use ioc_concord::wire::InitParams;
use serde_json::Value;

use super::channel::Channel;
use super::initiator::{self, Given, WriteError};
use super::reply::{anchors_of, answer_format, extract_json, submit, Submitted};
use crate::adapter::CliAdapter;

/// What a node needs the model for: the text that answers a task.
pub trait Responder: Send {
    /// The model's reply to `prompt`, the text of `task`. The reply is read
    /// as JSON (see [`super::reply`]).
    fn respond(&mut self, task: &Task, prompt: &str) -> Result<String, String>;

    /// The model's reply to a `prompt` that is not a task: what an initiator
    /// reads to write the frame of a run. A responder with no model for it
    /// says so.
    fn respond_to(&mut self, _prompt: &str) -> Result<String, String> {
        Err("this responder has no model to write the init".to_string())
    }
}

impl<R: Responder + ?Sized> Responder for Box<R> {
    fn respond(&mut self, task: &Task, prompt: &str) -> Result<String, String> {
        (**self).respond(task, prompt)
    }

    fn respond_to(&mut self, prompt: &str) -> Result<String, String> {
        (**self).respond_to(prompt)
    }
}

/// A harness as the model of a node. Each run gets its own conversation, so
/// that the harness keeps what it has read and written during the run.
pub struct HarnessResponder {
    adapter: Arc<dyn CliAdapter>,
}

impl HarnessResponder {
    pub fn new(adapter: Arc<dyn CliAdapter>) -> Self {
        Self { adapter }
    }
}

impl Responder for HarnessResponder {
    fn respond(&mut self, task: &Task, prompt: &str) -> Result<String, String> {
        self.adapter
            .execute_prompt_in(task.run_id(), prompt)
            .map_err(|e| e.to_string())
    }

    fn respond_to(&mut self, prompt: &str) -> Result<String, String> {
        self.adapter
            .execute_prompt_in(INIT_CONVERSATION, prompt)
            .map_err(|e| e.to_string())
    }
}

/// The conversation in which an initiator's harness writes the init.
const INIT_CONVERSATION: &str = "concord-init";

/// What opens a run: the problem, the two anchors of the scale, the shape of a
/// candidate, who negotiates, and the parameters.
#[derive(Debug, Clone)]
pub struct ConcordInit {
    pub participants: Vec<String>,
    pub context: String,
    /// The worst outcome, as a state and not as a proposal.
    pub x_reject: String,
    /// The best outcome, as a state and not as a proposal.
    pub x_ideal: String,
    /// The candidate schema, a JSON Schema.
    pub schema: Value,
    pub params: InitParams,
}

/// How a node paces itself.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// How many times the model may answer one task before the node gives up.
    pub max_attempts: u32,
    /// How many times a failed harness call is repeated before the node gives
    /// up. A reply that is refused is not a failure: it counts against
    /// `max_attempts`.
    pub harness_retries: u32,
    /// How long to wait before repeating a failed harness call.
    pub harness_pause: Duration,
    /// How long to wait for a message before looking at the timers.
    pub poll: Duration,
    /// How long the node may run in all. `None` runs until the run ends.
    pub deadline: Option<Duration>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            harness_retries: 2,
            harness_pause: Duration::from_secs(2),
            poll: Duration::from_millis(200),
            deadline: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("channel: {0}")]
    Channel(String),
    #[error("harness: {0}")]
    Harness(String),
    #[error("concord: {0}")]
    Concord(#[from] ioc_concord::ConcordError),
    #[error("the answer to a {kind} task was refused {attempts} times: {last}")]
    Refused {
        kind: &'static str,
        attempts: u32,
        last: String,
    },
    #[error("a {0} task is not supported by this version of the node")]
    Unsupported(&'static str),
    #[error("the run did not end within {0:?}")]
    Deadline(Duration),
    #[error("the node was stopped before the run ended")]
    Stopped,
}

/// What a node calls for every event.
type Observer = Box<dyn Fn(&Event) + Send>;

pub struct Node<C: Channel, R: Responder> {
    agent: Agent,
    channel: C,
    responder: R,
    config: NodeConfig,
    /// Messages of the others that the model has not read yet.
    inbox: Vec<String>,
    /// Whether the model has been told how a run goes.
    described: bool,
    /// The agent's own raw anchors, once its init reply is sent.
    anchors: Option<RawAnchors>,
    events: Vec<Event>,
    observer: Option<Observer>,
    stop: Arc<AtomicBool>,
}

impl<C: Channel, R: Responder> Node<C, R> {
    pub fn new(agent: Agent, channel: C, responder: R, config: NodeConfig) -> Self {
        Self {
            agent,
            channel,
            responder,
            config,
            inbox: Vec::new(),
            described: false,
            anchors: None,
            events: Vec::new(),
            observer: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Change how the node paces itself.
    pub fn set_config(&mut self, config: NodeConfig) {
        self.config = config;
    }

    /// Call `observer` for every event as it happens, for a log.
    pub fn observe(&mut self, observer: impl Fn(&Event) + Send + 'static) {
        self.observer = Some(Box::new(observer));
    }

    /// A flag that, once set, ends [`Node::run`] with [`NodeError::Stopped`]
    /// the next time the node looks at it: between messages, and before a
    /// failed harness call is repeated.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// What has happened so far, for a log.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Open a run, as the initiator. The node is a participant too when its
    /// agent is listed in `init.participants`.
    pub fn start(&mut self, init: &ConcordInit) -> Result<(), NodeError> {
        let step = self.agent.start(
            &init.participants,
            &init.context,
            &init.x_reject,
            &init.x_ideal,
            &init.schema,
            Some(&init.params),
            None,
            None,
        )?;
        self.apply(step)
    }

    /// Have the model write whatever of the frame of a run `given` leaves
    /// out: the anchors, the threshold and the shape of a candidate. What was
    /// given stays as it is, and nothing is asked when nothing is missing.
    pub fn write_init(
        &mut self,
        goal: &str,
        participants: &[String],
        given: &Given,
    ) -> Result<Given, NodeError> {
        let max_attempts = self.config.max_attempts;
        initiator::write(goal, participants, given, max_attempts, |prompt| {
            self.call("init", |responder| responder.respond_to(prompt))
        })
        .map_err(|error| match error {
            WriteError::Asking(error) => error,
            WriteError::Refused { attempts, last } => NodeError::Refused {
                kind: "init",
                attempts,
                last,
            },
        })
    }

    /// Take part until the run ends, and return its report.
    pub fn run(&mut self) -> Result<Report, NodeError> {
        let started = Instant::now();
        loop {
            if self.stopped() {
                return Err(NodeError::Stopped);
            }
            self.answer_due()?;
            if let Some(report) = self.finished() {
                return Ok(report);
            }
            if let Some(limit) = self.config.deadline {
                if started.elapsed() >= limit {
                    return Err(NodeError::Deadline(limit));
                }
            }
            match self
                .channel
                .recv(self.config.poll)
                .map_err(NodeError::Channel)?
            {
                Some(text) => match self.agent.receive(&text, None) {
                    Ok(step) => self.apply(step)?,
                    // a message that does not fit the run is not the end of it
                    Err(error) => tracing::warn!(%error, "concord: a message was not taken"),
                },
                None => {
                    let step = self.agent.tick(None)?;
                    self.apply(step)?;
                }
            }
        }
    }

    /// The report, once the run has ended (or been aborted) for this agent.
    fn finished(&self) -> Option<Report> {
        let status = self.agent.status(None)?;
        (status.status != RunStatus::Active)
            .then(|| self.agent.report(None))
            .flatten()
    }

    /// Hand to the channel what a call produced, and keep what the model has
    /// yet to read and what happened.
    fn apply(&mut self, step: Step) -> Result<(), NodeError> {
        for text in &step.send {
            self.channel.broadcast(text).map_err(NodeError::Channel)?;
        }
        for event in &step.events {
            tracing::debug!(event = %event.event, "concord");
            if let Some(observer) = &self.observer {
                observer(event);
            }
        }
        self.inbox.extend(step.accepted);
        self.events.extend(step.events);
        Ok(())
    }

    /// Answer every task that is due, until none is.
    fn answer_due(&mut self) -> Result<(), NodeError> {
        // answering one can make another due (the init reply is followed by
        // the scores), and a run that has ended owes nothing
        while let Some(task) = self.agent.due().into_iter().next() {
            if !self.answer(&task)? {
                break;
            }
        }
        Ok(())
    }

    /// Get an answer to `task` from the model and send it. `false` when the
    /// task turned out not to be the agent's to answer any more.
    fn answer(&mut self, task: &Task) -> Result<bool, NodeError> {
        let mut prompt = self.prompt(task)?;
        let mut last = String::new();
        let mut repeats = 0;
        for attempt in 1..=self.config.max_attempts {
            let reply = self.ask(task, &prompt)?;
            let outcome = match extract_json(&reply) {
                Some(answer) => {
                    let outcome = submit(&mut self.agent, task, &answer, self.anchors, repeats);
                    if matches!(outcome, Submitted::Sent(_)) && matches!(task, Task::InitReply(_)) {
                        self.anchors = anchors_of(&answer);
                    }
                    outcome
                }
                None => Submitted::Refused(ioc_concord::guidance::refusal_text(
                    "your answer is not a JSON object",
                    repeats,
                )),
            };
            match outcome {
                Submitted::Sent(step) => {
                    self.inbox.clear();
                    self.apply(step)?;
                    return Ok(true);
                }
                Submitted::Unsupported(kind) => return Err(NodeError::Unsupported(kind)),
                Submitted::Settled(why) => {
                    tracing::debug!(%why, kind = task.kind(), "concord: task no longer owed");
                    return Ok(false);
                }
                Submitted::Refused(text) => {
                    repeats = if text == last { repeats + 1 } else { 1 };
                    prompt = format!("{text}\n\n{}", answer_format(task));
                    last = text;
                    tracing::debug!(attempt, kind = task.kind(), "concord: answer refused");
                }
            }
        }
        Err(NodeError::Refused {
            kind: task.kind(),
            attempts: self.config.max_attempts,
            last,
        })
    }

    /// The model's reply to `prompt`. A call that fails is repeated after a
    /// pause, as a harness may fail once (a rate limit, a dropped connection)
    /// and answer the next time.
    fn ask(&mut self, task: &Task, prompt: &str) -> Result<String, NodeError> {
        self.call(task.kind(), |responder| responder.respond(task, prompt))
    }

    /// Repeat `call` on the responder while it fails, as `ask` does.
    fn call(
        &mut self,
        what: &str,
        mut call: impl FnMut(&mut R) -> Result<String, String>,
    ) -> Result<String, NodeError> {
        let mut failures = 0;
        loop {
            match call(&mut self.responder) {
                Ok(reply) => return Ok(reply),
                Err(_) if self.stopped() => return Err(NodeError::Stopped),
                Err(error) if failures >= self.config.harness_retries => {
                    return Err(NodeError::Harness(error));
                }
                Err(error) => {
                    failures += 1;
                    tracing::warn!(%error, failures, what, "concord: the harness failed, trying again");
                    std::thread::sleep(self.config.harness_pause);
                }
            }
        }
    }

    /// What the model reads for `task`: how a run goes (once), what the others
    /// sent since its last answer, the task, and the form of the answer.
    fn prompt(&mut self, task: &Task) -> Result<String, NodeError> {
        let mut parts = Vec::new();
        if !self.described {
            parts.push(RUN_DESCRIPTION.clone());
            self.described = true;
        }
        let delivery = render_delivery(&self.inbox);
        if !delivery.is_empty() {
            parts.push(delivery);
        }
        parts.push(self.agent.instructions(task)?);
        parts.push(answer_format(task));
        Ok(parts.join("\n\n"))
    }
}
