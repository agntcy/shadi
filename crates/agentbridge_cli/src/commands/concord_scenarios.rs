// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Whole CONCORD runs: several nodes, each with a scripted model, talking over
//! A2A Collaborate on a SLIM node in this process.
//!
//! They start a SLIM service, which sets a process-wide tracing subscriber,
//! so they are ignored in the shared run and go alone:
//!
//!   cargo test -p agntcy-agentbridge-cli --features concord -- --ignored concord_scenarios --test-threads=1

use std::sync::Arc;
use std::time::Duration;

use agentbridge::concord::ioc_concord::agent::Agent;
use agentbridge::concord::ioc_concord::protocol::Outcome;
use agentbridge::concord::ioc_concord::report::Report;
use agentbridge::concord::ioc_concord::tasks::Task;
use agentbridge::concord::ioc_concord::wire::InitParams;
use agentbridge::concord::node::{ConcordInit, Node, NodeConfig, NodeError, Responder};
use serde_json::{json, Value};

use super::concord_channel::tests::{member, node};
use super::concord_channel::CollaborateChannel;

const WHY: &str =
    "the concrete reasons: it fits the criteria of this role and the facts reported so far";

/// How an agent rates a candidate: `(who rates, the candidate's text)`.
type Rate = Arc<dyn Fn(&str, &str) -> u32 + Send + Sync>;

fn rate(f: impl Fn(&str, &str) -> u32 + Send + Sync + 'static) -> Rate {
    Arc::new(f)
}

/// A model that writes the answer its rule gives.
struct Scripted {
    me: String,
    rate: Rate,
    repairs: u32,
}

impl Scripted {
    fn new(me: &str, rate: &Rate) -> Self {
        Self {
            me: me.to_string(),
            rate: rate.clone(),
            repairs: 0,
        }
    }
}

impl Responder for Scripted {
    fn respond(&mut self, task: &Task, _prompt: &str) -> Result<String, String> {
        let me = self.me.clone();
        let answer = match task {
            Task::InitReply(_) => {
                let own = format!("opt-{me}");
                json!({"raw_reject": 0, "raw_ideal": 100, "candidate": own,
                       "rationale": WHY, "raw": (self.rate)(&me, &own), "reasoning": WHY})
            }
            Task::Score(t) => {
                let scores: Vec<Value> = t
                    .candidates
                    .iter()
                    .map(|c| json!({"id": c.id, "raw": (self.rate)(&me, &c.candidate), "reasoning": WHY}))
                    .collect();
                json!({ "scores": scores })
            }
            Task::Repair(_) => {
                self.repairs += 1;
                let fix = format!("fix-{me}-{}", self.repairs);
                json!({"candidate": fix, "rationale": WHY, "raw": (self.rate)(&me, &fix), "reasoning": WHY})
            }
            _ => return Err("unknown task".to_string()),
        };
        Ok(answer.to_string())
    }
}

fn init(participants: &[&str], params: InitParams) -> ConcordInit {
    ConcordInit {
        participants: participants.iter().map(ToString::to_string).collect(),
        context: "pick one option".to_string(),
        x_reject: "nothing is decided".to_string(),
        x_ideal: "every role is satisfied".to_string(),
        schema: json!({"type": "string", "description": "one option"}),
        params,
    }
}

fn config(deadline: Duration) -> NodeConfig {
    NodeConfig {
        poll: Duration::from_millis(50),
        deadline: Some(deadline),
        ..NodeConfig::default()
    }
}

type Outcomes = Vec<(String, Result<Report, NodeError>)>;

/// Run `members` (each takes part or only listens) with `opener` starting the
/// run, and give back each one's report.
fn run_group(members: &[&str], opener: &str, init: ConcordInit, rate: &Rate) -> Outcomes {
    let (_slim, url) = node();
    let mut nodes: Vec<(String, Node<CollaborateChannel, Scripted>)> = members
        .iter()
        .map(|name| {
            let channel = member(&url, name, members, Some(Duration::from_secs(10)));
            let node = Node::new(
                Agent::new(name).unwrap(),
                channel,
                Scripted::new(name, rate),
                config(Duration::from_secs(90)),
            );
            (name.to_string(), node)
        })
        .collect();
    // every member is listening before anything is sent
    std::thread::sleep(Duration::from_secs(2));
    let at = nodes.iter().position(|(n, _)| n == opener).unwrap();
    let (_, mut opener_node) = nodes.remove(at);
    let handles: Vec<_> = nodes
        .into_iter()
        .map(|(name, mut node)| std::thread::spawn(move || (name, node.run())))
        .collect();
    opener_node.start(&init).unwrap();
    let mut out = vec![(opener.to_string(), opener_node.run())];
    out.extend(handles.into_iter().map(|h| h.join().unwrap()));
    out
}

fn outcomes(results: &Outcomes) -> Vec<Option<Outcome>> {
    results
        .iter()
        .map(|(n, r)| r.as_ref().unwrap_or_else(|e| panic!("{n}: {e}")).outcome)
        .collect()
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn three_agents_that_all_like_the_options_end_in_success_with_one_winner() {
    let params = InitParams::default().satisfaction_threshold("0.6");
    let results = run_group(
        &["a", "b", "c"],
        "a",
        init(&["a", "b", "c"], params),
        &rate(|_, _| 80),
    );
    assert_eq!(outcomes(&results), vec![Some(Outcome::Success); 3]);
    let winners: Vec<_> = results
        .iter()
        .map(|(_, r)| r.as_ref().unwrap().winner.as_ref().map(|w| w.id.clone()))
        .collect();
    assert!(winners[0].is_some());
    assert!(winners.iter().all(|w| *w == winners[0]), "{winners:?}");
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn a_repair_by_the_bottleneck_can_clear_everyone() {
    // each agent likes its own option and rates the others' at 50, under the
    // threshold; a repair is rated 90 by all
    let rule = rate(|me, candidate| match candidate {
        c if c.starts_with("fix-") => 90,
        c if c == format!("opt-{me}") => 80,
        _ => 50,
    });
    let params = InitParams::default()
        .satisfaction_threshold("0.6")
        .budget(4);
    let results = run_group(&["a", "b", "c"], "a", init(&["a", "b", "c"], params), &rule);
    assert_eq!(outcomes(&results), vec![Some(Outcome::Success); 3]);
    for (_, r) in &results {
        assert!(r.as_ref().unwrap().rounds.is_some_and(|n| n >= 1));
    }
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn when_the_budget_runs_out_the_run_ends_in_best_effort() {
    let params = InitParams::default()
        .satisfaction_threshold("0.9")
        .budget(1);
    let results = run_group(
        &["a", "b"],
        "a",
        init(&["a", "b"], params),
        &rate(|_, _| 50),
    );
    assert_eq!(outcomes(&results), vec![Some(Outcome::BestEffort); 2]);
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn an_initiator_that_is_not_a_participant_still_gets_the_result() {
    let params = InitParams::default().satisfaction_threshold("0.6");
    let results = run_group(
        &["coord", "a", "b"],
        "coord",
        init(&["a", "b"], params),
        &rate(|_, _| 80),
    );
    assert_eq!(outcomes(&results), vec![Some(Outcome::Success); 3]);
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn a_silent_participant_aborts_the_run_for_the_others() {
    let (_slim, url) = node();
    let members = ["a", "b", "c"];
    let r = rate(|_, _| 80);
    // c is in the group and hears everything, but nothing answers for it
    let _silent = member(&url, "c", &members, Some(Duration::from_secs(10)));
    let mut nodes: Vec<_> = ["a", "b"]
        .iter()
        .map(|n| {
            let channel = member(&url, n, &members, Some(Duration::from_secs(10)));
            Node::new(
                Agent::new(n).unwrap(),
                channel,
                Scripted::new(n, &r),
                config(Duration::from_secs(60)),
            )
        })
        .collect();
    std::thread::sleep(Duration::from_secs(2));
    let mut b = nodes.pop().unwrap();
    let mut a = nodes.pop().unwrap();
    let handle = std::thread::spawn(move || b.run());
    let params = InitParams::default()
        .satisfaction_threshold("0.6")
        .timeout(1)
        .retries(0);
    a.start(&init(&members, params)).unwrap();
    let ours = a.run().unwrap();
    let theirs = handle.join().unwrap().unwrap();
    assert_eq!(ours.outcome, Some(Outcome::Aborted));
    assert_eq!(theirs.outcome, Some(Outcome::Aborted));
}

/// A model that gets the first answers wrong, then right.
struct Flaky {
    inner: Scripted,
    bad: u32,
    prompts: Vec<String>,
}

impl Responder for Flaky {
    fn respond(&mut self, task: &Task, prompt: &str) -> Result<String, String> {
        self.prompts.push(prompt.to_string());
        if self.bad > 0 {
            self.bad -= 1;
            return Ok("I would pick the first one, it seems best.".to_string());
        }
        self.inner.respond(task, prompt)
    }
}

/// `a` with the model `responder`, in a group with a `b` that never answers.
/// Its node gives up at `deadline`.
fn lone_node<R: Responder>(
    url: &str,
    responder: R,
    deadline: Duration,
) -> Node<CollaborateChannel, R> {
    let members = ["a", "b"];
    let channel = member(url, "a", &members, Some(Duration::from_secs(10)));
    // b only has to be listening
    std::mem::forget(member(url, "b", &members, Some(Duration::from_secs(10))));
    std::thread::sleep(Duration::from_secs(2));
    let mut node = Node::new(
        Agent::new("a").unwrap(),
        channel,
        responder,
        config(deadline),
    );
    node.start(&init(&members, InitParams::default())).unwrap();
    node
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn a_model_that_answers_badly_is_asked_again_with_what_to_fix() {
    let (_slim, url) = node();
    let r = rate(|_, _| 80);
    let flaky = Flaky {
        inner: Scripted::new("a", &r),
        bad: 2,
        prompts: Vec::new(),
    };
    let mut node = lone_node(&url, flaky, Duration::from_secs(5));
    // b never answers, so the run goes on until the deadline; what matters is
    // that a's own answer was taken
    assert!(matches!(node.run(), Err(NodeError::Deadline(_))));
    assert!(node.agent().due().is_empty(), "the init reply was sent");
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn a_model_that_never_answers_properly_ends_the_node_with_an_error() {
    let (_slim, url) = node();
    let r = rate(|_, _| 80);
    let flaky = Flaky {
        inner: Scripted::new("a", &r),
        bad: 99,
        prompts: Vec::new(),
    };
    let mut node = lone_node(&url, flaky, Duration::from_secs(30));
    match node.run() {
        Err(NodeError::Refused { kind, attempts, .. }) => {
            assert_eq!(kind, "init-reply");
            assert_eq!(attempts, 3);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A model whose calls fail the first `failures` times.
struct Unreliable {
    inner: Scripted,
    failures: u32,
}

impl Responder for Unreliable {
    fn respond(&mut self, task: &Task, prompt: &str) -> Result<String, String> {
        if self.failures > 0 {
            self.failures -= 1;
            return Err("the harness could not be reached".to_string());
        }
        self.inner.respond(task, prompt)
    }
}

fn quick_retries(node: &mut Node<CollaborateChannel, Unreliable>) {
    // the pause is not what is under test
    node.set_config(NodeConfig {
        harness_pause: Duration::from_millis(10),
        ..config(Duration::from_secs(5))
    });
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn a_harness_that_fails_a_few_times_is_tried_again() {
    let (_slim, url) = node();
    let r = rate(|_, _| 80);
    let responder = Unreliable {
        inner: Scripted::new("a", &r),
        failures: 2,
    };
    let mut node = lone_node(&url, responder, Duration::from_secs(5));
    quick_retries(&mut node);
    assert!(matches!(node.run(), Err(NodeError::Deadline(_))));
    assert!(node.agent().due().is_empty(), "the init reply was sent");
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn a_harness_that_keeps_failing_ends_the_node_with_its_error() {
    let (_slim, url) = node();
    let r = rate(|_, _| 80);
    let responder = Unreliable {
        inner: Scripted::new("a", &r),
        failures: 99,
    };
    let mut node = lone_node(&url, responder, Duration::from_secs(30));
    quick_retries(&mut node);
    match node.run() {
        Err(NodeError::Harness(error)) => assert!(error.contains("could not be reached")),
        other => panic!("expected a harness error, got {other:?}"),
    }
}

#[test]
#[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
fn a_node_that_is_told_to_stop_ends_with_stopped() {
    let (_slim, url) = node();
    let r = rate(|_, _| 80);
    let mut node = lone_node(&url, Scripted::new("a", &r), Duration::from_secs(30));
    node.stop_flag()
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(node.run(), Err(NodeError::Stopped)));
}
