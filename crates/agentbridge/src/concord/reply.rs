// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! What a harness writes for a CONCORD task, and how it becomes a `submit_*`
//! call.
//!
//! The library's guidance tells a model what each task asks for. This module
//! adds how to answer: one JSON object whose fields are the arguments of the
//! matching `submit_*` call. [`submit`] reads that object, runs the
//! library's own checks on it, and either sends it or says what to fix.

use ioc_concord::agent::{Agent, Step};
use ioc_concord::guidance::{check_answer, lacks, refusal, refusal_text, wrong_shape, RawAnchors};
use ioc_concord::protocol::Num;
use ioc_concord::tasks::Task;
use ioc_concord::wire::ScoreIn;
use serde_json::Value;

/// What to tell the model about the form of its answer to `task`.
pub fn answer_format(task: &Task) -> String {
    let (fields, note) = match task {
        Task::InitReply(_) => (
            "\"raw_reject\": number, \"raw_ideal\": number, \"candidate\": text, \
             \"rationale\": text, \"raw\": number, \"reasoning\": text",
            "",
        ),
        Task::Score(_) => (
            "\"scores\": [{\"id\": text, \"raw\": number, \"reasoning\": text}, ...]",
            " Write each id as it is printed above.",
        ),
        Task::Repair(_) => (
            "\"candidate\": text, \"rationale\": text, \"raw\": number, \"reasoning\": text",
            "",
        ),
        _ => ("the fields the task asks for", ""),
    };
    format!(
        "HOW TO ANSWER: reply with one JSON object and nothing else, with exactly these fields: \
         {{{fields}}}.{note}"
    )
}

/// The first JSON object in `text`, which may have prose or a code fence
/// around it. `None` when there is none.
pub fn extract_json(text: &str) -> Option<Value> {
    text.match_indices('{').find_map(|(start, _)| {
        let mut values = serde_json::Deserializer::from_str(&text[start..]).into_iter::<Value>();
        match values.next() {
            Some(Ok(value @ Value::Object(_))) => Some(value),
            _ => None,
        }
    })
}

/// The raw anchors an init reply sets, as the library's checks read them.
pub fn anchors_of(answer: &Value) -> Option<RawAnchors> {
    Some(RawAnchors {
        raw_reject: as_f64(answer.get("raw_reject"))?,
        raw_ideal: as_f64(answer.get("raw_ideal"))?,
    })
}

/// What came of submitting an answer.
#[derive(Debug)]
pub enum Submitted {
    /// The library took it. The step holds what to send.
    Sent(Step),
    /// The answer is wrong. The text says what to fix, for the model.
    Refused(String),
    /// The task is no longer this agent's to answer (it is answered, or the
    /// run moved on). Nothing is wrong and nothing is to be sent.
    Settled(String),
    /// A kind of task this integration does not know: the library is newer
    /// than the code that drives it.
    Unsupported(&'static str),
}

/// Send the model's `answer` to `task` through `agent`. `anchors` are the
/// agent's own raw anchors when they are known; `repeats` is how many times
/// in a row the model has been refused for the same thing.
pub fn submit(
    agent: &mut Agent,
    task: &Task,
    answer: &Value,
    anchors: Option<RawAnchors>,
    repeats: u32,
) -> Submitted {
    let problems = check_answer(task.kind(), answer, anchors);
    if !problems.is_empty() {
        return Submitted::Refused(refusal_text(&problems.join(" "), repeats));
    }
    let run_id = task.run_id();
    let result = match task {
        Task::InitReply(_) => init_reply(agent, run_id, answer),
        Task::Score(_) => score(agent, run_id, answer),
        Task::Repair(_) => repair(agent, run_id, answer),
        _ => return Submitted::Unsupported(task.kind()),
    };
    match result {
        Ok(Ok(step)) => Submitted::Sent(step),
        Ok(Err(error)) if ioc_concord::guidance::settled(&error) => {
            Submitted::Settled(error.to_string())
        }
        Ok(Err(error)) => Submitted::Refused(refusal(&error, repeats)),
        Err(text) => Submitted::Refused(refusal_text(&text, repeats)),
    }
}

/// The outer error is an answer that does not have the right fields; the
/// inner one is the library's answer to a call.
type Call = Result<ioc_concord::Result<Step>, String>;

fn init_reply(agent: &mut Agent, run_id: &str, a: &Value) -> Call {
    let fields = fields(
        a,
        &[
            "raw_reject",
            "raw_ideal",
            "candidate",
            "rationale",
            "raw",
            "reasoning",
        ],
    )?;
    Ok(agent.submit_init_reply(
        run_id,
        num(a, "raw_reject")?,
        num(a, "raw_ideal")?,
        &fields["candidate"],
        &fields["rationale"],
        num(a, "raw")?,
        &fields["reasoning"],
        None,
    ))
}

fn score(agent: &mut Agent, run_id: &str, a: &Value) -> Call {
    let list = match a.get("scores") {
        None | Some(Value::Null) => {
            return Err(lacks(&["scores"], &present(a), &["scores".into()]))
        }
        Some(Value::Array(list)) => list,
        Some(other) => return Err(wrong_shape("scores", "a list", other)),
    };
    let mut scores = Vec::with_capacity(list.len());
    for item in list {
        let id = text(item.get("id"));
        let reasoning = text(item.get("reasoning"));
        let (Some(id), Some(reasoning)) = (id, reasoning) else {
            return Err(lacks(
                &["an id and a reasoning for every score"],
                &present(item),
                &["id".into(), "raw".into(), "reasoning".into()],
            ));
        };
        scores.push(ScoreIn::new(id, num(item, "raw")?, reasoning));
    }
    Ok(agent.submit_score(run_id, &scores, None))
}

fn repair(agent: &mut Agent, run_id: &str, a: &Value) -> Call {
    let fields = fields(a, &["candidate", "rationale", "raw", "reasoning"])?;
    Ok(agent.submit_repair(
        run_id,
        &fields["candidate"],
        &fields["rationale"],
        num(a, "raw")?,
        &fields["reasoning"],
        None,
    ))
}

/// The text of every field in `keys`, or the sentence for those that are
/// missing. A number is kept for `num`; it is also readable here as text.
fn fields(
    a: &Value,
    keys: &[&'static str],
) -> Result<std::collections::HashMap<&'static str, String>, String> {
    let mut out = std::collections::HashMap::new();
    let mut missing = Vec::new();
    for key in keys {
        match text(a.get(key)) {
            Some(t) => {
                out.insert(*key, t);
            }
            None => missing.push(*key),
        }
    }
    if missing.is_empty() {
        Ok(out)
    } else {
        let takes: Vec<String> = keys.iter().map(|k| (*k).to_string()).collect();
        Err(lacks(&missing, &present(a), &takes))
    }
}

/// A field as text: a string as it is, anything else as its JSON. A missing
/// or null field, or an empty string, is `None`. The candidate may be a
/// JSON value when the schema asks for one.
fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null => None,
        Value::String(s) if s.trim().is_empty() => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn num(a: &Value, key: &str) -> Result<Num, String> {
    match a.get(key) {
        None | Some(Value::Null) => Err(lacks(&[key], &present(a), &[key.to_string()])),
        Some(Value::String(s)) => Ok(Num::Text(s.trim().to_string())),
        Some(Value::Number(n)) => Ok(match n.as_i64() {
            Some(i) => Num::Int(i),
            None => Num::Float(n.as_f64().unwrap_or(f64::NAN)),
        }),
        Some(other) => Err(wrong_shape(key, "a number", other)),
    }
}

fn as_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The keys an answer has, for the line that says what it sent.
fn present(a: &Value) -> Vec<String> {
    a.as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_json_finds_an_object_among_prose_and_fences() {
        let reply =
            "Here is my answer:\n```json\n{\"raw\": 70, \"nested\": {\"a\": 1}}\n```\nDone.";
        assert_eq!(
            extract_json(reply),
            Some(json!({"raw": 70, "nested": {"a": 1}}))
        );
    }

    #[test]
    fn extract_json_skips_a_brace_that_starts_no_object() {
        assert_eq!(
            extract_json("a {note} then {\"ok\": true}"),
            Some(json!({"ok": true}))
        );
    }

    #[test]
    fn extract_json_is_none_without_an_object() {
        assert_eq!(extract_json("no json here"), None);
        assert_eq!(extract_json("[1, 2, 3]"), None);
    }

    #[test]
    fn anchors_are_read_from_numbers_or_text() {
        let a = json!({"raw_reject": 5, "raw_ideal": "95.5"});
        assert_eq!(
            anchors_of(&a),
            Some(RawAnchors {
                raw_reject: 5.0,
                raw_ideal: 95.5
            })
        );
        assert_eq!(anchors_of(&json!({"raw_reject": 5})), None);
    }

    #[test]
    fn a_missing_number_says_what_is_lacking() {
        let error = num(&json!({"other": 1}), "raw").unwrap_err();
        assert!(error.contains("your answer lacks raw"), "{error}");
    }

    #[test]
    fn a_number_of_the_wrong_shape_is_named() {
        let error = num(&json!({"raw": [1]}), "raw").unwrap_err();
        assert!(error.contains("`raw` must be a number"), "{error}");
    }

    #[test]
    fn numbers_keep_their_form() {
        assert_eq!(num(&json!({"raw": 7}), "raw"), Ok(Num::Int(7)));
        assert_eq!(num(&json!({"raw": 7.5}), "raw"), Ok(Num::Float(7.5)));
        assert_eq!(
            num(&json!({"raw": " 7.5 "}), "raw"),
            Ok(Num::Text("7.5".into()))
        );
    }

    #[test]
    fn text_fields_take_a_json_candidate_and_reject_blanks() {
        assert_eq!(text(Some(&json!("x"))), Some("x".to_string()));
        assert_eq!(text(Some(&json!({"k": 1}))), Some("{\"k\":1}".to_string()));
        assert_eq!(text(Some(&json!("  "))), None);
        assert_eq!(text(Some(&json!(null))), None);
        assert_eq!(text(None), None);
    }

    #[test]
    fn fields_lists_every_missing_one_with_what_was_sent() {
        let error = fields(
            &json!({"candidate": "a"}),
            &["candidate", "rationale", "reasoning"],
        )
        .unwrap_err();
        assert!(error.contains("rationale; reasoning"), "{error}");
        assert!(error.contains("You sent: candidate"), "{error}");
    }
}
