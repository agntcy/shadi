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

/// The fields of an init reply, in the order the answer format lists them.
const INIT_REPLY: [&str; 6] = [
    "raw_reject",
    "raw_ideal",
    "candidate",
    "rationale",
    "raw",
    "reasoning",
];

/// The fields of a repair, in the order the answer format lists them.
const REPAIR: [&str; 4] = ["candidate", "rationale", "raw", "reasoning"];

/// Whether `field` of an answer is a number; every other one is text.
fn is_number(field: &str) -> bool {
    matches!(field, "raw" | "raw_reject" | "raw_ideal")
}

/// `{"a": text, "b": number}` for the fields in `keys`.
fn fields_of(keys: &[&str]) -> String {
    let fields: Vec<String> = keys
        .iter()
        .map(|key| {
            let kind = if is_number(key) { "number" } else { "text" };
            format!("\"{key}\": {kind}")
        })
        .collect();
    fields.join(", ")
}

/// What to tell the model about the form of its answer to `task`.
pub fn answer_format(task: &Task) -> String {
    let (fields, note) = match task {
        Task::InitReply(_) => (fields_of(&INIT_REPLY), ""),
        Task::Score(_) => (
            "\"scores\": [{\"id\": text, \"raw\": number, \"reasoning\": text}, ...]".to_string(),
            " Write each id as it is printed above.",
        ),
        Task::Repair(_) => (fields_of(&REPAIR), ""),
        // a kind of task this integration does not know: `submit` refuses it
        // before any prompt reaches the model
        _ => ("the fields the task asks for".to_string(), ""),
    };
    format!(
        "HOW TO ANSWER: reply with one JSON object and nothing else, with exactly these fields: \
         {{{fields}}}.{note}"
    )
}

/// The last JSON object in `text`, which may have prose or a code fence
/// around it. A model that quotes an example before its answer is read by its
/// answer, and an object inside another is not a separate one. `None` when
/// there is none.
pub fn extract_json(text: &str) -> Option<Value> {
    let mut found = None;
    let mut at = 0;
    while let Some(offset) = text[at..].find('{') {
        let start = at + offset;
        let mut values = serde_json::Deserializer::from_str(&text[start..]).into_iter::<Value>();
        match values.next() {
            Some(Ok(value @ Value::Object(_))) => {
                at = start + values.byte_offset();
                found = Some(value);
            }
            _ => at = start + 1,
        }
    }
    found
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
    /// The library took it. The step holds what to send; `anchors` are the
    /// agent's own raw anchors when the answer was its init reply.
    Sent {
        step: Step,
        anchors: Option<RawAnchors>,
    },
    /// The answer is wrong. `problem` is what is wrong, and `text` is what to
    /// tell the model about it, which changes when the model repeats itself.
    Refused { problem: String, text: String },
    /// The task is no longer this agent's to answer (it is answered, or the
    /// run moved on). Nothing is wrong and nothing is to be sent.
    Settled(String),
    /// A kind of task this integration does not know: the library is newer
    /// than the code that drives it.
    Unsupported(&'static str),
}

/// The refusals of one task so far, to tell a model that repeats itself: after
/// the same refusal twice in a row, the library adds that it must change its
/// answer. The refusal is told apart by its `problem`, not by the text, which
/// differs from one time to the next.
#[derive(Debug, Default)]
pub struct Refusals {
    last: String,
    times: u32,
}

impl Refusals {
    /// How many times in a row `problem` has been refused, this one included.
    pub fn count(&self, problem: &str) -> u32 {
        if self.last == problem {
            self.times + 1
        } else {
            1
        }
    }

    /// Note that `problem` has been refused.
    pub fn record(&mut self, problem: &str) {
        self.times = self.count(problem);
        self.last = problem.to_string();
    }

    /// The last problem, for an error that says why the answers were refused.
    pub fn last(&self) -> &str {
        &self.last
    }
}

/// Send the model's `answer` to `task` through `agent`. `anchors` are the
/// agent's own raw anchors when they are known; `refusals` are the refusals of
/// this task so far.
pub fn submit(
    agent: &mut Agent,
    task: &Task,
    answer: &Value,
    anchors: Option<RawAnchors>,
    refusals: &Refusals,
) -> Submitted {
    let refused = |problem: String, text: String| Submitted::Refused { problem, text };
    let problems = check_answer(task.kind(), answer, anchors);
    if !problems.is_empty() {
        let problem = problems.join(" ");
        let text = refusal_text(&problem, refusals.count(&problem));
        return refused(problem, text);
    }
    let run_id = task.run_id();
    let result = match task {
        Task::InitReply(_) => init_reply(agent, run_id, answer),
        Task::Score(_) => score(agent, run_id, answer),
        Task::Repair(_) => repair(agent, run_id, answer),
        _ => return Submitted::Unsupported(task.kind()),
    };
    match result {
        Ok(Ok(step)) => Submitted::Sent {
            step,
            anchors: matches!(task, Task::InitReply(_))
                .then(|| anchors_of(answer))
                .flatten(),
        },
        Ok(Err(error)) if ioc_concord::guidance::settled(&error) => {
            Submitted::Settled(error.to_string())
        }
        Ok(Err(error)) => {
            let problem = error.to_string();
            let text = refusal(&error, refusals.count(&problem));
            refused(problem, text)
        }
        Err(problem) => {
            let text = refusal_text(&problem, refusals.count(&problem));
            refused(problem, text)
        }
    }
}

/// The outer error is an answer that does not have the right fields; the
/// inner one is the library's answer to a call.
type Call = Result<ioc_concord::Result<Step>, String>;

fn init_reply(agent: &mut Agent, run_id: &str, a: &Value) -> Call {
    let ([candidate, rationale, reasoning], [raw_reject, raw_ideal, raw]) = gather(
        a,
        &INIT_REPLY,
        ["candidate", "rationale", "reasoning"],
        ["raw_reject", "raw_ideal", "raw"],
    )?;
    Ok(agent.submit_init_reply(
        run_id, raw_reject, raw_ideal, &candidate, &rationale, raw, &reasoning, None,
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
        scores.push(ScoreIn::new(id, num_or_say(item, "raw")?, reasoning));
    }
    Ok(agent.submit_score(run_id, &scores, None))
}

fn repair(agent: &mut Agent, run_id: &str, a: &Value) -> Call {
    let ([candidate, rationale, reasoning], [raw]) =
        gather(a, &REPAIR, ["candidate", "rationale", "reasoning"], ["raw"])?;
    Ok(agent.submit_repair(run_id, &candidate, &rationale, raw, &reasoning, None))
}

/// The text fields `texts` and the numbers `nums` of an answer, each in the
/// order of its keys, or one sentence for everything that is wrong with it:
/// what is missing and what has the wrong shape. `order` is how the answer
/// format lists the fields, for the sentence.
fn gather<const T: usize, const N: usize>(
    a: &Value,
    order: &[&str],
    texts: [&'static str; T],
    nums: [&'static str; N],
) -> Result<([String; T], [Num; N]), String> {
    let mut missing = Vec::new();
    let mut wrong = Vec::new();
    let mut got_texts = Vec::with_capacity(T);
    for key in texts {
        match text(a.get(key)) {
            Some(t) => got_texts.push(t),
            None => missing.push(key),
        }
    }
    let mut got_nums = Vec::with_capacity(N);
    for key in nums {
        match num(a, key) {
            Ok(n) => got_nums.push(n),
            Err(Absent::Missing) => missing.push(key),
            Err(Absent::Wrong(problem)) => wrong.push(problem),
        }
    }
    if missing.is_empty() && wrong.is_empty() {
        // one value per key, so the lengths are those of the arrays
        let (Ok(texts), Ok(nums)) = (got_texts.try_into(), got_nums.try_into()) else {
            unreachable!("one value per key");
        };
        return Ok((texts, nums));
    }
    let mut problems = Vec::new();
    if !missing.is_empty() {
        let takes: Vec<String> = order.iter().map(|k| (*k).to_string()).collect();
        problems.push(lacks(&missing, &present(a), &takes));
    }
    problems.extend(wrong);
    Err(problems.join(" "))
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

/// Why a number could not be read from an answer.
enum Absent {
    Missing,
    /// It is there, with the wrong shape: the sentence that says so.
    Wrong(String),
}

fn num(a: &Value, key: &str) -> Result<Num, Absent> {
    match a.get(key) {
        None | Some(Value::Null) => Err(Absent::Missing),
        Some(Value::String(s)) => Ok(Num::Text(s.trim().to_string())),
        Some(Value::Number(n)) => Ok(match n.as_i64() {
            Some(i) => Num::Int(i),
            None => Num::Float(n.as_f64().unwrap_or(f64::NAN)),
        }),
        Some(other) => Err(Absent::Wrong(wrong_shape(key, "a number", other))),
    }
}

/// A number of an answer, or the sentence that says what is wrong with it.
fn num_or_say(a: &Value, key: &str) -> Result<Num, String> {
    num(a, key).map_err(|absent| match absent {
        Absent::Missing => lacks(&[key], &present(a), &[key.to_string()]),
        Absent::Wrong(problem) => problem,
    })
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
        let error = num_or_say(&json!({"other": 1}), "raw").unwrap_err();
        assert!(error.contains("your answer lacks raw"), "{error}");
    }

    #[test]
    fn a_number_of_the_wrong_shape_is_named() {
        let error = num_or_say(&json!({"raw": [1]}), "raw").unwrap_err();
        assert!(error.contains("`raw` must be a number"), "{error}");
    }

    #[test]
    fn numbers_keep_their_form() {
        assert_eq!(num_or_say(&json!({"raw": 7}), "raw"), Ok(Num::Int(7)));
        assert_eq!(num_or_say(&json!({"raw": 7.5}), "raw"), Ok(Num::Float(7.5)));
        assert_eq!(
            num_or_say(&json!({"raw": " 7.5 "}), "raw"),
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
    fn a_repair_with_gaps_gets_one_refusal_that_lists_them_all() {
        // a text field and a number are missing, and another number is of the
        // wrong shape: the model learns of all of it at once
        let error = gather(
            &json!({"candidate": "a", "rationale": " ", "raw": [1]}),
            &REPAIR,
            ["candidate", "rationale", "reasoning"],
            ["raw"],
        )
        .unwrap_err();
        assert!(error.contains("rationale; reasoning"), "{error}");
        assert!(error.contains("You sent: candidate"), "{error}");
        assert!(error.contains("`raw` must be a number"), "{error}");
    }

    #[test]
    fn missing_numbers_are_listed_with_the_missing_text() {
        let error = gather(
            &json!({"candidate": "a", "rationale": "b", "reasoning": "c"}),
            &INIT_REPLY,
            ["candidate", "rationale", "reasoning"],
            ["raw_reject", "raw_ideal", "raw"],
        )
        .unwrap_err();
        assert!(error.contains("raw_reject; raw_ideal; raw"), "{error}");
    }

    #[test]
    fn a_complete_answer_gives_its_fields_in_the_order_of_the_keys() {
        let (texts, nums) = gather(
            &json!({"candidate": "c", "rationale": "r", "reasoning": "w", "raw": 70}),
            &REPAIR,
            ["candidate", "rationale", "reasoning"],
            ["raw"],
        )
        .unwrap();
        assert_eq!(texts, ["c".to_string(), "r".to_string(), "w".to_string()]);
        assert_eq!(nums, [Num::Int(70)]);
    }

    #[test]
    fn extract_json_takes_the_answer_and_not_an_example_before_it() {
        let reply = "The format is {\"raw\": 0}. My answer: {\"raw\": 70, \"nested\": {\"a\": 1}}";
        assert_eq!(
            extract_json(reply),
            Some(json!({"raw": 70, "nested": {"a": 1}}))
        );
    }

    #[test]
    fn extract_json_does_not_take_an_object_inside_another_as_the_last() {
        assert_eq!(
            extract_json("{\"outer\": {\"inner\": 1}}"),
            Some(json!({"outer": {"inner": 1}}))
        );
    }

    #[test]
    fn a_refusal_is_told_to_change_after_the_same_one_twice() {
        let mut refusals = Refusals::default();
        let problem = "your answer lacks raw";
        assert_eq!(refusals.count(problem), 1);
        refusals.record(problem);
        // the second time in a row: the library adds that the answer must change
        assert_eq!(refusals.count(problem), 2);
        let first = refusal_text(problem, 1);
        let second = refusal_text(problem, refusals.count(problem));
        assert_ne!(first, second);
        assert!(second.starts_with(&first), "{second}");
        // another problem starts the count again
        refusals.record(problem);
        assert_eq!(refusals.count("something else"), 1);
        refusals.record("something else");
        assert_eq!(refusals.count(problem), 1);
        assert_eq!(refusals.last(), "something else");
    }

    #[test]
    fn the_answer_format_lists_the_fields_in_the_order_gather_is_given() {
        // the format is built from the same constants the reading uses
        assert_eq!(
            fields_of(&INIT_REPLY),
            "\"raw_reject\": number, \"raw_ideal\": number, \"candidate\": text, \
             \"rationale\": text, \"raw\": number, \"reasoning\": text"
        );
        assert_eq!(
            fields_of(&REPAIR),
            "\"candidate\": text, \"rationale\": text, \"raw\": number, \"reasoning\": text"
        );
    }

    #[test]
    fn the_constants_split_into_the_texts_and_numbers_that_are_read() {
        // an answer made of exactly the fields of a constant is read whole,
        // so the constants and the reading cannot drift apart
        let answer = |keys: &[&str]| {
            let mut object = serde_json::Map::new();
            for key in keys {
                let value = if is_number(key) { json!(1) } else { json!("t") };
                object.insert((*key).to_string(), value);
            }
            Value::Object(object)
        };
        assert!(gather(
            &answer(&INIT_REPLY),
            &INIT_REPLY,
            ["candidate", "rationale", "reasoning"],
            ["raw_reject", "raw_ideal", "raw"],
        )
        .is_ok());
        assert!(gather(
            &answer(&REPAIR),
            &REPAIR,
            ["candidate", "rationale", "reasoning"],
            ["raw"],
        )
        .is_ok());
    }
}
