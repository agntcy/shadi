// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The frame of a run, written by a model.
//!
//! An initiator that has a model does not need its anchors, its threshold or
//! the shape of a candidate on the command line: the model reads the task and
//! writes them, as the library's initiator guidance describes. [`prompt`] is
//! what the model reads, [`complete`] reads what it wrote, and [`write`] asks
//! again, with what to fix, until the answer is accepted.

use ioc_concord::guidance::{refusal_text, START_PARAMS};
use serde_json::Value;

use super::reply::extract_json;

/// The parts of an init that a model can write. A part that is `Some` was
/// given and stays as it is; the model writes the others.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Given {
    /// The worst outcome, as a state and not as a proposal.
    pub reject: Option<String>,
    /// The best outcome, as a state and not as a proposal.
    pub ideal: Option<String>,
    /// The candidate schema, a JSON Schema object.
    pub schema: Option<Value>,
    /// The score every participant must reach, as text.
    pub threshold: Option<String>,
}

impl Given {
    /// Whether there is nothing left for a model to write.
    pub fn is_complete(&self) -> bool {
        self.missing().is_empty()
    }

    /// The names of the parts a model has to write, in the order of the
    /// library's guidance.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.threshold.is_none() {
            out.push("satisfaction_threshold");
        }
        if self.reject.is_none() {
            out.push("x_reject");
        }
        if self.ideal.is_none() {
            out.push("x_ideal");
        }
        if self.schema.is_none() {
            out.push("schema");
        }
        out
    }
}

/// The library's words on how to fill `field`.
fn guidance(field: &str) -> &'static str {
    START_PARAMS
        .iter()
        .find(|(name, _)| *name == field)
        .map_or("", |(_, text)| text)
}

const SCHEMA: &str = "How one candidate is written, as a JSON Schema object. If the task offers a fixed list of \
options, an enum of exactly those options, each copied exactly as given: \
{\"type\": \"string\", \"enum\": [\"a\", \"b\", \"c\"]}. If it offers none, a string, with a description of what one \
candidate is, in one sentence: {\"type\": \"string\", \"description\": \"...\"}. Never invent options the task does not list.";

/// The form of the answer for the parts in `given` that are missing.
pub fn answer_format(given: &Given) -> String {
    let fields: Vec<String> = given
        .missing()
        .iter()
        .map(|field| match *field {
            "satisfaction_threshold" => "\"satisfaction_threshold\": number".to_string(),
            "schema" => "\"schema\": object".to_string(),
            other => format!("\"{other}\": text"),
        })
        .collect();
    format!(
        "HOW TO ANSWER: reply with one JSON object and nothing else, with exactly these fields: {{{}}}.",
        fields.join(", ")
    )
}

/// What the model reads to write the missing parts of the init of a run on
/// `goal` among `participants`.
pub fn prompt(goal: &str, participants: &[String], given: &Given) -> String {
    let mut out = vec![
        "## Starting the run: you are the initiator".to_string(),
        "You open a CONCORD run for a team and take no part in it: the participants decide together, each \
from its own role, and each reads the frame you write as it is."
            .to_string(),
        String::new(),
        format!("TASK FOR THE TEAM: {goal}"),
        format!("PARTICIPANTS: {}", participants.join(", ")),
        String::new(),
        "To open the run you give:".to_string(),
    ];
    for field in given.missing() {
        let text = if field == "schema" {
            format!("- schema: {SCHEMA}")
        } else {
            format!("- {field}: {}", guidance(field))
        };
        out.push(text);
    }
    let fixed: Vec<String> = [
        ("satisfaction_threshold", given.threshold.clone()),
        ("x_reject", given.reject.clone()),
        ("x_ideal", given.ideal.clone()),
        ("schema", given.schema.as_ref().map(Value::to_string)),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|v| format!("- {name}: {v}")))
    .collect();
    if !fixed.is_empty() {
        out.push(String::new());
        out.push("Already fixed, do not write these:".to_string());
        out.extend(fixed);
    }
    out.push(String::new());
    out.push(answer_format(given));
    out.join("\n")
}

/// `given` with its missing parts taken from the model's `answer`, or what is
/// wrong with the answer, for the model.
pub fn complete(given: &Given, answer: &Value) -> Result<Given, String> {
    let mut out = given.clone();
    let mut problems = Vec::new();
    for field in given.missing() {
        match field {
            "satisfaction_threshold" => match threshold(answer.get(field)) {
                Ok(text) => out.threshold = Some(text),
                Err(problem) => problems.push(problem),
            },
            "schema" => match schema(answer.get(field)) {
                Ok(value) => out.schema = Some(value),
                Err(problem) => problems.push(problem),
            },
            _ => match anchor(field, answer.get(field)) {
                Ok(text) if field == "x_reject" => out.reject = Some(text),
                Ok(text) => out.ideal = Some(text),
                Err(problem) => problems.push(problem),
            },
        }
    }
    if problems.is_empty() {
        let same = |a: &Option<String>, b: &Option<String>| matches!((a, b), (Some(a), Some(b)) if a.trim().eq_ignore_ascii_case(b.trim()));
        if same(&out.reject, &out.ideal) {
            problems.push(
                "x_reject and x_ideal are the same: they are the worst and the best outcome."
                    .to_string(),
            );
        }
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(problems.join(" "))
    }
}

fn anchor(field: &str, value: Option<&Value>) -> Result<String, String> {
    match value {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        _ => Err(format!(
            "{field} must be a sentence that states the outcome."
        )),
    }
}

fn threshold(value: Option<&Value>) -> Result<String, String> {
    let text = match value {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.trim().to_string(),
        _ => String::new(),
    };
    match text.parse::<f64>() {
        Ok(n) if n > 0.0 && n <= 1.0 => Ok(text),
        _ => Err("satisfaction_threshold must be a number above 0 and at most 1.".to_string()),
    }
}

fn schema(value: Option<&Value>) -> Result<Value, String> {
    let object = match value {
        Some(Value::Object(_)) => value.cloned(),
        // a model may write the object as text
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok(),
        _ => None,
    };
    match object {
        Some(Value::Object(map)) => {
            let empty_enum = matches!(map.get("enum"), Some(Value::Array(a)) if a.is_empty())
                || matches!(map.get("enum"), Some(v) if !v.is_array());
            if empty_enum {
                Err("schema has an enum that is not a list of at least one option.".to_string())
            } else {
                Ok(Value::Object(map))
            }
        }
        _ => Err("schema must be a JSON Schema object, such as {\"type\": \"string\", \"description\": \"...\"}.".to_string()),
    }
}

/// Why [`write`] did not give an init.
#[derive(Debug)]
pub enum WriteError<E> {
    /// Asking the model failed.
    Asking(E),
    /// The model's answers were refused, every time.
    Refused { attempts: u32, last: String },
}

/// Ask for the missing parts of the init until an answer is accepted, at most
/// `max_attempts` times. `ask` gives the model's reply to a prompt.
pub fn write<E>(
    goal: &str,
    participants: &[String],
    given: &Given,
    max_attempts: u32,
    mut ask: impl FnMut(&str) -> Result<String, E>,
) -> Result<Given, WriteError<E>> {
    if given.is_complete() {
        return Ok(given.clone());
    }
    let mut text = prompt(goal, participants, given);
    let mut last = String::new();
    let mut repeats = 0;
    for _ in 0..max_attempts {
        let reply = ask(&text).map_err(WriteError::Asking)?;
        let problem = match extract_json(&reply) {
            Some(answer) => match complete(given, &answer) {
                Ok(done) => return Ok(done),
                Err(problem) => refusal_text(&problem, repeats),
            },
            None => refusal_text("your answer is not a JSON object", repeats),
        };
        repeats = if problem == last { repeats + 1 } else { 1 };
        text = format!("{problem}\n\n{}", answer_format(given));
        last = problem;
    }
    Err(WriteError::Refused {
        attempts: max_attempts,
        last,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn people() -> Vec<String> {
        vec!["a".into(), "b".into()]
    }

    fn good() -> Value {
        json!({
            "satisfaction_threshold": 0.6,
            "x_reject": "nothing is decided",
            "x_ideal": "everyone can live with the decision",
            "schema": {"type": "string", "description": "the decision"}
        })
    }

    #[test]
    fn the_prompt_has_the_task_the_participants_and_every_missing_part() {
        let text = prompt("build a thing", &people(), &Given::default());
        assert!(text.contains("TASK FOR THE TEAM: build a thing"), "{text}");
        assert!(text.contains("PARTICIPANTS: a, b"), "{text}");
        for field in ["satisfaction_threshold", "x_reject", "x_ideal", "schema"] {
            assert!(text.contains(&format!("- {field}: ")), "{field}: {text}");
        }
        assert!(text.contains("HOW TO ANSWER"), "{text}");
        assert!(!text.contains("Already fixed"), "{text}");
    }

    #[test]
    fn a_part_that_was_given_is_shown_as_fixed_and_not_asked() {
        let given = Given {
            reject: Some("nothing is decided".into()),
            threshold: Some("0.5".into()),
            ..Given::default()
        };
        let text = prompt("goal", &people(), &given);
        assert!(text.contains("Already fixed"), "{text}");
        assert!(text.contains("- x_reject: nothing is decided"), "{text}");
        assert!(
            !text.contains("The standard the outcome genuinely has to meet"),
            "{text}"
        );
        let asked = answer_format(&given);
        assert!(
            asked.contains("\"x_ideal\"") && asked.contains("\"schema\""),
            "{asked}"
        );
        assert!(
            !asked.contains("x_reject") && !asked.contains("threshold"),
            "{asked}"
        );
    }

    #[test]
    fn the_schema_guidance_asks_for_an_enum_only_when_the_task_lists_options() {
        let text = prompt("pick a, b or c", &people(), &Given::default());
        assert!(text.contains("an enum of exactly those options"), "{text}");
        assert!(text.contains("If it offers none, a string"), "{text}");
    }

    #[test]
    fn a_good_answer_fills_what_was_missing_and_keeps_what_was_given() {
        let given = Given {
            ideal: Some("kept".into()),
            ..Given::default()
        };
        let done = complete(&given, &good()).unwrap();
        assert_eq!(done.ideal.as_deref(), Some("kept"));
        assert_eq!(done.reject.as_deref(), Some("nothing is decided"));
        assert_eq!(done.threshold.as_deref(), Some("0.6"));
        assert_eq!(done.schema.unwrap()["type"], "string");
    }

    #[test]
    fn a_threshold_must_be_above_zero_and_at_most_one() {
        for bad in [json!(0), json!(1.5), json!("high"), json!(null)] {
            let mut answer = good();
            answer["satisfaction_threshold"] = bad;
            let error = complete(&Given::default(), &answer).unwrap_err();
            assert!(error.contains("satisfaction_threshold"), "{error}");
        }
        let mut answer = good();
        answer["satisfaction_threshold"] = json!("0.75");
        assert_eq!(
            complete(&Given::default(), &answer)
                .unwrap()
                .threshold
                .as_deref(),
            Some("0.75")
        );
    }

    #[test]
    fn the_anchors_must_be_text_and_must_differ() {
        let mut answer = good();
        answer["x_reject"] = json!("");
        assert!(complete(&Given::default(), &answer)
            .unwrap_err()
            .contains("x_reject"));

        let mut answer = good();
        answer["x_reject"] = json!("The same.");
        answer["x_ideal"] = json!("the same.");
        assert!(complete(&Given::default(), &answer)
            .unwrap_err()
            .contains("the same"));
    }

    #[test]
    fn a_schema_may_be_an_object_or_text_and_an_enum_needs_options() {
        let mut answer = good();
        answer["schema"] = json!("{\"type\": \"string\", \"enum\": [\"a\", \"b\"]}");
        let done = complete(&Given::default(), &answer).unwrap();
        assert_eq!(done.schema.unwrap()["enum"], json!(["a", "b"]));

        for bad in [
            json!("not json"),
            json!(3),
            json!({"enum": []}),
            json!({"enum": "a"}),
        ] {
            let mut answer = good();
            answer["schema"] = bad;
            let error = complete(&Given::default(), &answer).unwrap_err();
            assert!(error.contains("schema"), "{error}");
        }
    }

    #[test]
    fn nothing_is_asked_when_everything_was_given() {
        let given = Given {
            reject: Some("r".into()),
            ideal: Some("i".into()),
            schema: Some(json!({"type": "string"})),
            threshold: Some("0.6".into()),
        };
        let done = write("goal", &people(), &given, 3, |_| -> Result<String, ()> {
            panic!("the model must not be asked")
        });
        assert_eq!(done.unwrap(), given);
    }

    #[test]
    fn a_refused_answer_is_asked_again_with_what_to_fix() {
        let mut prompts = Vec::new();
        let mut replies = vec!["I think 0.6.".to_string(), good().to_string()].into_iter();
        let done = write(
            "goal",
            &people(),
            &Given::default(),
            3,
            |p| -> Result<String, ()> {
                prompts.push(p.to_string());
                Ok(replies.next().unwrap())
            },
        )
        .unwrap();
        assert_eq!(done.threshold.as_deref(), Some("0.6"));
        assert_eq!(prompts.len(), 2);
        assert!(prompts[1].contains("not a JSON object"), "{}", prompts[1]);
        assert!(prompts[1].contains("HOW TO ANSWER"), "{}", prompts[1]);
    }

    #[test]
    fn an_answer_that_is_never_accepted_ends_in_a_refusal() {
        let result = write(
            "goal",
            &people(),
            &Given::default(),
            2,
            |_| -> Result<String, ()> { Ok("{\"x_reject\": \"\"}".to_string()) },
        );
        match result {
            Err(WriteError::Refused { attempts, last }) => {
                assert_eq!(attempts, 2);
                assert!(last.contains("satisfaction_threshold"), "{last}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_model_that_cannot_be_asked_ends_with_its_error() {
        let result = write(
            "goal",
            &people(),
            &Given::default(),
            3,
            |_| -> Result<String, &str> { Err("no harness") },
        );
        assert!(matches!(result, Err(WriteError::Asking("no harness"))));
    }
}
