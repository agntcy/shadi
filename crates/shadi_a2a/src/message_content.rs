// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! A2A prompts and replies on spans, as the OpenTelemetry GenAI conventions'
//! opt-in `gen_ai.input.messages` and `gen_ai.output.messages` attributes.
//!
//! A span records them only if it declares both fields, and only when
//! [`CAPTURE_CONTENT_ENV`] is `true`.

/// The switch OpenTelemetry's GenAI instrumentations use. Content is off
/// unless it is `true`.
pub const CAPTURE_CONTENT_ENV: &str = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT";

/// Record the prompt `span` carries, when capture is on.
pub fn record_input(span: &tracing::Span, text: &str) {
    if capture_content() {
        span.record("gen_ai.input.messages", input_messages(text));
    }
}

/// Record the reply `span` carries, when capture is on.
pub fn record_output(span: &tracing::Span, text: &str) {
    if capture_content() {
        span.record("gen_ai.output.messages", output_messages(text));
    }
}

fn capture_content() -> bool {
    std::env::var(CAPTURE_CONTENT_ENV).is_ok_and(|value| value.eq_ignore_ascii_case("true"))
}

fn input_messages(text: &str) -> String {
    serde_json::json!([{"role": "user", "parts": [{"type": "text", "content": text}]}]).to_string()
}

fn output_messages(text: &str) -> String {
    serde_json::json!([{
        "role": "assistant",
        "parts": [{"type": "text", "content": text}],
        "finish_reason": "stop",
    }])
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_is_captured_only_when_the_switch_says_true() {
        for (value, on) in [
            (None, false),
            (Some("1"), false),
            (Some("false"), false),
            (Some("TRUE"), true),
        ] {
            match value {
                Some(value) => std::env::set_var(CAPTURE_CONTENT_ENV, value),
                None => std::env::remove_var(CAPTURE_CONTENT_ENV),
            }
            assert_eq!(capture_content(), on, "{value:?}");
        }
        std::env::remove_var(CAPTURE_CONTENT_ENV);
    }

    #[test]
    fn messages_follow_the_genai_shape() {
        let input: serde_json::Value = serde_json::from_str(&input_messages("do it")).unwrap();
        assert_eq!(
            input,
            serde_json::json!([{"role": "user", "parts": [{"type": "text", "content": "do it"}]}])
        );
        let output: serde_json::Value = serde_json::from_str(&output_messages("done")).unwrap();
        assert_eq!(output[0]["role"], "assistant");
        assert_eq!(output[0]["parts"][0]["content"], "done");
        assert_eq!(output[0]["finish_reason"], "stop");
    }
}
