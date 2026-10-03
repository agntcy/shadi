// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! W3C Trace Context in A2A message metadata, so the sender's and the
//! receiver's spans join one trace in any OpenTelemetry backend.
//!
//! The sender chooses these values and nothing signs them: they only link
//! traces, and nothing else may read them.

use std::borrow::Cow;
use std::collections::HashMap;

use a2a::{Message, SendMessageRequest};
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::trace::TraceContextExt;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// `req` with the current span's `traceparent` (and `tracestate`, when there
/// is one) in its message metadata. Borrowed when the span is not traced.
pub(crate) fn with_trace_context(req: &SendMessageRequest) -> Cow<'_, SendMessageRequest> {
    let mut fields = HashMap::new();
    TraceContextPropagator::new().inject_context(&tracing::Span::current().context(), &mut fields);
    if fields.is_empty() {
        return Cow::Borrowed(req);
    }
    let mut req = req.clone();
    let metadata = req.message.metadata.get_or_insert_with(HashMap::new);
    for (key, value) in fields {
        metadata.insert(key, serde_json::Value::String(value));
    }
    Cow::Owned(req)
}

/// Make `span` a child of the trace `message` names, if it names a valid one.
/// Call it before the span is first entered.
pub fn set_remote_parent(span: &tracing::Span, message: &Message) {
    let Some(metadata) = message.metadata.as_ref() else {
        return;
    };
    // Extracted onto an empty context, so a bad value yields an invalid parent
    // rather than whatever context happens to be current.
    let parent = TraceContextPropagator::new()
        .extract_with_context(&opentelemetry::Context::new(), &MetadataCarrier(metadata));
    if parent.span().span_context().is_valid() {
        let _ = span.set_parent(parent);
    }
}

struct MetadataCarrier<'a>(&'a HashMap<String, serde_json::Value>);

impl Extractor for MetadataCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(serde_json::Value::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a2a::{Part, Role};
    use opentelemetry::trace::{TraceId, TracerProvider as _};
    use tracing_subscriber::layer::SubscriberExt;

    fn traced<T>(run: impl FnOnce() -> T) -> T {
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("test"));
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), run)
    }

    fn current_trace() -> TraceId {
        let context = tracing::Span::current().context();
        context.span().span_context().trace_id()
    }

    fn request() -> SendMessageRequest {
        SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("task")]),
            configuration: None,
            metadata: None,
            tenant: None,
        }
    }

    #[test]
    fn the_receiver_joins_the_senders_trace() {
        traced(|| {
            let (sent, trace) = tracing::info_span!("send")
                .in_scope(|| (with_trace_context(&request()).into_owned(), current_trace()));
            let metadata = sent.message.metadata.as_ref().expect("metadata");
            assert!(metadata.contains_key("traceparent"), "{metadata:?}");

            let receive = tracing::info_span!("receive");
            set_remote_parent(&receive, &sent.message);
            assert_eq!(receive.in_scope(current_trace), trace);
        });
    }

    #[test]
    fn an_untraced_send_is_left_alone() {
        let req = request();
        assert!(matches!(with_trace_context(&req), Cow::Borrowed(_)));
    }

    /// The W3C propagator only reads two keys; others list them all.
    #[test]
    fn the_carrier_reads_and_lists_message_metadata() {
        let metadata = HashMap::from([
            ("traceparent".to_string(), serde_json::Value::from("tp")),
            ("a2a-dst-did".to_string(), serde_json::Value::from("did")),
            ("count".to_string(), serde_json::Value::from(3)),
        ]);
        let carrier = MetadataCarrier(&metadata);
        assert_eq!(carrier.get("traceparent"), Some("tp"));
        assert_eq!(carrier.get("count"), None, "only string values are read");
        let mut keys = carrier.keys();
        keys.sort_unstable();
        assert_eq!(keys, ["a2a-dst-did", "count", "traceparent"]);
    }

    /// Only a valid remote trace replaces the local parent.
    #[test]
    fn a_missing_or_malformed_traceparent_keeps_the_local_parent() {
        traced(|| {
            tracing::info_span!("local").in_scope(|| {
                let local = current_trace();
                let malformed = HashMap::from([(
                    "traceparent".to_string(),
                    serde_json::Value::String("00-not-a-trace".to_string()),
                )]);
                for metadata in [None, Some(malformed)] {
                    let mut message = request().message;
                    message.metadata = metadata;
                    let receive = tracing::info_span!("receive");
                    set_remote_parent(&receive, &message);
                    assert_eq!(receive.in_scope(current_trace), local);
                }
            });
        });
    }
}
