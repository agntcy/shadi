// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// One A2A request, as an [`AgentVerifier`](crate::AgentVerifier) sees it.
///
/// Apart from [`Self::evaluation_id`], every field is read from the message,
/// so it is the sender's claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    evaluation_id: String,
    /// The A2A message id. The sender chooses it and no signature covers it,
    /// so it must not key a decision record.
    pub message_id: Option<String>,
    /// The `did:key` the message is addressed to, when it names one.
    pub destination_did: Option<String>,
    /// The human DID whose binding was verified for the sender. Only a
    /// receiver sets it, after admission.
    pub human_did: Option<String>,
    /// The message text, set only for a verifier whose
    /// [`wants_content`](crate::AgentVerifier::wants_content) is true.
    pub content: Option<String>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            evaluation_id: next_evaluation_id(),
            message_id: None,
            destination_did: None,
            human_did: None,
            content: None,
        }
    }

    /// Generated locally for each request and never read from the message,
    /// so a peer can neither choose nor collide with it. Decision records are
    /// keyed on this.
    pub fn evaluation_id(&self) -> &str {
        &self.evaluation_id
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

fn next_evaluation_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!(
        "{:x}-{nanos:x}-{:x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_ids_are_local_and_distinct() {
        let mut first = RequestContext::new();
        first.message_id = Some("peer-chosen".to_string());
        let second = RequestContext::new();
        assert!(!first.evaluation_id().is_empty());
        assert_ne!(first.evaluation_id(), second.evaluation_id());
        assert_ne!(first.evaluation_id(), "peer-chosen");
    }
}
