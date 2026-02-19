// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub agent_id: String,
    pub session_id: String,
    pub verified: bool,
    pub claims: Vec<String>,
}

impl SessionContext {
    pub fn new(agent_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            verified: false,
            claims: Vec::new(),
        }
    }
}
