use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl From<&str> for AgentId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

impl From<&str> for EventId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u64);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternKind {
    Preference,
    Cascade,
    Resource,
    Development,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    Local,
    Peer(AgentId),
    Tool(String),
    Task(String),
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMetadata {
    pub event_id: EventId,
    pub correlation_id: Option<String>,
    pub epoch: Epoch,
    pub source: EventSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub participant: AgentId,
    pub value: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub participant: AgentId,
    pub value: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sensitivity {
    pub participant: AgentId,
    pub delta: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticPayload {
    Proposal(Proposal),
    Vote(Vote),
    Sensitivity(Sensitivity),
    ToolResult {
        tool_name: String,
        accepted: bool,
    },
    TaskResult {
        task_id: String,
        accepted: bool,
    },
    ExternalBytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticEvent {
    pub pattern: PatternKind,
    pub metadata: EventMetadata,
    pub payload: SemanticPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizationSummary {
    pub epoch: Epoch,
    pub participants: usize,
    pub selected_value: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    DuplicateEvent,
    StaleEpoch { current: Epoch },
    FinalizedEpoch { epoch: Epoch },
    IncompatiblePattern,
    IncompatiblePayload,
    UnknownParticipant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventOutcome {
    Applied,
    Deferred { expected: Epoch, received: Epoch },
    Finalized(FinalizationSummary),
    Rejected(RejectReason),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCounters {
    pub applied: usize,
    pub rejected: usize,
    pub deferred: usize,
    pub duplicates: usize,
    pub stale: usize,
    pub finalized: usize,
}
