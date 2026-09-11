use serde::{Deserialize, Serialize};

/// ASSEMBLY / CONVERGE phases. ASSEMBLY is open-ended joint modeling.
/// CONVERGE is the epoch engine that applies a mapped class update.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolPhase {
    Assembly,
    Converge,
}

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

#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Epoch(pub u64);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternKind {
    Preference,
    Cascade,
    Resource,
    Development,
    /// ASSEMBLY named a class SHADI does not implement. CONVERGE must not pretend it solved it.
    Unmapped,
}

impl PatternKind {
    pub fn paper_examples() -> &'static [PatternKind] {
        &[Self::Preference, Self::Cascade, Self::Resource]
    }

    /// True when CONVERGE uses the scalar paper driver (`ConvergeController`).
    /// `Development` is also a CONVERGE class; it uses the artifact driver.
    pub fn is_converge_class(self) -> bool {
        matches!(self, Self::Preference | Self::Cascade | Self::Resource)
    }

    pub fn parse_name(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "preference" | "preference-aggregation" | "jacobi" => Some(Self::Preference),
            "cascade" | "supply-chain" | "supply_chain" | "beer" => Some(Self::Cascade),
            "resource" | "allocation" | "fishbanks" => Some(Self::Resource),
            "development" | "dev" => Some(Self::Development),
            "unmapped" | "unknown" | "other" => Some(Self::Unmapped),
            _ => None,
        }
    }

    pub fn parse_cli(raw: &str) -> Result<Self, String> {
        Self::parse_name(raw).ok_or_else(|| {
            format!("unknown pattern {raw:?} (development|preference|cascade|resource|unmapped)")
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preference => "preference",
            Self::Cascade => "cascade",
            Self::Resource => "resource",
            Self::Development => "development",
            Self::Unmapped => "unmapped",
        }
    }
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

/// Quadratic-preference announcement. `value` is the agent's current `z_i`
/// (or a neighbor view of it). Distinct from [`Proposal`], which stays `i64`
/// for vote-style payloads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScalarProposal {
    pub participant: AgentId,
    pub value: f64,
}

/// CONVERGE STOP / CONTINUE after an improvement signal.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvergeDecision {
    Continue,
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergeBallot {
    pub participant: AgentId,
    pub decision: ConvergeDecision,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvergeHalt {
    MajorityStop,
    Plateau,
    PaperHorizon,
    Unmapped,
    NoSolution,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConvergeSignal {
    pub epoch: Epoch,
    pub metric: f64,
    pub previous: Option<f64>,
    pub delta: f64,
    pub improved: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SemanticPayload {
    Proposal(Proposal),
    Vote(Vote),
    Sensitivity(Sensitivity),
    ScalarProposal(ScalarProposal),
    ConvergeBallot(ConvergeBallot),
    ToolResult { tool_name: String, accepted: bool },
    TaskResult { task_id: String, accepted: bool },
    ExternalBytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_maps_aliases_and_unmapped() {
        assert_eq!(
            PatternKind::parse_name("jacobi"),
            Some(PatternKind::Preference)
        );
        assert_eq!(
            PatternKind::parse_name("supply-chain"),
            Some(PatternKind::Cascade)
        );
        assert_eq!(
            PatternKind::parse_name("fishbanks"),
            Some(PatternKind::Resource)
        );
        assert_eq!(
            PatternKind::parse_name("dev"),
            Some(PatternKind::Development)
        );
        assert_eq!(
            PatternKind::parse_name("other"),
            Some(PatternKind::Unmapped)
        );
        assert_eq!(PatternKind::parse_name("not-a-class"), None);
    }

    #[test]
    fn parse_cli_rejects_unknown_and_accepts_unmapped() {
        assert_eq!(
            PatternKind::parse_cli("unmapped").unwrap(),
            PatternKind::Unmapped
        );
        assert!(PatternKind::parse_cli("nope").is_err());
    }

    #[test]
    fn paper_examples_use_scalar_driver_development_does_not() {
        for kind in PatternKind::paper_examples() {
            assert!(kind.is_converge_class());
        }
        assert!(!PatternKind::Development.is_converge_class());
        assert!(!PatternKind::Unmapped.is_converge_class());
    }
}
