// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0
//
// agentbridge_demo — self-contained demo that runs without any external
// infrastructure (no SLIM node, no LLMs, no API keys required).
//
// Usage:
//   cargo run -p agentbridge_demo                         # all scenarios
//   cargo run -p agentbridge_demo -- --scenario handoff
//   cargo run -p agentbridge_demo -- --scenario coordination
//   cargo run -p agentbridge_demo -- --scenario bridge

use agentbridge::{
    adapter::{CliAdapter, CliAdapterError, CliToolAdapter},
    context::{ArtifactPayload, ConversationMessage, ContextPacket, FileSnapshot},
    mas::{
        AgentId, CoordinationEngine, DevelopmentEngine, DevelopmentEngineConfig, Epoch, EventId,
        EventMetadata, EventOutcome, EventSource, MasRuntime, PatternKind, SemanticEvent,
        SemanticPayload,
    },
};
use shadi_mas::experiments::{RecordingMessagingAdapter, RecordingTaskAdapter};
use shadi_mas::ToolProvider;
use std::sync::Arc;

// ─── Mock CLI adapters ────────────────────────────────────────────────────────

/// Simulates a real CLI coding-agent subprocess. In production this would be
/// `ClaudeCodeAdapter`, `CopilotAdapter`, `CodexAdapter`, or `CursorAgentAdapter`.
struct MockCodingAgent {
    id: AgentId,
    generated_code: &'static str,
    style_note: &'static str,
}

impl CliAdapter for MockCodingAgent {
    fn agent_id(&self) -> &AgentId {
        &self.id
    }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        let mut pkt = ContextPacket::new(self.id.0.clone());
        pkt.conversation.push(ConversationMessage {
            role: "user".to_string(),
            content: "implement a JSON parser function in Rust".to_string(),
        });
        pkt.conversation.push(ConversationMessage {
            role: "assistant".to_string(),
            content: format!(
                "Here is my implementation ({}):\n{}",
                self.style_note, self.generated_code
            ),
        });
        pkt.code_context.files.push(FileSnapshot {
            path: "src/parser.rs".to_string(),
            content: self.generated_code.to_string(),
        });
        pkt.code_context.active_file = Some("src/parser.rs".to_string());
        pkt.code_context.project_root = Some("/workspace/json-parser".to_string());
        pkt.artifacts.push(ArtifactPayload {
            name: "parser.rs".to_string(),
            content: self.generated_code.to_string(),
            media_type: "text/x-rust".to_string(),
        });
        Ok(pkt)
    }

    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError> {
        println!(
            "  [{agent}] <- receiving handoff from '{source}': \
             {msgs} messages, {files} files, {arts} artifacts",
            agent = self.id.0,
            source = ctx.source_agent,
            msgs = ctx.conversation.len(),
            files = ctx.code_context.files.len(),
            arts = ctx.artifacts.len(),
        );
        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        let preview: String = prompt.chars().take(60).collect();
        println!("  [{}] prompt: \"{}...\"", self.id.0, preview);
        println!(
            "  [{}] -> {}: {}",
            self.id.0,
            self.style_note,
            self.generated_code.lines().next().unwrap_or("").trim()
        );
        Ok(self.generated_code.to_string())
    }
}

// ─── Four mock agents with distinct implementation styles ─────────────────────

fn claude_code_agent() -> MockCodingAgent {
    MockCodingAgent {
        id: AgentId("claude-code".to_string()),
        style_note: "Result<Value,Error> — idiomatic, zero-cost propagation",
        generated_code: "\
pub fn parse(input: &str) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(input)
}",
    }
}

fn copilot_agent() -> MockCodingAgent {
    MockCodingAgent {
        id: AgentId("copilot".to_string()),
        style_note: "Option<Value> — absorbs parse errors into None",
        generated_code: "\
pub fn parse(input: &str) -> Option<serde_json::Value> {
    serde_json::from_str(input).ok()
}",
    }
}

fn codex_agent() -> MockCodingAgent {
    MockCodingAgent {
        id: AgentId("codex".to_string()),
        style_note: "Value with unwrap_or_default — tolerant, never panics",
        generated_code: "\
pub fn parse(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_default()
}",
    }
}

fn cursor_agent() -> MockCodingAgent {
    MockCodingAgent {
        id: AgentId("cursor-agent".to_string()),
        style_note: "Box<dyn Error> — ergonomic for callers using ?",
        generated_code: "\
/// Parse a JSON string into a dynamic Value.
pub fn parse(json: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(json)?)
}",
    }
}

// ─── Event helpers ────────────────────────────────────────────────────────────

fn proposal_event(agent: &str, epoch: u64, code: &[u8]) -> SemanticEvent {
    SemanticEvent {
        pattern: PatternKind::Development,
        metadata: EventMetadata {
            event_id: EventId(format!("prop-{agent}-e{epoch}")),
            correlation_id: None,
            epoch: Epoch(epoch),
            source: EventSource::Peer(AgentId(agent.to_string())),
        },
        payload: SemanticPayload::ExternalBytes(code.to_vec()),
    }
}

fn vote_event(voter: &str, endorsee: &str, epoch: u64) -> SemanticEvent {
    SemanticEvent {
        pattern: PatternKind::Development,
        metadata: EventMetadata {
            event_id: EventId(format!("vote-{voter}-e{epoch}")),
            correlation_id: None,
            epoch: Epoch(epoch),
            source: EventSource::Peer(AgentId(voter.to_string())),
        },
        payload: SemanticPayload::ToolResult {
            tool_name: endorsee.to_string(),
            accepted: true,
        },
    }
}

// ─── Scenario 1: Context handoff chain ───────────────────────────────────────

fn demo_handoff() {
    println!("\n===================================================");
    println!(" SCENARIO 1: Context Handoff Chain");
    println!(" claude-code -> copilot -> codex -> cursor-agent");
    println!("===================================================\n");

    let claude = claude_code_agent();
    let copilot = copilot_agent();
    let codex = codex_agent();
    let cursor = cursor_agent();
    let successors: &[&dyn CliAdapter] = &[&copilot, &codex, &cursor];

    // Snapshot from the first agent.
    let ctx = claude.snapshot_context().expect("snapshot");
    println!(
        "[claude-code] snapshotted context: id={id} msgs={msgs} files={files} artifacts={arts}",
        id = &ctx.id[..8],
        msgs = ctx.conversation.len(),
        files = ctx.code_context.files.len(),
        arts = ctx.artifacts.len(),
    );

    // Serialize (simulates A2A transport payload).
    let bytes = ctx.to_bytes().expect("serialize");
    println!("\n[transport] serialized -> {} bytes", bytes.len());

    // Each successor receives the packet.
    let restored = ContextPacket::from_bytes(&bytes).expect("deserialize");
    println!("[transport] deserialized at destination\n");

    for successor in successors {
        successor.inject_context(&restored).expect("inject");
    }

    println!("\n[OK] Handoff chain complete: all 3 successors received the claude-code context.\n");
}

// ─── Scenario 2: 4-agent autonomous coordination ─────────────────────────────

fn demo_coordination() {
    println!("\n===================================================");
    println!(" SCENARIO 2: 4-Agent Autonomous Coordination");
    println!(" Mirrors: agentbridge coordinate \\");
    println!("   --agents claude-code,copilot,codex,cursor-agent \\");
    println!("   --quorum 4 \"implement a JSON parser in Rust\"");
    println!("===================================================\n");

    // 4 agents, quorum = 4 (all must propose), max 5 rounds.
    // This demonstrates the staggered proposal + endorsement loop:
    //   proposals 1..3 applied first (won't finalize with quorum=4)
    //   all 4 agents vote before the last proposal arrives
    //   4th proposal applied -> quorum met -> FINALIZED with votes already counted
    let config = DevelopmentEngineConfig::new(
        [
            AgentId::from("claude-code"),
            AgentId::from("copilot"),
            AgentId::from("codex"),
            AgentId::from("cursor-agent"),
        ],
        4,  // quorum: all four proposals required
        5,  // max_rounds: safety cutoff
    );
    let mut runtime = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));

    let agents = [
        claude_code_agent(),
        copilot_agent(),
        codex_agent(),
        cursor_agent(),
    ];

    let mut apply = |ev: SemanticEvent, label: &str| {
        let outcome = runtime.apply(ev);
        let tag = match &outcome {
            EventOutcome::Applied => "Applied".to_string(),
            EventOutcome::Finalized(s) => {
                format!("FINALIZED (participants={})", s.participants)
            }
            EventOutcome::Rejected(r) => format!("Rejected({r:?})"),
            EventOutcome::Deferred { .. } => "Deferred".to_string(),
        };
        println!("  {label:<55} -> {tag}");
        outcome
    };

    println!("-- Epoch 0: proposal phase ----------------------------------\n");
    println!("  Agent styles:");
    for a in &agents {
        println!("    [{}]  {}", a.id.0, a.style_note);
    }
    println!();

    // Apply proposals 1..N-1 (won't finalize when quorum=N).
    apply(
        proposal_event("claude-code", 0, agents[0].generated_code.as_bytes()),
        "[claude-code]  proposes Result<Value,Error>",
    );
    apply(
        proposal_event("copilot", 0, agents[1].generated_code.as_bytes()),
        "[copilot]      proposes Option<Value>",
    );
    apply(
        proposal_event("codex", 0, agents[2].generated_code.as_bytes()),
        "[codex]        proposes Value+unwrap_or_default",
    );

    println!("\n-- Epoch 0: endorsement phase --------------------------------\n");
    println!("  All 4 agents vote BEFORE the last proposal arrives.");
    println!("  Votes are recorded now and counted at finalization.\n");

    // Vote round: all agents endorse one proposal.
    // claude-code gets 3 votes -> wins.
    apply(
        vote_event("claude-code", "claude-code", 0),
        "[claude-code]  endorses claude-code",
    );
    apply(
        vote_event("copilot", "claude-code", 0),
        "[copilot]      endorses claude-code",
    );
    apply(
        vote_event("codex", "copilot", 0),
        "[codex]        endorses copilot",
    );
    apply(
        vote_event("cursor-agent", "claude-code", 0),
        "[cursor-agent] endorses claude-code",
    );

    println!();
    // 4th proposal triggers finalization (quorum met, votes already counted).
    let final_outcome = apply(
        proposal_event("cursor-agent", 0, agents[3].generated_code.as_bytes()),
        "[cursor-agent] proposes Box<dyn Error>  <- quorum met",
    );

    println!();
    assert!(
        matches!(final_outcome, EventOutcome::Finalized(_)),
        "Expected finalization after 4 proposals"
    );

    println!("-- Result ---------------------------------------------------\n");
    println!("  Vote tally: claude-code=3, copilot=1, codex=0, cursor-agent=0");
    println!("  Winner: claude-code (Result-based, 3/4 endorsements)\n");

    if let Some(artifact) = runtime.engine().selected_artifact(Epoch(0)) {
        println!("  Winning artifact:");
        println!("  .----------------------------------------------------.");
        for line in std::str::from_utf8(artifact).unwrap_or("(binary)").lines() {
            println!("  | {line}");
        }
        println!("  '----------------------------------------------------'");
    }

    let c = runtime.engine().counters();
    println!(
        "\n  Runtime counters: applied={} finalized={} rejected={} deferred={}",
        c.applied, c.finalized, c.rejected, c.deferred
    );

    println!("\n[OK] Coordination complete. In production, replace MockCodingAgent with");
    println!("     ClaudeCodeAdapter, CopilotAdapter, CodexAdapter, CursorAgentAdapter.\n");
}

// ─── Scenario 3: CliToolAdapter bridge ───────────────────────────────────────

fn demo_tool_adapter_bridge() {
    println!("\n===================================================");
    println!(" SCENARIO 3: CliAdapter -> ToolAdapter bridge");
    println!(" Any CliAdapter can participate in MasRuntime coordination");
    println!("===================================================\n");

    let agent = Arc::new(claude_code_agent());
    let tool_adapter = CliToolAdapter::new(Arc::clone(&agent));

    let messaging = RecordingMessagingAdapter::default();
    let tasks = RecordingTaskAdapter::default();

    println!("[1] CliToolAdapter wraps MockCodingAgent(claude-code) as a shadi_mas ToolAdapter");
    println!("    provider = {:?}", tool_adapter.provider());

    use shadi_mas::{ToolAdapter, ToolCall};
    let call = ToolCall {
        provider: ToolProvider::AgentSkills,
        tool_name: "execute_prompt".to_string(),
        arguments: b"implement a JSON parser in Rust".to_vec(),
        target: None,
        correlation_id: Some("demo-corr-001".to_string()),
        epoch: Epoch(0),
    };

    println!("[2] Dispatching tool call: {:?}", std::str::from_utf8(&call.arguments).unwrap());
    let result = tool_adapter.call(call).expect("tool call");
    println!("[3] Tool result: {} bytes", result.payload.len());

    let recorded_msgs = messaging.published_messages().unwrap();
    let recorded_tasks = tasks.dispatched_tasks().unwrap();
    println!(
        "[4] Recording adapters: {} messages, {} tasks (no live infra in this demo)",
        recorded_msgs.len(),
        recorded_tasks.len()
    );

    println!("\n[OK] CliToolAdapter bridge works. MasRuntime<DevelopmentEngine> calls this");
    println!("     adapter for each agent during coordination rounds.\n");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let scenario = args
        .iter()
        .find(|a| a.starts_with("--scenario=") || *a == "--scenario")
        .and_then(|a| {
            if let Some((_, value)) = a.split_once('=') {
                Some(value.to_string())
            } else {
                args.iter()
                    .skip_while(|b| *b != "--scenario")
                    .nth(1)
                    .cloned()
            }
        });

    println!("+==========================================================+");
    println!("|             agentbridge demo                              |");
    println!("|  4-agent CLI coding-tool interconnect                    |");
    println!("|  claude-code  copilot  codex  cursor-agent               |");
    println!("|  no external infrastructure required                     |");
    println!("+==========================================================+");

    match scenario.as_deref() {
        Some("handoff")      => demo_handoff(),
        Some("coordination") => demo_coordination(),
        Some("bridge")       => demo_tool_adapter_bridge(),
        Some(other) => {
            eprintln!("Unknown scenario: {other}. Valid: handoff, coordination, bridge");
            std::process::exit(1);
        }
        None => {
            demo_handoff();
            demo_coordination();
            demo_tool_adapter_bridge();
            println!("----------------------------------------------------------");
            println!(" All scenarios complete.");
            println!();
            println!(" To run with real agents:");
            println!("   agentbridge coordinate \\");
            println!("     --agents claude-code,copilot,codex,cursor-agent \\");
            println!("     --quorum 4 \\");
            println!("     \"implement a JSON parser in Rust\"");
            println!("----------------------------------------------------------");
        }
    }
}
