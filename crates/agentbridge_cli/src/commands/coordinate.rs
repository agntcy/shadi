use agentbridge::{
    adapter::CliToolAdapter,
    adapters::{
        claude_code::ClaudeCodeAdapter,
        codex::CodexAdapter,
        copilot::CopilotAdapter,
        cursor_agent::CursorAgentAdapter,
        generic_stdio::GenericStdioAdapter,
    },
    mas::{
        AgentId, CoordinationEngine, DevelopmentEngine, DevelopmentEngineConfig, Epoch,
        EventId, EventMetadata, EventOutcome, EventSource, MasRuntime, PatternKind,
        SemanticEvent, SemanticPayload,
    },
};
use shadi_mas::ToolAdapter;
use std::sync::Arc;

struct AgentEntry {
    id: AgentId,
    tool: Arc<dyn ToolAdapter>,
}

/// Run autonomous multi-round coordination toward a programming goal.
///
/// ## Staggered proposal + endorsement loop
///
/// With N agents and quorum = N:
///
///   1. Agent 1 proposes  → engine: Applied (1/N)
///   2. Agent 2 proposes  → engine: Applied (2/N)
///      → vote round: agents 1,2 each endorse a proposal
///   3. Agent 3 proposes  → engine: Applied (3/N)
///      → vote round: agents 1,2,3 each endorse a proposal
///   ...
///   N. Agent N proposes  → engine: FINALIZED (votes already counted!)
///
/// This guarantees the endorsement phase actually runs before finalization,
/// so the winner is the agent whose implementation earned the most peer votes.
pub fn run(
    goal: &str,
    agent_specs: &[String],
    quorum: usize,
    max_rounds: u64,
    output: Option<&str>,
    require_human: bool,
) -> anyhow::Result<()> {
    let agents = build_agents(agent_specs)?;
    if agents.is_empty() {
        anyhow::bail!(
            "no agents specified — use --agents claude-code,cursor-agent,copilot,codex \
             or --agents generic-stdio:<cmd>"
        );
    }

    let effective_quorum = quorum.min(agents.len());
    let config = DevelopmentEngineConfig::new(
        agents.iter().map(|a| a.id.clone()),
        effective_quorum,
        max_rounds,
    );
    let mut runtime = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));

    println!(
        "Starting autonomous coordination: {} agents, quorum={effective_quorum}, max_rounds={max_rounds}",
        agents.len()
    );
    println!("Goal: {goal}\n");

    for epoch in 0..max_rounds {
        println!("─── Epoch {epoch}: proposal phase ───");

        // Collect all proposals for this epoch (sequential — each agent calls its LLM).
        let mut proposals: Vec<(AgentId, String)> = Vec::new();
        for agent in &agents {
            let prompt = proposal_prompt(goal, epoch, &proposals);
            match invoke_tool(&agent.tool, &prompt, &agent.id.0, "prop", epoch) {
                Ok(code) => {
                    println!("  [{}] proposed {} bytes", agent.id.0, code.len());
                    proposals.push((agent.id.clone(), code));
                }
                Err(e) => println!("  [{}] proposal failed: {e}", agent.id.0),
            }
        }

        if proposals.is_empty() {
            anyhow::bail!("all agents failed to propose at epoch {epoch}");
        }

        // Staggered voting: apply proposals 1..N-1 to the engine (won't finalize
        // when quorum=N), then run a single vote round where ALL agents evaluate
        // all proposals, then apply the Nth proposal to trigger finalization with
        // votes already counted.
        println!("\n─── Epoch {epoch}: endorsement phase ───");

        let last_idx = proposals.len().saturating_sub(1);
        let proposal_list = build_proposal_list(&proposals);

        // Apply proposals 1..N-1 (these do not trigger finalization with quorum=N).
        for (proposer_id, code) in &proposals[..last_idx] {
            let ev = proposal_event(proposer_id, epoch, code.as_bytes());
            runtime.apply(ev);
        }

        // Vote round: ALL agents evaluate all proposals and endorse one.
        // This runs before the last proposal so votes are counted at finalization.
        let vote_prompt_str = vote_prompt(goal, &proposal_list, epoch);
        for voter in &agents {
            match invoke_tool(&voter.tool, &vote_prompt_str, &voter.id.0, "vote", epoch) {
                Ok(endorsee_raw) => {
                    let endorsee = endorsee_raw.trim().to_string();
                    let valid = proposals.iter().any(|(id, _)| id.0 == endorsee);
                    println!(
                        "  [{}] endorses '{}'{}",
                        voter.id.0,
                        endorsee,
                        if valid { "" } else { " (unrecognised — skipped)" }
                    );
                    let ev = vote_event(&voter.id, &endorsee, epoch, valid);
                    runtime.apply(ev);
                }
                Err(e) => println!("  [{}] vote failed: {e}", voter.id.0),
            }
        }

        // Apply the last proposal — triggers finalization with votes counted.
        let (last_proposer, last_code) = &proposals[last_idx];
        let ev = proposal_event(last_proposer, epoch, last_code.as_bytes());
        let outcome = runtime.apply(ev);
        if let EventOutcome::Finalized(ref s) = outcome {
            println!("\n  🏆 Finalized at epoch {} ({} participants)", s.epoch.0, s.participants);
        } else {
            println!("\n  (quorum not met — will retry next round)");
        }

        // Check outcome of the last proposal.
        let engine_finalized = runtime.engine().selected_artifact(Epoch(epoch)).is_some();
        if engine_finalized {
            return finish(&runtime, epoch, output, require_human);
        }

        println!();
        if epoch + 1 >= max_rounds {
            println!("Max rounds reached — force-finalizing best artifact.");
        }
    }

    finish(&runtime, max_rounds.saturating_sub(1), output, require_human)
}

// ─── Prompt builders ─────────────────────────────────────────────────────────

fn proposal_prompt(goal: &str, epoch: u64, prior: &[(AgentId, String)]) -> String {
    if prior.is_empty() {
        format!(
            "Epoch {epoch}. Goal: {goal}\n\n\
             Produce a complete, compilable implementation. \
             Reply with ONLY source code — no markdown fences, no explanations."
        )
    } else {
        // After seeing prior proposals, agents can improve or differentiate.
        let prior_summary = prior
            .iter()
            .map(|(id, code)| {
                let preview = &code[..code.len().min(80)];
                format!("  [{}]: {}…", id.0, preview)
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "Epoch {epoch}. Goal: {goal}\n\n\
             You have seen these prior proposals from other agents:\n{prior_summary}\n\n\
             Now produce your own complete, compilable implementation. \
             Aim to differentiate from or improve on the proposals above. \
             Reply with ONLY source code — no markdown fences, no explanations."
        )
    }
}

fn vote_prompt(goal: &str, proposal_list: &str, epoch: u64) -> String {
    format!(
        "Epoch {epoch}. Goal: {goal}\n\n\
         Review these proposed implementations:\n{proposal_list}\n\n\
         Which agent produced the best implementation for the stated goal? \
         Consider: correctness, idiomatic style, error handling, and API design.\n\
         Reply with ONLY the agent name (e.g. \"claude-code\"). No other words."
    )
}

fn build_proposal_list(proposals: &[(AgentId, String)]) -> String {
    proposals
        .iter()
        .map(|(id, code)| {
            // First non-empty line gives the function signature — most diagnostic.
            let first_line = code
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            let preview = if first_line.len() > 100 {
                format!("{}…", &first_line[..100])
            } else {
                first_line.to_string()
            };
            format!("[{}]: {}", id.0, preview)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── Engine event builders ────────────────────────────────────────────────────

fn proposal_event(agent: &AgentId, epoch: u64, code: &[u8]) -> SemanticEvent {
    SemanticEvent {
        pattern: PatternKind::Development,
        metadata: EventMetadata {
            event_id: EventId(format!("prop-{}-e{epoch}", agent.0)),
            correlation_id: None,
            epoch: Epoch(epoch),
            source: EventSource::Peer(agent.clone()),
        },
        payload: SemanticPayload::ExternalBytes(code.to_vec()),
    }
}

fn vote_event(voter: &AgentId, endorsee: &str, epoch: u64, accepted: bool) -> SemanticEvent {
    SemanticEvent {
        pattern: PatternKind::Development,
        metadata: EventMetadata {
            event_id: EventId(format!("vote-{}-e{epoch}", voter.0)),
            correlation_id: None,
            epoch: Epoch(epoch),
            source: EventSource::Peer(voter.clone()),
        },
        payload: SemanticPayload::ToolResult {
            tool_name: endorsee.to_string(),
            accepted,
        },
    }
}

// ─── Tool call helper ─────────────────────────────────────────────────────────

fn invoke_tool(
    tool: &Arc<dyn ToolAdapter>,
    prompt: &str,
    agent_label: &str,
    phase: &str,
    epoch: u64,
) -> Result<String, String> {
    let call = shadi_mas::ToolCall {
        provider: shadi_mas::ToolProvider::AgentSkills,
        tool_name: "execute_prompt".to_string(),
        arguments: prompt.as_bytes().to_vec(),
        target: None,
        correlation_id: Some(format!("{phase}-{agent_label}-e{epoch}")),
        epoch: Epoch(epoch),
    };
    tool.call(call)
        .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
}

// ─── Finish ───────────────────────────────────────────────────────────────────

fn finish(
    runtime: &MasRuntime<DevelopmentEngine>,
    epoch: u64,
    output: Option<&str>,
    require_human: bool,
) -> anyhow::Result<()> {
    let artifact = runtime
        .engine()
        .selected_artifact(Epoch(epoch))
        .map(|b| String::from_utf8_lossy(b).into_owned());

    match artifact {
        None => println!("No artifact finalized."),
        Some(code) => {
            println!("\n══ Winning artifact ({} bytes) ══\n", code.len());
            println!("{code}");

            if require_human {
                print!("\nAccept this artifact? [y/N] ");
                use std::io::BufRead;
                let line = std::io::stdin()
                    .lock()
                    .lines()
                    .next()
                    .and_then(|r| r.ok())
                    .unwrap_or_default();
                if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
                    println!("Rejected by operator.");
                    return Ok(());
                }
            }

            if let Some(path) = output {
                std::fs::write(path, code.as_bytes())?;
                println!("Saved to {path}.");
            }
        }
    }

    let c = runtime.engine().counters();
    println!(
        "\nCounters: applied={} finalized={} rejected={} deferred={}",
        c.applied, c.finalized, c.rejected, c.deferred
    );
    Ok(())
}

// ─── Agent spec parser ────────────────────────────────────────────────────────

fn build_agents(specs: &[String]) -> anyhow::Result<Vec<AgentEntry>> {
    let mut agents = Vec::new();
    for spec in specs {
        let (id_str, tool): (String, Arc<dyn ToolAdapter>) = if spec.starts_with("claude-code") {
            let work_dir = spec
                .strip_prefix("claude-code:")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = Arc::new(ClaudeCodeAdapter::new("claude-code", work_dir));
            ("claude-code".to_string(), Arc::new(CliToolAdapter::new(adapter)))
        } else if spec.starts_with("cursor-agent") {
            let work_dir = spec
                .strip_prefix("cursor-agent:")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = Arc::new(CursorAgentAdapter::new("cursor-agent", work_dir));
            ("cursor-agent".to_string(), Arc::new(CliToolAdapter::new(adapter)))
        } else if spec.starts_with("copilot") {
            let work_dir = spec
                .strip_prefix("copilot:")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = Arc::new(CopilotAdapter::new("copilot", work_dir));
            ("copilot".to_string(), Arc::new(CliToolAdapter::new(adapter)))
        } else if spec.starts_with("codex") {
            let work_dir = spec
                .strip_prefix("codex:")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = Arc::new(CodexAdapter::new("codex", work_dir));
            ("codex".to_string(), Arc::new(CliToolAdapter::new(adapter)))
        } else if let Some(cmd) = spec.strip_prefix("generic-stdio:") {
            let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
            let prog = parts[0];
            let args: Vec<&str> = if parts.len() > 1 {
                parts[1].split_whitespace().collect()
            } else {
                vec![]
            };
            let adapter = Arc::new(
                GenericStdioAdapter::spawn(spec, prog, &args)
                    .map_err(|e| anyhow::anyhow!("failed to spawn {spec}: {e}"))?,
            );
            (spec.clone(), Arc::new(CliToolAdapter::new(adapter)))
        } else {
            anyhow::bail!(
                "unknown agent spec '{spec}'. Supported: \
                 claude-code[:/path], cursor-agent[:/path], \
                 copilot[:/path], codex[:/path], generic-stdio:<command>"
            );
        };
        agents.push(AgentEntry {
            id: AgentId(id_str),
            tool,
        });
    }
    Ok(agents)
}
