use agentbridge::{
    adapter::CliToolAdapter,
    adapters::generic_stdio::GenericStdioAdapter,
    mas::{
        infer_pattern, parse_announce, parse_converge_vote, AgentId, AssemblySession,
        CascadeEngine, CascadeEngineConfig, ConvergeBallot, ConvergeController, ConvergeHalt,
        ConvergeSurface, CoordinationEngine, DevelopmentEngine, DevelopmentEngineConfig, Epoch,
        EventId, EventMetadata, EventOutcome, EventSource, MasRuntime, PatternKind,
        PreferenceEngine, PreferenceEngineConfig, ResourceEngine, ResourceEngineConfig,
        SemanticEvent, SemanticPayload,
    },
    open_profile_adapter,
};
use shadi_mas::{
    experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig},
    TaskAdapter, ToolAdapter, ToolCall, ToolProvider, ToolResult,
};
use std::sync::{Arc, Mutex};

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
/// 1. Agent 1 proposes → engine: Applied (1/N)
/// 2. Agent 2 proposes → engine: Applied (2/N), then a vote round
/// 3. Agent 3 proposes → engine: Applied (3/N), then a vote round
/// 4. Agent N proposes → engine: FINALIZED (votes already counted)
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
    slim_endpoint: &str,
    pattern: PatternKind,
    assembly: bool,
) -> anyhow::Result<()> {
    let agents = build_agents(agent_specs, slim_endpoint)?;
    if agents.is_empty() {
        anyhow::bail!(
            "no agents specified — use --agents claude-code,cursor-agent,copilot,codex \
             or --agents generic-stdio:<cmd>"
        );
    }

    let mut pattern = pattern;
    if assembly || pattern == PatternKind::Unmapped {
        pattern = run_assembly(goal, &agents, pattern)?;
    }
    if pattern.is_converge_class() {
        return run_converge(goal, &agents, max_rounds, pattern);
    }
    if pattern == PatternKind::Unmapped {
        anyhow::bail!("ASSEMBLY inferred an unmapped class; CONVERGE will not start");
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
                        if valid {
                            ""
                        } else {
                            " (unrecognised — skipped)"
                        }
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
            println!(
                "\n  🏆 Finalized at epoch {} ({} participants)",
                s.epoch.0, s.participants
            );
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

    finish(
        &runtime,
        max_rounds.saturating_sub(1),
        output,
        require_human,
    )
}

fn run_assembly(
    goal: &str,
    agents: &[AgentEntry],
    seed: PatternKind,
) -> anyhow::Result<PatternKind> {
    let mut session = AssemblySession::default();
    if seed.is_converge_class() {
        session.inferred = Some(seed);
    }
    println!("─── ASSEMBLY: model the problem ───");
    println!("Goal: {goal}\n");
    for agent in agents {
        let prompt = format!(
            "phase=ASSEMBLY\nGoal: {goal}\n\
             Understand this problem with your peers. Propose a system model.\n\
             You may name a class beyond Preference, Cascade, or Resource.\n\
             End with one line: CLASS <name>\nNo other protocol."
        );
        match invoke_tool(&agent.tool, &prompt, &agent.id.0, "assembly", 0) {
            Ok(text) => {
                println!("  [{}] {}", agent.id.0, truncate(&text, 160));
                session.ingest(text);
            }
            Err(e) => println!("  [{}] ASSEMBLY failed: {e}", agent.id.0),
        }
    }
    let inferred = session
        .inferred
        .or_else(|| infer_pattern(goal))
        .unwrap_or(PatternKind::Unmapped);
    println!("ASSEMBLY inferred {}\n", inferred.as_str());
    Ok(inferred)
}

fn run_converge(
    goal: &str,
    agents: &[AgentEntry],
    max_rounds: u64,
    pattern: PatternKind,
) -> anyhow::Result<()> {
    let ids: Vec<AgentId> = agents.iter().map(|a| a.id.clone()).collect();
    match pattern {
        PatternKind::Preference => {
            let cfg = PreferenceEngineConfig::line_with_participants(ids.clone(), 8.0, 0.75)
                .map_err(anyhow::Error::msg)?;
            let engine = PreferenceEngine::new(Epoch(0), cfg);
            drive_converge(goal, agents, engine, max_rounds.max(1))
        }
        PatternKind::Cascade => {
            let cfg = CascadeEngineConfig::scaled(ids.clone()).map_err(anyhow::Error::msg)?;
            let horizon = max_rounds.min(cfg.paper_horizon()).max(1);
            let engine = CascadeEngine::new(Epoch(0), cfg);
            drive_converge(goal, agents, engine, horizon)
        }
        PatternKind::Resource => {
            let cfg = ResourceEngineConfig::scaled(ids.clone()).map_err(anyhow::Error::msg)?;
            let horizon = max_rounds.min(cfg.paper_horizon).max(1);
            let engine = ResourceEngine::new(Epoch(0), cfg);
            drive_converge(goal, agents, engine, horizon)
        }
        _ => anyhow::bail!("CONVERGE requires preference, cascade, or resource"),
    }
}

fn drive_converge<E: ConvergeSurface>(
    goal: &str,
    agents: &[AgentEntry],
    engine: E,
    horizon: u64,
) -> anyhow::Result<()> {
    let ids: Vec<AgentId> = agents.iter().map(|a| a.id.clone()).collect();
    let mut runtime = MasRuntime::new(engine);
    let mut ctl = ConvergeController::new(ids, horizon, runtime.engine().lower_is_better(), 3);
    println!(
        "Starting CONVERGE: {} agents, pattern={}, horizon={horizon}",
        agents.len(),
        runtime.engine().pattern().as_str()
    );
    println!("Goal: {goal}\n");

    for epoch in 0..horizon {
        if ctl.halt().is_some() {
            break;
        }
        println!("─── CONVERGE epoch {epoch}: announce ───");
        ctl.begin_epoch();
        let mut last = EventOutcome::Applied;
        for agent in agents {
            let view = runtime.engine().local_view(&agent.id);
            let fallback = runtime.engine().current_value(&agent.id).unwrap_or(0.0);
            let prompt = format!(
                "phase=CONVERGE\nGoal: {goal}\nepoch={epoch}\n{view}\n\
                 Announce the printed local value. Do not compute the next number.\n\
                 ANNOUNCE value=<f64> agent={} epoch={epoch}\nThen VOTE CONTINUE or VOTE STOP.\n",
                agent.id.0
            );
            let announced = match invoke_tool(&agent.tool, &prompt, &agent.id.0, "converge", epoch)
            {
                Ok(text) => {
                    println!("  [{}] {}", agent.id.0, truncate(&text, 120));
                    if let Some(decision) = parse_converge_vote(&text) {
                        ctl.vote(ConvergeBallot {
                            participant: agent.id.clone(),
                            decision,
                        });
                    }
                    parse_announce(&text).unwrap_or(fallback)
                }
                Err(e) => {
                    println!("  [{}] announce failed: {e}", agent.id.0);
                    fallback
                }
            };
            let ev = runtime.engine().announce_event(
                &agent.id,
                epoch,
                announced,
                &format!("ann-{}-e{epoch}", agent.id.0),
            );
            last = runtime.apply(ev);
        }
        if let EventOutcome::Finalized(ref summary) = last {
            let metric = runtime.engine().metric();
            let signal = ctl.record_metric(summary.epoch, metric);
            println!(
                "  finalized epoch {} metric={:.6} delta={:.6} improved={}",
                summary.epoch.0, signal.metric, signal.delta, signal.improved
            );
        }
        if ctl.conclude_votes().is_some() {
            break;
        }
    }

    match ctl.halt() {
        Some(ConvergeHalt::MajorityStop) => println!("CONVERGE halt: majority STOP"),
        Some(ConvergeHalt::Plateau) => println!("CONVERGE halt: plateau"),
        Some(ConvergeHalt::PaperHorizon) => println!("CONVERGE halt: paper horizon"),
        Some(ConvergeHalt::NoSolution) => println!("CONVERGE halt: no solution"),
        Some(ConvergeHalt::Unmapped) => println!("CONVERGE halt: unmapped class"),
        None => println!("CONVERGE halt: max rounds"),
    }
    let c = runtime.engine().counters();
    println!(
        "Counters: applied={} finalized={} rejected={} deferred={}",
        c.applied, c.finalized, c.rejected, c.deferred
    );
    Ok(())
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

// ─── SLIM remote tool adapter ─────────────────────────────────────────────────

struct SlimToolAdapter {
    agent_id: String,
    inner: LiveA2ATaskAdapter,
    dispatch_count: Mutex<usize>,
}

impl ToolAdapter for SlimToolAdapter {
    fn provider(&self) -> ToolProvider {
        ToolProvider::AgentSkills
    }

    fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
        let idx = {
            let mut count = self.dispatch_count.lock().map_err(|_| "lock poisoned")?;
            let v = *count;
            *count += 1;
            v
        };
        let prompt = String::from_utf8_lossy(&request.arguments);
        let phase = request
            .correlation_id
            .as_deref()
            .and_then(|c| c.split('-').next())
            .unwrap_or("?");
        let epoch = request.epoch.0;

        println!("\n┌─ A2A ─→ {} [{}] epoch {}", self.agent_id, phase, epoch);
        println!("│  {}", truncate(&prompt, 120));
        println!("└─────────────────────────────────────────────────────────");

        let task = shadi_mas::TaskEnvelope {
            task_id: format!("slim-tool-{idx}"),
            pattern: PatternKind::Development,
            epoch: request.epoch,
            correlation_id: request.correlation_id.clone(),
            body: request.arguments,
        };

        let started = std::time::Instant::now();
        self.inner.dispatch(task)?;
        let elapsed_ms = started.elapsed().as_millis();

        let dispatches = self.inner.dispatches()?;
        let record = dispatches.get(idx);
        let response_str = record.map(|r| r.response.as_str()).unwrap_or("");

        println!("\n┌─ A2A ←─ {} ({} ms)", self.agent_id, elapsed_ms);
        println!("│  {}", truncate(response_str, 120));
        println!("└─────────────────────────────────────────────────────────\n");

        let payload = record
            .map(|r| r.response.as_bytes().to_vec())
            .unwrap_or_default();
        Ok(ToolResult {
            provider: ToolProvider::AgentSkills,
            tool_name: request.tool_name,
            payload,
            target: request.target,
            correlation_id: request.correlation_id,
            epoch: request.epoch,
        })
    }
}

fn truncate(s: &str, max: usize) -> String {
    let first_line = s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s);
    if first_line.len() > max {
        format!("{}…", &first_line[..max])
    } else {
        first_line.to_string()
    }
}

// ─── Agent spec parser ────────────────────────────────────────────────────────

fn build_agents(specs: &[String], slim_endpoint: &str) -> anyhow::Result<Vec<AgentEntry>> {
    let mut agents = Vec::new();
    for spec in specs {
        let (id_str, tool): (String, Arc<dyn ToolAdapter>) = if let Some((id, adapter)) =
            open_profile_adapter(spec).map_err(|e| anyhow::anyhow!("{e}"))?
        {
            (
                id,
                Arc::new(CliToolAdapter::new(Arc::new(adapter))) as Arc<dyn ToolAdapter>,
            )
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
        } else if let Some(rest) = spec.strip_prefix("slim:") {
            // Format: slim:<agent-id>  or  slim:<agent-id>@<host:port>
            let (agent_id, endpoint) = rest
                .split_once('@')
                .map(|(id, ep)| (id.to_string(), ep.to_string()))
                .unwrap_or_else(|| (rest.to_string(), slim_endpoint.to_string()));
            let config = LiveA2ATaskAdapterConfig {
                endpoint: endpoint.clone(),
                agent_id: "coordinator".to_string(),
                local_name: Some("agntcy/shadi/coordinator-a2a".to_string()),
                peer_agent_id: agent_id.clone(),
                destination: Some(format!("agntcy/shadi/{agent_id}-a2a")),
                a2a_url: None,
                a2a_binding: None,
                peer_did: None,
            };
            let slim_adapter = Arc::new(SlimToolAdapter {
                agent_id: agent_id.clone(),
                inner: LiveA2ATaskAdapter::new(config),
                dispatch_count: Mutex::new(0),
            });
            (agent_id, slim_adapter as Arc<dyn ToolAdapter>)
        } else {
            anyhow::bail!(
                "unknown agent spec '{spec}'. Supported: a profile id \
                 (claude-code[:/path], …), generic-stdio:<command>, \
                 slim:<agent-id>[@ <host:port>]"
            );
        };
        agents.push(AgentEntry {
            id: AgentId(id_str),
            tool,
        });
    }
    Ok(agents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadi_mas::{SemanticPayload, ToolResult};

    struct MockTool;

    impl ToolAdapter for MockTool {
        fn provider(&self) -> ToolProvider {
            ToolProvider::AgentSkills
        }

        fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
            Ok(ToolResult {
                provider: ToolProvider::AgentSkills,
                tool_name: request.tool_name,
                payload: b"mock-response".to_vec(),
                target: request.target,
                correlation_id: request.correlation_id,
                epoch: request.epoch,
            })
        }
    }

    #[test]
    fn proposal_prompt_without_prior_requests_fresh_implementation() {
        let prompt = proposal_prompt("build a parser", 0, &[]);
        assert!(prompt.contains("Goal: build a parser"));
        assert!(prompt.contains("Epoch 0"));
        assert!(prompt.contains("ONLY source code"));
    }

    #[test]
    fn proposal_prompt_with_prior_references_other_agents() {
        let prior = vec![(
            AgentId("claude-code".to_string()),
            "fn main() {}".to_string(),
        )];
        let prompt = proposal_prompt("build a parser", 1, &prior);
        assert!(prompt.contains("prior proposals"));
        assert!(prompt.contains("claude-code"));
    }

    #[test]
    fn vote_prompt_asks_for_a_single_agent_name() {
        let prompt = vote_prompt("build a parser", "[claude-code]: fn main()", 2);
        assert!(prompt.contains("Which agent"));
        assert!(prompt.contains("ONLY the agent name"));
    }

    #[test]
    fn build_proposal_list_previews_first_signature_line() {
        let proposals = vec![
            (
                AgentId("a".to_string()),
                "\nfn solve() -> u8 { 0 }\nmore".to_string(),
            ),
            (AgentId("b".to_string()), "struct S;".to_string()),
        ];
        let list = build_proposal_list(&proposals);
        assert!(list.contains("[a]: fn solve() -> u8 { 0 }"));
        assert!(list.contains("[b]: struct S;"));
    }

    #[test]
    fn proposal_event_carries_development_pattern_and_bytes() {
        let event = proposal_event(&AgentId("a".to_string()), 4, b"code");
        assert_eq!(event.pattern, PatternKind::Development);
        assert_eq!(event.metadata.event_id.0, "prop-a-e4");
        assert!(matches!(event.payload, SemanticPayload::ExternalBytes(ref b) if b == b"code"));
        assert!(matches!(event.metadata.source, EventSource::Peer(ref id) if id.0 == "a"));
    }

    #[test]
    fn vote_event_records_endorsement_as_tool_result() {
        let event = vote_event(&AgentId("voter".to_string()), "winner", 1, true);
        assert_eq!(event.metadata.event_id.0, "vote-voter-e1");
        match event.payload {
            SemanticPayload::ToolResult {
                tool_name,
                accepted,
            } => {
                assert_eq!(tool_name, "winner");
                assert!(accepted);
            }
            _ => panic!("expected tool-result payload"),
        }
    }

    #[test]
    fn truncate_shortens_long_single_lines() {
        assert_eq!(truncate("hello world", 5), "hello…");
        assert_eq!(truncate("short", 20), "short");
    }

    #[test]
    fn invoke_tool_returns_adapter_payload_as_string() {
        let tool: Arc<dyn ToolAdapter> = Arc::new(MockTool);
        let out = invoke_tool(&tool, "do it", "claude-code", "prop", 0).expect("call");
        assert_eq!(out, "mock-response");
    }

    #[test]
    fn build_agents_constructs_native_and_slim_specs() {
        let specs = vec![
            "claude-code".to_string(),
            "copilot".to_string(),
            "codex".to_string(),
            "cursor-agent".to_string(),
            "slim:peer@127.0.0.1:47357".to_string(),
        ];
        let agents = build_agents(&specs, "127.0.0.1:47357").expect("build");
        let ids: Vec<&str> = agents.iter().map(|a| a.id.0.as_str()).collect();
        assert_eq!(
            ids,
            ["claude-code", "copilot", "codex", "cursor-agent", "peer"]
        );
    }

    #[test]
    fn build_agents_rejects_unknown_specs() {
        let specs = vec!["totally-unknown".to_string()];
        assert!(build_agents(&specs, "127.0.0.1:47357").is_err());
    }

    struct ReplyTool(&'static str);

    impl ToolAdapter for ReplyTool {
        fn provider(&self) -> ToolProvider {
            ToolProvider::AgentSkills
        }

        fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
            Ok(ToolResult {
                provider: ToolProvider::AgentSkills,
                tool_name: request.tool_name,
                payload: self.0.as_bytes().to_vec(),
                target: request.target,
                correlation_id: request.correlation_id,
                epoch: request.epoch,
            })
        }
    }

    fn mock_agents(reply: &'static str, n: usize) -> Vec<AgentEntry> {
        (0..n)
            .map(|i| AgentEntry {
                id: AgentId::from(i.to_string().as_str()),
                tool: Arc::new(ReplyTool(reply)),
            })
            .collect()
    }

    #[test]
    fn assembly_infers_preference_from_class_line() {
        let inferred = run_assembly(
            "share scores",
            &mock_agents("CLASS preference\nNEXT 1", 2),
            PatternKind::Unmapped,
        )
        .expect("assembly");
        assert_eq!(inferred, PatternKind::Preference);
    }

    #[test]
    fn assembly_unknown_class_is_unmapped() {
        let inferred = run_assembly(
            "open markets",
            &mock_agents("CLASS matching-markets\nDONE", 2),
            PatternKind::Unmapped,
        )
        .expect("assembly");
        assert_eq!(inferred, PatternKind::Unmapped);
    }

    #[test]
    fn unmapped_assembly_does_not_select_a_converge_engine() {
        let inferred = run_assembly(
            "matching markets",
            &mock_agents("CLASS matching-markets", 2),
            PatternKind::Unmapped,
        )
        .unwrap();
        assert_eq!(inferred, PatternKind::Unmapped);
        assert!(!inferred.is_converge_class());
    }

    #[test]
    fn drive_converge_halts_when_all_vote_stop() {
        let agents = mock_agents("ANNOUNCE value=0.0\nVOTE STOP", 2);
        let ids: Vec<AgentId> = agents.iter().map(|a| a.id.clone()).collect();
        let cfg = PreferenceEngineConfig::line_with_participants(ids, 8.0, 0.75).expect("cfg");
        let engine = PreferenceEngine::new(Epoch(0), cfg);
        drive_converge("share scores", &agents, engine, 8).expect("converge");
    }
}
