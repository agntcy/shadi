// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! agentbridge control panel (agntcy/shadi#120) — links `agentbridge`/
//! `shadi_mas` directly rather than shelling out to the `agentbridge`
//! binary. `agentbridge_list_adapters`/`agentbridge_handoff` mirror
//! `agentbridge_cli`'s `list`/`handoff` commands; `agentbridge_delegate`/
//! `agentbridge_coordinate` mirror `delegate`/`coordinate` — that logic is
//! private to the `agentbridge_cli` binary crate, so it's reimplemented here
//! against the same public `agentbridge`/`shadi_mas` APIs rather than shared.
//!
//! `agentbridge_delegate` and the `slim:`-prefixed agent specs in
//! `agentbridge_coordinate` need `SLIM_ENDPOINT` and the DID auth env vars
//! (`SHADI_SLIM_AUTH`, `SLIM_HUMAN_SEED`, `SLIM_MEMBER_DIDS`) set in the
//! desktop app's own process environment, same as the CLI — there is no
//! desktop-specific bypass. Local agent specs (`claude-code`, `copilot`,
//! `codex`, `cursor-agent`, `generic-stdio:<cmd>`) need none of that.

use std::sync::{Arc, Mutex};

use agentbridge::adapter::CliToolAdapter;
use agentbridge::adapters::claude_code::ClaudeCodeAdapter;
use agentbridge::adapters::codex::CodexAdapter;
use agentbridge::adapters::copilot::CopilotAdapter;
use agentbridge::adapters::cursor_agent::CursorAgentAdapter;
use agentbridge::adapters::generic_stdio::GenericStdioAdapter;
use agentbridge::mas::{
    AgentId, CoordinationEngine, DevelopmentEngine, DevelopmentEngineConfig, Epoch, EventId,
    EventMetadata, EventOutcome, EventSource, MasRuntime, PatternKind, SemanticEvent,
    SemanticPayload,
};
use agentbridge::member_source::{DirLookupOptions, MemberSource, SkillSearchSource};
use agentbridge::{CliAdapter, ContextPacket};
use serde::{Deserialize, Serialize};
use shadi_mas::experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig};
use shadi_mas::{TaskAdapter, TaskEnvelope, ToolAdapter, ToolCall, ToolProvider, ToolResult};
use tauri::Emitter;

/// Tauri event name `agentbridge_coordinate` emits a [`CoordinateRoundEvent`]
/// on, once per round, while a coordination run is in flight. The frontend
/// subscribes with `listen("coordinate:round", ...)` before invoking the
/// command — this is what makes round-by-round progress visible instead of
/// only a final result (the highest-value piece of this panel, per #120).
pub const COORDINATE_ROUND_EVENT: &str = "coordinate:round";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub agent_id: String,
    pub tool: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPacketSummary {
    pub id: String,
    pub source_agent: String,
    pub conversation_messages: usize,
    pub artifacts: usize,
}

impl From<&ContextPacket> for ContextPacketSummary {
    fn from(ctx: &ContextPacket) -> Self {
        Self {
            id: ctx.id.clone(),
            source_agent: ctx.source_agent.clone(),
            conversation_messages: ctx.conversation.len(),
            artifacts: ctx.artifacts.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateResult {
    pub response: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinateRequest {
    pub goal: String,
    /// `claude-code[:/path]` | `copilot[:/path]` | `codex[:/path]` |
    /// `cursor-agent[:/path]` | `generic-stdio:<cmd>` |
    /// `slim:<agent-id>[@<host:port>]`, matching
    /// `agentbridge coordinate --agents`.
    pub agent_specs: Vec<String>,
    pub quorum: usize,
    pub max_rounds: u64,
    pub require_human: bool,
    /// Only consulted for bare `slim:<agent-id>` specs with no `@host:port`.
    pub slim_endpoint: String,
}

/// Emitted on [`COORDINATE_ROUND_EVENT`] as a coordination run progresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinateRoundEvent {
    pub round: u64,
    pub agent: String,
    /// "proposal" | "vote" | "finalized".
    pub kind: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinateResult {
    pub winning_agent: Option<String>,
    pub artifact: Option<String>,
    pub applied: u64,
    pub finalized: u64,
    pub rejected: u64,
    pub deferred: u64,
}

/// List registered adapters. DIR-backed discovery (`local_only = false`)
/// resolves candidates advertising the standard agentbridge skills, same
/// technique a SLIM group moderator uses to pull in members. Local SLIM-node
/// discovery (`local_only = true`) isn't wired yet in the CLI either — see
/// `agentbridge_cli::commands::list`.
#[tauri::command]
pub async fn agentbridge_list_adapters(
    local_only: bool,
    dir_server: String,
    gh_token: Option<String>,
) -> Result<Vec<AdapterInfo>, String> {
    if local_only {
        return Ok(Vec::new());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let source = SkillSearchSource {
            skill: "agent_orchestration/agent_coordination".to_string(),
            dir: DirLookupOptions {
                server_addr: dir_server,
                gh_token,
                limit: 20,
            },
        };
        let candidates = source.resolve()?;
        Ok(candidates
            .into_iter()
            .map(|c| AdapterInfo {
                agent_id: c.name,
                tool: c.did,
                endpoint: c.slim_endpoint,
            })
            .collect())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// Snapshot context from `from` and inject it into `to`. Phase-1 parity with
/// `agentbridge handoff`: both endpoints are `generic-stdio` subprocess
/// commands. `save_path`, if set, persists the captured packet to disk.
#[tauri::command]
pub async fn agentbridge_handoff(
    from: String,
    to: String,
    save_path: Option<String>,
) -> Result<ContextPacketSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let src = GenericStdioAdapter::spawn("source", &from, &[])
            .map_err(|e| format!("failed to spawn source '{from}': {e}"))?;
        let ctx = src
            .snapshot_context()
            .map_err(|e| format!("snapshot failed: {e}"))?;

        if let Some(path) = save_path {
            let bytes = ctx
                .to_bytes()
                .map_err(|e| format!("failed to serialize context: {e}"))?;
            std::fs::write(&path, &bytes).map_err(|e| format!("failed to save to {path}: {e}"))?;
        }

        let dst = GenericStdioAdapter::spawn("destination", &to, &[])
            .map_err(|e| format!("failed to spawn destination '{to}': {e}"))?;
        dst.inject_context(&ctx)
            .map_err(|e| format!("inject failed: {e}"))?;

        Ok(ContextPacketSummary::from(&ctx))
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// Send a single prompt to a remote adapter over A2A/SLIM.
#[tauri::command]
pub async fn agentbridge_delegate(
    prompt: String,
    to: String,
    agent_id: String,
    endpoint: String,
) -> Result<DelegateResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // LiveA2ATaskAdapter reads SLIM_ENDPOINT internally.
        std::env::set_var("SLIM_ENDPOINT", &endpoint);

        let config = LiveA2ATaskAdapterConfig {
            endpoint,
            agent_id: agent_id.clone(),
            local_name: Some(format!("agntcy/shadi/{agent_id}-a2a")),
            peer_agent_id: to.clone(),
            destination: Some(format!("agntcy/shadi/{to}-a2a")),
        };
        let adapter = LiveA2ATaskAdapter::new(config);

        let task_id = uuid::Uuid::new_v4().to_string();
        let task = TaskEnvelope {
            task_id: task_id.clone(),
            pattern: PatternKind::Development,
            epoch: Epoch(0),
            correlation_id: Some(format!("agentbridge-delegate-{task_id}")),
            body: prompt.into_bytes(),
        };

        adapter.dispatch(task)?;
        let dispatches = adapter.dispatches()?;
        let record = dispatches
            .first()
            .ok_or_else(|| "task dispatched but no response recorded".to_string())?;

        Ok(DelegateResult {
            response: record.response.clone(),
            elapsed_ms: record.elapsed_ms as u64,
        })
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

struct AgentEntry {
    id: AgentId,
    tool: Arc<dyn ToolAdapter>,
}

/// Wraps a `slim:` agent spec as a `ToolAdapter` over `LiveA2ATaskAdapter`,
/// matching `agentbridge_cli`'s private `SlimToolAdapter`.
struct SlimToolAdapter {
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
        let task = TaskEnvelope {
            task_id: format!("slim-tool-{idx}"),
            pattern: PatternKind::Development,
            epoch: request.epoch,
            correlation_id: request.correlation_id.clone(),
            body: request.arguments,
        };
        self.inner.dispatch(task)?;
        let dispatches = self.inner.dispatches()?;
        let record = dispatches.get(idx);
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

fn build_agents(specs: &[String], slim_endpoint: &str) -> Result<Vec<AgentEntry>, String> {
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
                    .map_err(|e| format!("failed to spawn {spec}: {e}"))?,
            );
            (spec.clone(), Arc::new(CliToolAdapter::new(adapter)))
        } else if let Some(rest) = spec.strip_prefix("slim:") {
            let (agent_id, endpoint) = rest
                .split_once('@')
                .map(|(id, ep)| (id.to_string(), ep.to_string()))
                .unwrap_or_else(|| (rest.to_string(), slim_endpoint.to_string()));
            std::env::set_var("SLIM_ENDPOINT", &endpoint);
            let config = LiveA2ATaskAdapterConfig {
                endpoint,
                agent_id: "coordinator".to_string(),
                local_name: Some("agntcy/shadi/coordinator-a2a".to_string()),
                peer_agent_id: agent_id.clone(),
                destination: Some(format!("agntcy/shadi/{agent_id}-a2a")),
            };
            let slim_adapter = Arc::new(SlimToolAdapter {
                inner: LiveA2ATaskAdapter::new(config),
                dispatch_count: Mutex::new(0),
            });
            (agent_id, slim_adapter as Arc<dyn ToolAdapter>)
        } else {
            return Err(format!(
                "unknown agent spec '{spec}'. Supported: claude-code[:/path], \
                 cursor-agent[:/path], copilot[:/path], codex[:/path], \
                 generic-stdio:<command>, slim:<agent-id>[@host:port]"
            ));
        };
        agents.push(AgentEntry {
            id: AgentId(id_str),
            tool,
        });
    }
    Ok(agents)
}

fn invoke_tool(tool: &Arc<dyn ToolAdapter>, prompt: &str, label: &str, phase: &str, epoch: u64) -> Result<String, String> {
    let call = ToolCall {
        provider: ToolProvider::AgentSkills,
        tool_name: "execute_prompt".to_string(),
        arguments: prompt.as_bytes().to_vec(),
        target: None,
        correlation_id: Some(format!("{phase}-{label}-e{epoch}")),
        epoch: Epoch(epoch),
    };
    tool.call(call)
        .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
}

fn proposal_prompt(goal: &str, epoch: u64, prior: &[(AgentId, String)]) -> String {
    if prior.is_empty() {
        format!(
            "Epoch {epoch}. Goal: {goal}\n\n\
             Produce a complete, compilable implementation. \
             Reply with ONLY source code — no markdown fences, no explanations."
        )
    } else {
        let prior_summary = prior
            .iter()
            .map(|(id, code)| format!("  [{}]: {}…", id.0, &code[..code.len().min(80)]))
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
            let first_line = code.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
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

/// Run `MasRuntime<DevelopmentEngine>` across a set of agents toward a goal.
/// Emits [`COORDINATE_ROUND_EVENT`] as each proposal/vote/finalization
/// happens; returns only the final winning artifact and counters.
#[tauri::command]
pub async fn agentbridge_coordinate(
    app: tauri::AppHandle,
    request: CoordinateRequest,
) -> Result<CoordinateResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let agents = build_agents(&request.agent_specs, &request.slim_endpoint)?;
        if agents.is_empty() {
            return Err("no agents specified".to_string());
        }

        let effective_quorum = request.quorum.min(agents.len());
        let config = DevelopmentEngineConfig::new(
            agents.iter().map(|a| a.id.clone()),
            effective_quorum,
            request.max_rounds,
        );
        let mut runtime = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));

        let emit = |event: CoordinateRoundEvent| {
            let _ = app.emit(COORDINATE_ROUND_EVENT, event);
        };

        let mut last_finalized_epoch = 0u64;
        let mut finalized = false;
        // Carries the most recent round's proposals out of the loop so the
        // winning artifact's bytes can be matched back to the agent that
        // proposed it — FinalizationSummary doesn't record that itself.
        let mut last_round_proposals: Vec<(AgentId, String)> = Vec::new();

        for epoch in 0..request.max_rounds {
            let mut proposals: Vec<(AgentId, String)> = Vec::new();
            for agent in &agents {
                let prompt = proposal_prompt(&request.goal, epoch, &proposals);
                match invoke_tool(&agent.tool, &prompt, &agent.id.0, "prop", epoch) {
                    Ok(code) => {
                        emit(CoordinateRoundEvent {
                            round: epoch,
                            agent: agent.id.0.clone(),
                            kind: "proposal".to_string(),
                            summary: format!("proposed {} bytes", code.len()),
                        });
                        proposals.push((agent.id.clone(), code));
                    }
                    Err(e) => emit(CoordinateRoundEvent {
                        round: epoch,
                        agent: agent.id.0.clone(),
                        kind: "proposal".to_string(),
                        summary: format!("failed: {e}"),
                    }),
                }
            }

            if proposals.is_empty() {
                return Err(format!("all agents failed to propose at epoch {epoch}"));
            }

            let last_idx = proposals.len().saturating_sub(1);
            let proposal_list = build_proposal_list(&proposals);

            for (proposer_id, code) in &proposals[..last_idx] {
                runtime.apply(proposal_event(proposer_id, epoch, code.as_bytes()));
            }

            let vote_prompt_str = vote_prompt(&request.goal, &proposal_list, epoch);
            for voter in &agents {
                match invoke_tool(&voter.tool, &vote_prompt_str, &voter.id.0, "vote", epoch) {
                    Ok(endorsee_raw) => {
                        let endorsee = endorsee_raw.trim().to_string();
                        let valid = proposals.iter().any(|(id, _)| id.0 == endorsee);
                        emit(CoordinateRoundEvent {
                            round: epoch,
                            agent: voter.id.0.clone(),
                            kind: "vote".to_string(),
                            summary: format!(
                                "endorses '{endorsee}'{}",
                                if valid { "" } else { " (unrecognised — skipped)" }
                            ),
                        });
                        runtime.apply(vote_event(&voter.id, &endorsee, epoch, valid));
                    }
                    Err(e) => emit(CoordinateRoundEvent {
                        round: epoch,
                        agent: voter.id.0.clone(),
                        kind: "vote".to_string(),
                        summary: format!("failed: {e}"),
                    }),
                }
            }

            let (last_proposer, last_code) = &proposals[last_idx];
            let outcome = runtime.apply(proposal_event(last_proposer, epoch, last_code.as_bytes()));
            if let EventOutcome::Finalized(ref s) = outcome {
                emit(CoordinateRoundEvent {
                    round: epoch,
                    agent: last_proposer.0.clone(),
                    kind: "finalized".to_string(),
                    summary: format!("finalized with {} participants", s.participants),
                });
            }

            last_round_proposals = proposals;
            last_finalized_epoch = epoch;
            if runtime.engine().selected_artifact(Epoch(epoch)).is_some() {
                finalized = true;
                break;
            }
        }

        if !finalized && request.max_rounds > 0 {
            last_finalized_epoch = request.max_rounds - 1;
        }

        let artifact_bytes = runtime
            .engine()
            .selected_artifact(Epoch(last_finalized_epoch))
            .map(|b| b.to_vec());
        let winning_agent = artifact_bytes.as_ref().and_then(|bytes| {
            last_round_proposals
                .iter()
                .find(|(_, code)| code.as_bytes() == bytes.as_slice())
                .map(|(id, _)| id.0.clone())
        });
        let artifact = artifact_bytes.map(|b| String::from_utf8_lossy(&b).into_owned());

        let c = runtime.engine().counters();
        Ok(CoordinateResult {
            winning_agent,
            artifact,
            applied: c.applied as u64,
            finalized: c.finalized as u64,
            rejected: c.rejected as u64,
            deferred: c.deferred as u64,
        })
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}
