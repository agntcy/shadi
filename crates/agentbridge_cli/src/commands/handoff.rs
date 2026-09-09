use agentbridge::{
    adapters::generic_stdio::GenericStdioAdapter, open_profile_adapter, CliAdapter, ContextPacket,
};
use shadi_mas::{
    experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig},
    Epoch, PatternKind, TaskAdapter, TaskEnvelope,
};
use std::path::Path;
use std::sync::Arc;

/// Transfer context from one CLI tool to another.
///
/// `--from` / `--to` accept the same specs as `coordinate`:
/// `claude-code`, `copilot`, `codex`, `cursor-agent`, `goose`, `opencode`,
/// `generic-stdio:<cmd>`,
/// `slim:<id>`, plus a bare subprocess command (Phase 1 GenericStdio).
///
/// The snapshot is an LLM summary of the source session this cycle, not a
/// true session export. `--save` / `--from-file` still persist the packet.
pub fn run(
    from_spec: &str,
    to_spec: &str,
    save: Option<&str>,
    slim_endpoint: &str,
) -> anyhow::Result<()> {
    let src = open_peer(from_spec, slim_endpoint)?;
    println!("Source '{}' connected.", src.label());

    let ctx = src.snapshot().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "Captured context (LLM session summary, not a full export): {} messages, {} files, {} artifacts.",
        ctx.conversation.len(),
        ctx.code_context.files.len(),
        ctx.artifacts.len(),
    );

    if let Some(path) = save {
        let bytes = ctx.to_bytes()?;
        std::fs::write(path, &bytes)?;
        println!("Context saved to {path}.");
    }

    let dst = open_peer(to_spec, slim_endpoint)?;
    println!("Destination '{}' connected.", dst.label());
    dst.inject(&ctx).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Context successfully handed off to '{}'.", dst.label());
    Ok(())
}

/// Load a previously saved `ContextPacket` from disk and inject it into a
/// destination adapter. Useful for resuming after a crash.
pub fn run_from_file(
    context_path: &Path,
    to_spec: &str,
    slim_endpoint: &str,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(context_path)?;
    let ctx = ContextPacket::from_bytes(&bytes)?;
    println!(
        "Loaded context from '{}': {} messages.",
        context_path.display(),
        ctx.conversation.len(),
    );

    let dst = open_peer(to_spec, slim_endpoint)?;
    dst.inject(&ctx).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Context injected into '{}'.", dst.label());
    Ok(())
}

enum HandoffPeer {
    Local {
        label: String,
        adapter: Arc<dyn CliAdapter>,
    },
    Slim {
        agent_id: String,
        adapter: LiveA2ATaskAdapter,
    },
    /// The calling process *is* this agent (`SHADI_AGENT_ID` matches
    /// `slim:<id>`). Snapshot stays local so we do not A2A-deadlock on
    /// our own listener. Inject is not used on this variant.
    SelfSlim { agent_id: String },
}

impl HandoffPeer {
    fn label(&self) -> &str {
        match self {
            HandoffPeer::Local { label, .. } => label,
            HandoffPeer::Slim { agent_id, .. } => agent_id,
            HandoffPeer::SelfSlim { agent_id } => agent_id,
        }
    }

    fn snapshot(&self) -> Result<ContextPacket, String> {
        match self {
            HandoffPeer::Local { adapter, .. } => {
                adapter.snapshot_context().map_err(|e| e.to_string())
            }
            HandoffPeer::SelfSlim { agent_id } => {
                let summary = format!(
                    "{agent_id} finished a coding turn and is handing off as an A2A client."
                );
                let mut pkt = ContextPacket::new(agent_id.clone());
                pkt.conversation.push(agentbridge::ConversationMessage {
                    role: "assistant".to_string(),
                    content: summary.clone(),
                });
                pkt.artifacts.push(agentbridge::ArtifactPayload {
                    name: "session_summary.md".to_string(),
                    content: summary,
                    media_type: "text/markdown".to_string(),
                });
                Ok(pkt)
            }
            HandoffPeer::Slim { agent_id, adapter } => {
                let summary = dispatch_prompt(
                    adapter,
                    "Summarize this session for handoff: current goal, key decisions, files changed, what remains.",
                )?;
                let mut pkt = ContextPacket::new(agent_id.clone());
                pkt.conversation.push(agentbridge::ConversationMessage {
                    role: "assistant".to_string(),
                    content: summary.clone(),
                });
                pkt.artifacts.push(agentbridge::ArtifactPayload {
                    name: "session_summary.md".to_string(),
                    content: summary,
                    media_type: "text/markdown".to_string(),
                });
                Ok(pkt)
            }
        }
    }

    fn inject(&self, ctx: &ContextPacket) -> Result<(), String> {
        match self {
            HandoffPeer::Local { adapter, .. } => {
                adapter.inject_context(ctx).map_err(|e| e.to_string())
            }
            HandoffPeer::Slim { adapter, .. } => {
                let prompt = render_inject_prompt(ctx);
                let _ = dispatch_prompt(adapter, &prompt)?;
                Ok(())
            }
            HandoffPeer::SelfSlim { agent_id } => Err(format!(
                "cannot A2A-inject into self ({agent_id}); destination must be another peer"
            )),
        }
    }
}

fn dispatch_prompt(adapter: &LiveA2ATaskAdapter, prompt: &str) -> Result<String, String> {
    let task_id = format!("handoff-{}", uuid::Uuid::new_v4());
    adapter.dispatch(TaskEnvelope {
        task_id: task_id.clone(),
        pattern: PatternKind::Development,
        epoch: Epoch(0),
        correlation_id: Some(task_id),
        body: prompt.as_bytes().to_vec(),
    })?;
    let dispatches = adapter.dispatches()?;
    dispatches
        .last()
        .map(|record| record.response.clone())
        .ok_or_else(|| "handoff dispatch produced no response".to_string())
}

fn render_inject_prompt(ctx: &ContextPacket) -> String {
    let mut system = format!(
        "You are continuing a coding session from {}.\n\n",
        ctx.source_agent
    );
    for msg in &ctx.conversation {
        system.push_str(&format!("[{}]: {}\n", msg.role, msg.content));
    }
    for art in &ctx.artifacts {
        system.push_str(&format!("\n## {}\n{}\n", art.name, art.content));
    }
    system.push_str("\nAcknowledge you have received the handoff context.");
    system
}

fn open_peer(spec: &str, slim_endpoint: &str) -> anyhow::Result<HandoffPeer> {
    if let Some((label, adapter)) =
        open_profile_adapter(spec).map_err(|e| anyhow::anyhow!("{e}"))?
    {
        return Ok(HandoffPeer::Local {
            label,
            adapter: Arc::new(adapter),
        });
    }
    if let Some(cmd) = spec.strip_prefix("generic-stdio:") {
        return spawn_stdio("generic-stdio", cmd);
    }
    if let Some(rest) = spec.strip_prefix("slim:") {
        let (agent_id, endpoint) = rest
            .split_once('@')
            .map(|(id, ep)| (id.to_string(), ep.to_string()))
            .unwrap_or_else(|| (rest.to_string(), slim_endpoint.to_string()));
        // Prove as the calling agent (SHADI_AGENT_ID), not a synthetic
        // "handoff" name — that DID is not on SLIM_MEMBER_DIDS and SLIM
        // drops discovery with InvalidSignature.
        let local_id = std::env::var("SHADI_AGENT_ID").unwrap_or_else(|_| "avatar".to_string());
        if local_id == agent_id {
            return Ok(HandoffPeer::SelfSlim { agent_id });
        }
        let config = LiveA2ATaskAdapterConfig {
            endpoint,
            agent_id: local_id.clone(),
            local_name: Some(format!("agntcy/shadi/{local_id}-a2a")),
            peer_agent_id: agent_id.clone(),
            destination: Some(format!("agntcy/shadi/{agent_id}-a2a")),
            a2a_url: None,
            a2a_binding: None,
            peer_did: None,
        };
        return Ok(HandoffPeer::Slim {
            agent_id,
            adapter: LiveA2ATaskAdapter::new(config),
        });
    }
    spawn_stdio(spec, spec)
}

fn spawn_stdio(label: &str, cmd: &str) -> anyhow::Result<HandoffPeer> {
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let prog = parts[0];
    let args: Vec<&str> = if parts.len() > 1 {
        parts[1].split_whitespace().collect()
    } else {
        vec![]
    };
    let adapter = GenericStdioAdapter::spawn(label, prog, &args)
        .map_err(|e| anyhow::anyhow!("failed to spawn {label}: {e}"))?;
    Ok(HandoffPeer::Local {
        label: label.to_string(),
        adapter: Arc::new(adapter),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_peer_accepts_native_and_slim_specs() {
        let claude = open_peer("claude-code", "127.0.0.1:47357").expect("claude");
        assert_eq!(claude.label(), "claude-code");
        let copilot = open_peer("copilot", "127.0.0.1:47357").expect("copilot");
        assert_eq!(copilot.label(), "copilot");
        let codex = open_peer("codex", "127.0.0.1:47357").expect("codex");
        assert_eq!(codex.label(), "codex");
        let cursor = open_peer("cursor-agent", "127.0.0.1:47357").expect("cursor");
        assert_eq!(cursor.label(), "cursor-agent");
        match open_peer("slim:peer@10.0.0.1:9", "127.0.0.1:47357").expect("slim") {
            HandoffPeer::Slim { agent_id, .. } => assert_eq!(agent_id, "peer"),
            other => panic!("expected slim peer, got {}", other.label()),
        }
    }

    #[test]
    fn slim_from_self_does_not_open_a2a_client_to_own_listener() {
        let prev = std::env::var("SHADI_AGENT_ID").ok();
        std::env::set_var("SHADI_AGENT_ID", "claude-code");
        let peer = open_peer("slim:claude-code", "127.0.0.1:47357").expect("self slim");
        match peer {
            HandoffPeer::SelfSlim { agent_id } => assert_eq!(agent_id, "claude-code"),
            other => panic!("expected SelfSlim, got {}", other.label()),
        }
        match prev {
            Some(value) => std::env::set_var("SHADI_AGENT_ID", value),
            None => std::env::remove_var("SHADI_AGENT_ID"),
        }
    }

    #[test]
    fn render_inject_prompt_includes_source_and_summary() {
        let mut ctx = ContextPacket::new("claude-code");
        ctx.conversation.push(agentbridge::ConversationMessage {
            role: "assistant".to_string(),
            content: "working on parser".to_string(),
        });
        let prompt = render_inject_prompt(&ctx);
        assert!(prompt.contains("claude-code"));
        assert!(prompt.contains("working on parser"));
        assert!(prompt.contains("Acknowledge"));
    }
}
