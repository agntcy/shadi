# agentbridge

`agentbridge` is the CLI coding-agent adapter library. It bridges individual
coding tools (Claude Code, GitHub Copilot, OpenAI Codex, or any CLI that speaks
the agentbridge JSON protocol) into the `shadi_mas` coordination runtime so they
can exchange context, delegate tasks, and coordinate autonomously toward a shared
programming goal.

## How it fits into SHADI

```
CLI tools          agentbridge adapters       shadi_mas engine
──────────────     ─────────────────────     ─────────────────────────────
Claude Code    ──► ClaudeCodeAdapter   ──►
Copilot CLI    ──► CopilotAdapter      ──►   MasRuntime<DevelopmentEngine>
Codex CLI      ──► CodexAdapter        ──►
any CLI        ──► GenericStdioAdapter ──►
                        │                         │
                        │  ContextPacket           │  A2A / SLIM / DIR
                        │  (handoff / relay)       │  (transport / discovery)
```

## Core types

### `CliAdapter` (trait)

The central abstraction. Implement this to add any coding tool.

```rust
pub trait CliAdapter: Send + Sync {
    fn agent_id(&self) -> &AgentId;
    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError>;
    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError>;
    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError>;
}
```

### `ContextPacket`

A portable, serializable snapshot of a coding session: conversation history,
code files, git diff, and generated artifacts. Used for context handoff between
tools and for persistence across sessions.

```rust
pub struct ContextPacket {
    pub id: String,                        // UUID v4
    pub source_agent: String,
    pub created_at: String,                // unix timestamp
    pub conversation: Vec<ConversationMessage>,
    pub code_context: CodeContext,         // files, git diff, active file
    pub artifacts: Vec<ArtifactPayload>,   // generated code, patches
}
```

Serializes to/from JSON:

```rust
let pkt = ContextPacket::new("claude-code");
let bytes = pkt.to_bytes()?;
let restored = ContextPacket::from_bytes(&bytes)?;
```

### `CliToolAdapter<A>` (wrapper)

Bridges any `CliAdapter` into `shadi_mas::ToolAdapter` so it can participate
directly in `MasRuntime<DevelopmentEngine>` coordination rounds.

```rust
let inner = Arc::new(MyAdapter::new());
let tool_adapter = CliToolAdapter::new(inner);
// tool_adapter now implements shadi_mas::ToolAdapter
```

## Subprocess protocol (`GenericStdioAdapter`)

`GenericStdioAdapter` spawns a subprocess and communicates via newline-delimited
JSON on stdin/stdout. Any process that speaks this protocol becomes a agentbridge
participant with no code changes:

**Requests (agentbridge → subprocess stdin):**
```json
{"cmd":"snapshot"}
{"cmd":"inject","context":{...}}
{"cmd":"execute","prompt":"write a parser for JSON"}
```

**Responses (subprocess stdout → agentbridge):**
```json
{"ok":true,"data":{...}}
{"ok":false,"error":"subprocess error message"}
```

Spawn an adapter:

```rust
let adapter = GenericStdioAdapter::spawn(
    "my-tool",
    "my-cli",
    &["--agentbridge-mode"],
)?;
```

## Implementing a custom adapter

```rust
use agentbridge::{CliAdapter, CliAdapterError, ContextPacket};
use shadi_mas::AgentId;

struct MyCliAdapter { id: AgentId }

impl CliAdapter for MyCliAdapter {
    fn agent_id(&self) -> &AgentId { &self.id }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        // Read conversation history from the tool's state file / API
        let mut pkt = ContextPacket::new(self.id.0.clone());
        pkt.conversation.push(ConversationMessage {
            role: "assistant".to_string(),
            content: "...".to_string(),
        });
        Ok(pkt)
    }

    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError> {
        // Write ctx into the tool's context file or API
        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        // Call the tool's API or subprocess with the prompt
        Ok("generated code".to_string())
    }
}
```

## Crate features

This crate ships with zero optional features. All heavy infrastructure
(`shadi_mas` coordination, A2A, SLIM) is brought in at the `agentbridge_cli`
binary level so the library stays lightweight.
