# agentbridge Demo

Self-contained demonstration of the agentbridge coding-agent interconnect using
all four supported agents: **claude-code**, **copilot**, **codex**, and
**cursor-agent**. No external infrastructure required — no SLIM node, no LLM API
keys, no CLI tools installed.

## Build

```bash
cargo build -p agentbridge_demo
```

## Run all scenarios

```bash
cargo run -p agentbridge_demo
```

## Run individual scenarios

### Scenario 1: Context handoff chain

Shows how `ContextPacket` carries an entire coding session (conversation history,
open files, generated artifacts) from claude-code to all three successors via A2A
serialization.

```bash
cargo run -p agentbridge_demo -- --scenario handoff
```

Sample output:
```
[claude-code] snapshotted context: id=a1b2c3d4 msgs=2 files=1 artifacts=1

[transport] serialized -> 866 bytes
[transport] deserialized at destination

  [copilot]      <- receiving handoff from 'claude-code': 2 messages, 1 files, 1 artifacts
  [codex]        <- receiving handoff from 'claude-code': 2 messages, 1 files, 1 artifacts
  [cursor-agent] <- receiving handoff from 'claude-code': 2 messages, 1 files, 1 artifacts

[OK] Handoff chain complete: all 3 successors received the claude-code context.
```

### Scenario 2: 4-agent autonomous coordination

Shows `MasRuntime<DevelopmentEngine>` coordinating all four agents using the
staggered proposal + endorsement loop — the same pattern used by
`agentbridge coordinate --quorum 4`. Finalization is fully autonomous.

```bash
cargo run -p agentbridge_demo -- --scenario coordination
```

Sample output:
```
-- Epoch 0: proposal phase ----------------------------------

  [claude-code]  proposes Result<Value,Error>              -> Applied
  [copilot]      proposes Option<Value>                    -> Applied
  [codex]        proposes Value+unwrap_or_default          -> Applied

-- Epoch 0: endorsement phase --------------------------------

  All 4 agents vote BEFORE the last proposal arrives.

  [claude-code]  endorses claude-code                      -> Applied
  [copilot]      endorses claude-code                      -> Applied
  [codex]        endorses copilot                          -> Applied
  [cursor-agent] endorses claude-code                      -> Applied

  [cursor-agent] proposes Box<dyn Error>  <- quorum met    -> FINALIZED (participants=4)

-- Result ---------------------------------------------------

  Vote tally: claude-code=3, copilot=1, codex=0, cursor-agent=0
  Winner: claude-code (Result-based, 3/4 endorsements)

  Winning artifact:
  .----------------------------------------------------.
  | pub fn parse(input: &str) -> Result<serde_json::Value, serde_json::Error> {
  |     serde_json::from_str(input)
  | }
  '----------------------------------------------------'
```

### Scenario 3: CliAdapter → ToolAdapter bridge

Shows how any `CliAdapter` is bridged into `shadi_mas::ToolAdapter` via
`CliToolAdapter`, making it usable in coordination rounds without any changes
to the underlying tool.

```bash
cargo run -p agentbridge_demo -- --scenario bridge
```

## What this demo does NOT show

The demo uses in-process mock adapters for clarity. The full production stack adds:

| Feature | Where it lives |
|---------|---------------|
| Real subprocess communication | `GenericStdioAdapter` (crates/agentbridge) |
| Coding-CLI profiles | `crates/agentbridge/profiles/*.json` + `ProfileAdapter` |
| `register --tool cursor-agent` | `crates/agentbridge_cli/src/commands/register.rs` |
| `list --local` | on-host leases in `crates/agentbridge/src/local_registry.rs` |
| DID-proof send/recv + `AUTH_REQUIRED` | `shadi_identity::did_proof` + `shadi_mas` auth_required |
| Native `handoff --from/--to` | same specs as `coordinate` |
| A2A task delegation | `LiveA2ATaskAdapter` (crates/shadi_mas/src/experiments) |
| SLIM group broadcast | `LiveSlimMessagingAdapter::group()` |
| DIR agent discovery | `shadictl dir` / `agentbridge list` |
| Context persistence | `shadi_memory::SqlCipherStore` |

## Running with real agents

```bash
# After register --slim-endpoint (under shadictl --net-block):
agentbridge list --local
agentbridge handoff --from claude-code --to copilot

# All four agents, staggered vote loop, human approval on result
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest" \
  --agents claude-code,copilot,codex,cursor-agent \
  --quorum 4 \
  --max-rounds 3 \
  --output result.rs \
  --require-human
```

Live multi-turn coding (two lines of Rust per agent, round-robin until
`cargo test` passes):
[docs/content/demos/collab-rust.md](../../docs/content/demos/collab-rust.md).

See [docs/content/agentbridge.md](../../docs/content/agentbridge.md) for architecture and roadmap.
