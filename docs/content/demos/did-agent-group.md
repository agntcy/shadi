# Demo: a DID-identified group of coding-agent CLIs

This walkthrough forms a SLIM group where a **moderator** (bound to a human identity)
creates a channel and invites four coding-agent CLIs — **claude-code**, **codex**,
**copilot**, **cursor-agent** — as members. Every participant authenticates with its
own `did:key`, and every DID is **derived from the same human key**, so the mesh can
tell which human an agent belongs to.

It uses only `shadictl` shell commands. You can run it two ways:

- **One command (recommended):** `bash docs/content/demos/run-demo.sh` orchestrates the whole
  flow — node, moderator, four agents, invites, an A2A roll-call broadcast, and real
  task delegation to claude-code/codex/copilot — and prints the result. Best for a
  quick, reliable demo. It prints its log dir immediately and echoes a one-line
  status per phase as it runs; in a second terminal, `bash docs/content/demos/watch-demo.sh`
  tails every per-agent log live (including ones from later phases, as they're
  created) so you can watch progress in real time instead of waiting for the final
  summary.
- **By hand:** drive the `shadictl` shell across a terminal per agent (steps 1–6
  below). Best for exploring; note `/slim join` blocks, so mind the choreography and
  use generous `--timeout` values.

## What this shows

- **Per-agent DID identity** — each CLI proves itself with a `did:key`/EdDSA JWT
  instead of a shared secret.
- **Human ↔ agent binding** — all five agents are HKDF-derived from one human root
  key (salt `shadi-agent-derive`), so they share one **human DID**.
- **Moderator role** — the channel creator/inviter is the human's `avatar`; members
  join and are admitted against a DID allow-list.
- **Role-visible UX** — `create`, `invite`, and `whoami` surface the DID, the human
  it belongs to, and the moderator/participant role.
- **A2A-native group messaging** — `/slim a2a-collaborate` broadcasts and receives
  through A2A's `Message` type (SLIM's group/multicast is used underneath A2A via
  the SLIMRPC `Collaborate` RPC, not instead of it), with `slim-src` attribution.
- **Real coding-agent CLIs in the loop** — `agentbridge` wraps the actual `claude`/
  `codex`/`copilot` binaries as SLIM/A2A listeners under the same DID identity, so a
  delegated task really executes on that CLI, not a mock.

## Prerequisites

```bash
# 1. Build the CLI
cargo build -p agntcy-shadi-cli   # produces target/debug/shadictl

# 2. Generate mTLS material for the SLIM transport (one CA + client/server certs)
export DEMO=/tmp/shadi-did-demo
bash tools/generate_slim_mtls_certs.sh "$DEMO/shadi-slim-mtls"
```

## 1. Shared environment (every terminal)

The whole group shares one human root secret and one allow-list, provided in
[`demo-env.sh`](demo-env.sh). From the repo root, `source` it in **every** terminal
below:

```bash
source docs/content/demos/demo-env.sh
```

It sets `SHADI_SLIM_AUTH=did`, `SLIM_HUMAN_SEED`, `SLIM_HUMAN_DID`, `SHADI_TMP_DIR`,
`SLIM_ENDPOINT`, the shared transport cert (`SLIM_TLS_CERT`/`SLIM_TLS_KEY`), and the
`SLIM_MEMBER_DIDS` allow-list — the DID of every member (moderator + 4 agents).
Each agent's DID is derived from `SLIM_HUMAN_SEED` + its `SHADI_AGENT_ID`:

| `SHADI_AGENT_ID` | role | `did:key` |
|---|---|---|
| `avatar`       | moderator   | `z6Mkix7tAk25UD8f4Uy7tTxn1FAErhGZ7rfifBgrvdKgzM82` |
| `claude-code`  | participant | `z6MkhRuJgsaipjWB6No8RUGD4P7fnn8qGBZKK5C5zGJjPZa1` |
| `codex`        | participant | `z6MkmaFFysqqMsE1q5M6E7LDuoJMaSBv3PkNHz5SwwwnuGr6` |
| `copilot`      | participant | `z6MkmJUcT1F6BK21nQv1C2zo46gJJA9hsMGnbdpiN2LrMnwT` |
| `cursor-agent` | participant | `z6MktdzQzm171sAoRZc6cCUPDa8XWxaG8Bi6R3Y4ohP7qS5Q` |

## 2. Discover a member's DID (optional)

You don't have to precompute the table — any agent prints its own DID with `whoami`.
In a fresh terminal, `source demo-env.sh`, then:

```bash
SHADI_AGENT_ID=claude-code target/debug/shadictl shell
# in the shell:
/slim whoami
#   agent agntcy/shadi/claude-code
#     auth:  did
#     role:  none
#     did:   did:key:z6MkhRuJgsaipjWB6No8RUGD4P7fnn8qGBZKK5C5zGJjPZa1
#     human: did:key:z6MkhVTmZLk7g6zRXm8DF2u2Y5b2WCkC75n16xuoJDN1X4Bp
/exit
```

Collect each agent's `did:` line to build `SLIM_MEMBER_DIDS`.

## 3. Moderator: start the node and open the channel

**Terminal M** (`source demo-env.sh` first):

```bash
SHADI_AGENT_ID=avatar target/debug/shadictl shell
```

```text
/slim start node
started SLIM node on 127.0.0.1:47560

/slim create agntcy/shadi/dev-room
created channel agntcy/shadi/dev-room as moderator agntcy/shadi/avatar
  (did:key:z6Mkix7tAk25UD8f4Uy7tTxn1FAErhGZ7rfifBgrvdKgzM82) — human did:key:z6MkhVT…

/slim whoami
  agent agntcy/shadi/avatar
    auth:  did
    role:  moderator
    did:   did:key:z6Mkix7tAk25UD8f4Uy7tTxn1FAErhGZ7rfifBgrvdKgzM82
    human: did:key:z6MkhVTmZLk7g6zRXm8DF2u2Y5b2WCkC75n16xuoJDN1X4Bp
```

## 4. Each agent joins the channel

Open a terminal per agent (`source demo-env.sh` first). Each `join` blocks, listening
for the moderator's invite; give it a generous timeout so it stays up while you invite
everyone in step 5.

**Terminal claude-code:**

```bash
SHADI_AGENT_ID=claude-code target/debug/shadictl shell
```
```text
/slim join agntcy/shadi/dev-room --timeout 120
joined group session for channel agntcy/shadi/dev-room as agntcy/shadi/claude-code

/slim whoami
  agent agntcy/shadi/claude-code
    auth:  did
    role:  participant
    did:   did:key:z6MkhRuJgsaipjWB6No8RUGD4P7fnn8qGBZKK5C5zGJjPZa1
    human: did:key:z6MkhVTmZLk7g6zRXm8DF2u2Y5b2WCkC75n16xuoJDN1X4Bp
```

Repeat in three more terminals with `SHADI_AGENT_ID=codex`, `copilot`, and
`cursor-agent` (same `/slim join agntcy/shadi/dev-room --timeout 120`).

## 5. Moderator: invite the four agents

Back in **Terminal M**, invite each agent by name. Each `invite` completes as that
agent's `join` (step 4) responds and the MLS join finishes:

```text
/slim invite agntcy/shadi/claude-code
invited agntcy/shadi/claude-code to agntcy/shadi/dev-room (moderator did:key:z6Mkix7t…)
/slim invite agntcy/shadi/codex
invited agntcy/shadi/codex to agntcy/shadi/dev-room (moderator did:key:z6Mkix7t…)
/slim invite agntcy/shadi/copilot
invited agntcy/shadi/copilot to agntcy/shadi/dev-room (moderator did:key:z6Mkix7t…)
/slim invite agntcy/shadi/cursor-agent
invited agntcy/shadi/cursor-agent to agntcy/shadi/dev-room (moderator did:key:z6Mkix7t…)
```

Each agent terminal reports `joined group session …` — the group is now formed: one
human's moderator plus its four coding-agent CLIs, every member cryptographically
identified by a `did:key` admitted against the shared allow-list.

## 6. Roll call — every agent introduces itself

Messaging always goes through **A2A**, not raw SLIM bytes: `/slim a2a-collaborate`
drives the SLIMRPC `Collaborate` RPC — an A2A operation that broadcasts each
`Message` you send to every other member of a SLIM group channel, and streams back
everyone else's messages with `metadata["slim-src"]` identifying the sender. Every
member (moderator included) both sends its own intro and listens for everyone
else's, in one call — no `/slim create`/`invite`/`join` needed for this step, since
`Collaborate` forms its own group session (it's independent of the moderator/role
session from steps 3–5 above).

**Each terminal — moderator and all four agents — runs the same shape (e.g. claude-code):**
```text
/slim a2a-collaborate codex,copilot,cursor-agent,avatar --message Hi, I am claude-code — reporting in --timeout 15
broadcast "Hi, I am claude-code — reporting in" to 4 peer(s); received:
  Hi, I am codex — reporting in
  Hi, I am copilot — reporting in
  Hi, I am cursor-agent — reporting in
  Hi, I am avatar — reporting in
```

Give every terminal the peer-list of the *other* four members and start them all
within the timeout window — this is a genuine mesh: every member reaches every
other member directly, not just moderator → members.

## 7. Delegate a real task to the coding-agent CLIs

Everything so far shows *identity* and *messaging*. This step wires in the real
thing: **`agentbridge`** wraps the actual installed `claude`, `codex`, and `copilot`
CLI binaries as SLIM/A2A listeners, so a delegated task really invokes that CLI and
returns its real output — using the *same* DID identity from step 1 (agentbridge
checks `SHADI_SLIM_AUTH=did` the same way `shadictl` does, no separate setup).
`cursor-agent` doesn't have an `agentbridge register` listener yet, so it's not part
of this step (it still participates in the roll call above).

**Each agent terminal (e.g. claude-code)** — registers a live adapter backed by the
real CLI, reachable at `agntcy/shadi/claude-code-a2a`. `agentbridge register
--slim-endpoint` refuses to start unless it's running under a SHADI sandbox with
network blocked by default — Seatbelt/Landlock/AppContainer policies are inherited
by child processes, so wrapping it in `shadictl` is enough to constrain whatever CLI
tool the adapter spawns to run a task, with no extra code:

```bash
SHADI_AGENT_ID=claude-code target/debug/shadictl --net-block --net-allow "$SLIM_ENDPOINT" \
  --read "$SHADI_TMP_DIR" -- \
  target/debug/agentbridge register --tool claude-code \
  --command "$(pwd)" --slim-endpoint "$SLIM_ENDPOINT"
```
```text
Registered Claude Code adapter (agent id: claude-code, dir: /path/to/shadi)
Starting SLIM A2A listener on 127.0.0.1:47560 as agntcy/shadi/claude-code-a2a ...
[agentbridge] ready — listening on agntcy/shadi/claude-code-a2a
```

Repeat for `codex` and `copilot` (same shape, `--tool codex` / `--tool copilot`).

**Moderator terminal** — delegates one real task to each:

```bash
target/debug/agentbridge delegate "Reply with exactly the single word: PONG" \
  --to claude-code --agent-id avatar --endpoint "$SLIM_ENDPOINT"
```
```text
Delegating task 09024c44-... to 'claude-code'...
Response from 'claude-code' (5518ms):
PONG
```

The listener terminal prints the same round trip from its side:
```text
┌─ A2A recv [claude-code] task ...
│  Reply with exactly the single word: PONG
└─────────────────────────────────────────────────────────
┌─ A2A send [claude-code] (5518 ms)
│  PONG
└─────────────────────────────────────────────────────────
```

**Chaining a real task across agents** — `run-demo.sh` does this for real: it
delegates a disk-usage check to `codex`, a top-CPU-processes check to `copilot`,
then hands *both real outputs* to `claude-code` and asks it to synthesize an
operational report — each step genuinely depends on the previous agent's result,
not a canned reply. By hand, that's three `delegate` calls chained through shell
variables:

```bash
DISK=$(target/debug/agentbridge delegate \
  "Run a disk usage check on this machine (e.g. df -h) and report the real output." \
  --to codex --agent-id avatar --endpoint "$SLIM_ENDPOINT")
CPU=$(target/debug/agentbridge delegate \
  "Rank the top 10 processes on this machine by CPU usage (e.g. ps aux) and report the real output." \
  --to copilot --agent-id avatar --endpoint "$SLIM_ENDPOINT")
target/debug/agentbridge delegate \
  "Summarize these two real system-health snippets into a short report, flagging anything concerning:\n\n$DISK\n\n$CPU" \
  --to claude-code --agent-id avatar --endpoint "$SLIM_ENDPOINT"
```

`claude-code`'s response is a real report — e.g. flagging a disk volume nearing
capacity or a process with unexpectedly high CPU — built from the other two
agents' real command output.

This is a genuinely live `claude`/`copilot` process handling the prompt — swap the
message for any real coding task to see it delegated end to end. `codex`'s success
depends on your local `codex` CLI/model configuration (an unsupported default model
returns a `400` from the OpenAI backend, unrelated to SHADI); that's an environment
issue, not a bug in this wiring.

## How admission works (under the hood)

- The moderator's `create`/`invite` control messages carry its DID-JWT; each
  participant verifies that JWT against `SLIM_MEMBER_DIDS` (the allow-list) before
  replying — a non-member DID is dropped, so only invited agents can be admitted.
- Because every DID is HKDF-derived from `SLIM_HUMAN_SEED`, the `human:` line is the
  same for all five, which is how the mesh attributes each agent to its human.
- Switching the whole group back to the legacy shared secret is just
  `unset SHADI_SLIM_AUTH` (then the shell uses `SLIM_SHARED_SECRET`); the same
  `create`/`invite`/`join` commands work, without the DID lines.

## Notes / limitations

- `/slim join` **blocks** (listening for the moderator's invite) — an agent terminal
  will appear to "hang" until invited, or the timeout elapses. That is expected.
- `/slim a2a-collaborate` also blocks for its `--timeout`, since it stays listening
  for other members' broadcasts for that whole window after sending its own intro.
- Verified live with the full 5-member group (moderator + 4 coding-agent CLIs):
  every member reliably receives all four peers' intros, in either order, across
  repeated runs.
- Server-side listener attribution is a known gap in the current SLIMRPC
  `Collaborate` implementation: a member's *own* broadcast gets proper `slim-src`
  attribution on its reply-observer stream, but messages surfaced purely through the
  passive listener path have no per-message sender tag yet (the message text itself
  states the sender, which is enough for this demo).
- `agentbridge register --tool claude-code|codex|copilot` needs that CLI actually
  installed (and authenticated) on PATH; `cursor-agent` doesn't have a `register`
  listener yet. A `delegate` failure usually means the target CLI itself errored
  (auth, unsupported model, etc.), not the SLIM/A2A wiring — the response text
  includes the real error from that CLI so it's easy to tell apart.

## Next steps

- Read the concept-level model behind this demo in [SLIM and A2A](../slim_a2a.md).
- See [AgentBridge](../agentbridge.md) for the full CLI coding-agent interconnect this demo exercises.
- Look up exact `shadictl`/`agentbridge` flags in the [CLI Reference](../cli.md).
