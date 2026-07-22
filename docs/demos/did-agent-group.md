# Demo: a DID-identified group of coding-agent CLIs

This walkthrough forms a SLIM group where a **moderator** (bound to a human identity)
creates a channel and invites four coding-agent CLIs — **claude-code**, **codex**,
**copilot**, **cursor-agent** — as members. Every participant authenticates with its
own `did:key`, and every DID is **derived from the same human key**, so the mesh can
tell which human an agent belongs to.

It uses only `shadictl` shell commands. You can run it two ways:

- **One command (recommended):** `bash docs/demos/run-demo.sh` orchestrates the whole
  flow — node, moderator, four agents, invites, and a broadcast message — and prints
  the result. Best for a quick, reliable demo.
- **By hand:** drive the `shadictl` shell across a terminal per agent (steps 1–6
  below). Best for exploring; note `/slim join` and `/slim recv` block, so mind the
  choreography and use generous `--timeout` values.

## What this shows

- **Per-agent DID identity** — each CLI proves itself with a `did:key`/EdDSA JWT
  instead of a shared secret.
- **Human ↔ agent binding** — all five agents are HKDF-derived from one human root
  key (salt `shadi-agent-derive`), so they share one **human DID**.
- **Moderator role** — the channel creator/inviter is the human's `avatar`; members
  join and are admitted against a DID allow-list.
- **Role-visible UX** — `create`, `invite`, and `whoami` surface the DID, the human
  it belongs to, and the moderator/participant role.

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
source docs/demos/demo-env.sh
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

Any member can broadcast to the channel with `/slim send`, and any member can wait
for the next message with `/slim recv`. Once everyone has joined, have each agent
announce itself; every other member (moderator included) receives it.

**Each agent terminal (e.g. claude-code):**
```text
/slim send Hi, I am claude-code — reporting in
sent to agntcy/shadi/dev-room: Hi, I am claude-code — reporting in
```

**Every other terminal — moderator and the other three agents — prints:**
```text
received: Hi, I am claude-code — reporting in
```

Repeat for `codex`, `copilot`, and `cursor-agent`; `recv` is one-shot and
blocking, so call it once per expected message (`run-demo.sh` calls it five times
per terminal — once per peer plus the moderator's own greeting — to collect the
full roll call). This is a genuine mesh: every member can reach every other
member, not just moderator → members.

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

- `/slim join` and `/slim recv` **block** (listening for an invite / a message) — an
  agent terminal will appear to "hang" until the moderator invites it, or a message
  arrives, or the timeout elapses. That is expected.
- `/slim recv` is one-shot: it returns the next single message. Call it again for the
  next one. (No background subscriber loop yet.)
- The four agent names match the `agentbridge` coding-agent adapters
  (`claude_code`, `codex`, `copilot`, `cursor_agent`). This demo forms the DID group
  and passes messages; wiring the actual agent binaries in via `agentbridge` is the
  next step.
