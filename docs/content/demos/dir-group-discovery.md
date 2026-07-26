# Demo: form a SLIM group by discovering members in the Agent Directory

This walkthrough forms a SLIM group where the **moderator** doesn't start out
knowing who's in it — it discovers members by capability (skill) or by an
already-known DID via the [AGNTCY Agent Directory](https://github.com/agntcy/dir)
(DIR), and can pull a newly-discovered agent into an already-running group
later, without ever losing the option to add someone by hand.

This is a separate, additive demo from
[Secure Agent Group Demo](did-agent-group.md) — that one still works exactly
as written; nothing here changes it. `/slim create`, `/slim invite <name>`,
and `/slim join` are untouched by any of this.

## What this shows

- **Real, connectable AgentCards in DIR** — `agentbridge register --dir-publish`
  publishes a real A2A `AgentCard` (real skills, real SLIM endpoint) wrapped in
  DIR's `integration/a2a` OASF module, with the agent's `did:key` as the
  record's `authors` entry — not a disconnected placeholder record.
- **Discovery by skill** — `agentbridge list` and `shadictl slim create-group
  --members skill:<skill>` resolve real `{name, did, slim_endpoint}` triples
  from a Directory search, not raw CLI output.
- **Discovery by already-known DID** — `--members did:<did>` resolves an
  agent's current name/endpoint from Directory when the moderator already
  trusts a specific DID but not necessarily anything else about it.
- **The fully-manual technique, formalized** — `--members
  explicit:<name>=<did>[@<endpoint>]` names an agent directly, no Directory
  round-trip at all, as a peer to the two discovery techniques above.
- **A live audit trail for the trust set** — `--write-config` persists the
  resolved DID trust superset as a `slim_mas` `GroupConfig` TOML, so
  `shadictl slim-mas list-members`/`validate` can inspect it later.
- **Dynamic growth** — `/slim invite-from <spec>` re-resolves a member source
  *live*, inside an already-running group session, and invites whichever
  matches are already in the group's trust set.

## Prerequisites

```bash
# 1. Build the CLIs
cargo build -p agntcy-shadi-cli -p agntcy-agentbridge-cli

# 2. Generate mTLS material for the SLIM transport (one CA + client/server certs)
export DEMO=/tmp/shadi-dir-demo
bash tools/generate_slim_mtls_certs.sh "$DEMO/shadi-slim-mtls"

# 3. Install dirctl if you don't already have it
brew tap agntcy/dir https://github.com/agntcy/dir/ && brew install dirctl
```

### Start a local Agent Directory node

`dirctl daemon start` runs a complete local DIR node in one process — API
server, reconciler, SQLite database, and a local content store — with no
Docker, Postgres, or external OCI registry required:

```bash
dirctl daemon start
dirctl daemon status   # "Daemon is running"
```

!!! warning "macOS: port 5000 conflicts with AirPlay Receiver"
    The daemon's embedded content store defaults to `localhost:5000` for its
    OCI-compatible registry, which on macOS is claimed by AirPlay Receiver by
    default — pushes fail with a `403 Forbidden` that has nothing to do with
    SHADI or DIR permissions. Either turn off AirPlay Receiver (System
    Settings → General → AirDrop & Handoff), or point the daemon at a
    different port with a custom config:

    ```bash
    cp $(brew --prefix dirctl 2>/dev/null || echo .)/../share/dirctl/daemon.config.yaml \
      ~/.agntcy/dir/daemon.config.yaml 2>/dev/null || \
    curl -s https://raw.githubusercontent.com/agntcy/dir/main/cli/cmd/daemon/daemon.config.yaml \
      -o ~/.agntcy/dir/daemon.config.yaml
    sed -i '' 's/registry_address: "localhost:5555"/registry_address: "localhost:5556"/' ~/.agntcy/dir/daemon.config.yaml
    dirctl daemon start --config ~/.agntcy/dir/daemon.config.yaml
    ```

Stop it later with `dirctl daemon stop`.

## 1. Shared environment (every terminal)

```bash
source docs/content/demos/demo-env-dir.sh
```

Unlike [`demo-env.sh`](demo-env.sh), this **deliberately doesn't set
`SLIM_MEMBER_DIDS`** for the moderator — that's the whole point: the
moderator's trust set gets built from Directory discovery, not a
hand-written list.

## 2. Start the SLIM node

**Terminal M** (moderator):

```bash
source docs/content/demos/demo-env-dir.sh
target/debug/shadictl slim start-node
```

```text
started SLIM node on 127.0.0.1:47660
```

Leave this running for the rest of the demo.

## 3. Register two agents, publishing real AgentCards to DIR

Each agent terminal needs the moderator's DID in its own `SLIM_MEMBER_DIDS`
(to admit the moderator's future invite) — get it once with `/slim whoami`:

```bash
source docs/content/demos/demo-env-dir.sh
printf '/slim whoami\n/exit\n' | SHADI_AGENT_ID=avatar target/debug/shadictl shell | grep did:
#   did:   did:key:z6MkwE1Y6L4KLgaQMACssnKN9LSEGTJpgdJxATgvRJAgkF76
```

**Terminal copilot** and **Terminal codex** — register a real listener and
publish its AgentCard to the local DIR node:

```bash
source docs/content/demos/demo-env-dir.sh
export SLIM_MEMBER_DIDS="did:key:z6MkwE1Y6L4KLgaQMACssnKN9LSEGTJpgdJxATgvRJAgkF76"
SHADI_AGENT_ID=copilot target/debug/agentbridge register --tool copilot \
  --command "$(pwd)" --slim-endpoint "$SLIM_ENDPOINT" \
  --dir-publish --dir-server "$SHADI_DIR_SERVER"
```

```text
Registered Copilot adapter (agent id: copilot)
Starting SLIM A2A listener on 127.0.0.1:47660 as agntcy/shadi/copilot-a2a ...
Publishing AgentCard for 'copilot' to 127.0.0.1:8888...
Published. CID: baeareiccmurazht4fdrmlcl3optjab7qvybnejojjappzfgjhmgqx6dd5u
[agentbridge] ready — listening on agntcy/shadi/copilot-a2a
```

Repeat in **Terminal codex** with `--tool codex`. Both adapters advertise the
standard agentbridge skill set — `agent_orchestration/task_decomposition`,
`agent_orchestration/agent_coordination`, and
`natural_language_processing/natural_language_generation/text_completion` —
real [OASF](https://github.com/agntcy/oasf) skill taxonomy classes, confirmed
against a live Directory's schema validator (arbitrary skill strings are
rejected by `dirctl push`).

## 4. Discover them with `agentbridge list`

**Any terminal:**

```bash
source docs/content/demos/demo-env-dir.sh
target/debug/agentbridge list --dir-server "$SHADI_DIR_SERVER"
```

```text
Searching Agent Directory (127.0.0.1:8888) for agentbridge adapters...

codex     did=did:key:z6MkjFJX8CHfgsZKWpS2FfQz38KyzHkf2mDo1vKJ9rMfSUvg  slim://127.0.0.1:47660
copilot   did=did:key:z6MkfGB4nkEoDvT6KgdPbobdXqnWh5K8jQSy3Ho5Ga6CdJFb  slim://127.0.0.1:47660
```

Both entries are real, resolved from Directory records `agentbridge list`
pulled and parsed — not raw `dirctl` stdout.

## 5. Moderator: create a group by discovering its members

**Terminal M:**

```bash
target/debug/shadictl slim create-group \
  --members "skill:agent_orchestration/agent_coordination" \
  --dir-server "$SHADI_DIR_SERVER" \
  --write-config /tmp/shadi-dir-demo/mas.toml \
  agntcy/shadi/dir-room
```

```text
Resolved 2 candidate member(s):
  codex     did=did:key:z6MkjFJX8CHfgsZKWpS2FfQz38KyzHkf2mDo1vKJ9rMfSUvg  slim://127.0.0.1:47660
  copilot   did=did:key:z6MkfGB4nkEoDvT6KgdPbobdXqnWh5K8jQSy3Ho5Ga6CdJFb  slim://127.0.0.1:47660
wrote group config to /tmp/shadi-dir-demo/mas.toml

shadi> /slim create agntcy/shadi/dir-room
created channel agntcy/shadi/dir-room as moderator agntcy/shadi/avatar (did:key:z6MkwE1Y6L4KLgaQMACssnKN9LSEGTJpgdJxATgvRJAgkF76)
```

`create-group` resolved both adapters' DIDs from the skill search, folded
them into `SLIM_MEMBER_DIDS` for this process, created the channel, and
handed off into the same interactive shell `shadictl shell` gives you —
`/slim invite <name>`, `/slim status`, `/slim whoami`, etc. all work here
exactly as in [the other demo](did-agent-group.md), because they're the same
commands, unmodified.

The written config is a real `slim_mas` `GroupConfig`:

```toml
[mas]
default_group = "agntcy/shadi/dir-room"

[groups."agntcy/shadi/dir-room"]
moderator_did = "did:key:z6MkwE1Y6L4KLgaQMACssnKN9LSEGTJpgdJxATgvRJAgkF76"

[[groups."agntcy/shadi/dir-room".members]]
did = "did:key:z6MkfGB4nkEoDvT6KgdPbobdXqnWh5K8jQSy3Ho5Ga6CdJFb"

[[groups."agntcy/shadi/dir-room".members]]
did = "did:key:z6MkjFJX8CHfgsZKWpS2FfQz38KyzHkf2mDo1vKJ9rMfSUvg"
```

Audit it independently at any time:

```bash
target/debug/shadictl slim-mas --config /tmp/shadi-dir-demo/mas.toml list-members
```

```text
did:key:z6MkfGB4nkEoDvT6KgdPbobdXqnWh5K8jQSy3Ho5Ga6CdJFb
did:key:z6MkjFJX8CHfgsZKWpS2FfQz38KyzHkf2mDo1vKJ9rMfSUvg
```

## 6. Members join, moderator invites

Same choreography as [the other demo](did-agent-group.md) steps 4–5 — each
discovered agent runs `/slim join agntcy/shadi/dir-room --timeout 120` in its
own terminal (**Terminal copilot**, **Terminal codex**), then **Terminal M**
invites each by name:

```text
/slim invite agntcy/shadi/copilot
/slim invite agntcy/shadi/codex
```

This is the *exact* `invite_participant` call manual `/slim invite` always
used — `create-group` only changed how the trust set that makes these DIDs
admittable in the first place got built.

## 7. Dynamic growth: discover and invite a new agent mid-session

This is the part that isn't possible with a static allow-list: register one
*more* matching adapter **after** the group already exists, and pull it in
without recreating anything.

**Terminal claude-code** (opened now, after step 5):

```bash
source docs/content/demos/demo-env-dir.sh
export SLIM_MEMBER_DIDS="did:key:z6MkwE1Y6L4KLgaQMACssnKN9LSEGTJpgdJxATgvRJAgkF76"
SHADI_AGENT_ID=claude-code target/debug/agentbridge register --tool claude-code \
  --command "$(pwd)" --slim-endpoint "$SLIM_ENDPOINT" \
  --dir-publish --dir-server "$SHADI_DIR_SERVER"
```

Then join the already-running channel, same as step 6:

```text
/slim join agntcy/shadi/dir-room --timeout 120
```

**Back in Terminal M** (still the same session from step 5 — this is the
important part, `/slim invite-from` operates on the live in-process trust
set `create-group` built):

```text
/slim invite-from skill:agent_orchestration/agent_coordination
```

`invite-from` re-runs the skill search live. It finds `claude-code` — but
`claude-code`'s DID was never in this session's trust set (it wasn't a
candidate when `create-group` first resolved members), so it's reported and
skipped rather than silently failing:

```text
skipping claude-code (did:key:z6MkkYR1mqCHqEutWUM6bKoqPsPj2diDu8ykXk3cZMGxeQV9): not in this group's trust set — recreate the group with a broader --members set to include it
```

To actually admit a DID discovered after the group's `App` was created, that
`App`'s JWKS would need to change live — SLIM has no mutation API for that
today (see [Notes / limitations](#notes-limitations)). The fix isn't to
retroactively trust it; it's to have included it in the trust superset up
front. `did:<did>` can't do that before the agent has published anything —
there's nothing yet for a Directory search to find — but `explicit:` can,
since it names a DID directly with no Directory round trip at all. If the
moderator already knows `claude-code`'s DID is coming (e.g. from a prior run,
or communicated out of band), creating the group with one extra spec:

```bash
target/debug/shadictl slim create-group \
  --members "skill:agent_orchestration/agent_coordination" \
  --members "explicit:claude-code=did:key:z6MkkYR1mqCHqEutWUM6bKoqPsPj2diDu8ykXk3cZMGxeQV9" \
  --dir-server "$SHADI_DIR_SERVER" \
  agntcy/shadi/dir-room
```

puts that DID in the trust superset immediately, before `claude-code` even
exists in the Directory. Once it later registers, publishes, and joins, the
*exact same* live command from this section:

```text
/slim invite-from did:did:key:z6MkkYR1mqCHqEutWUM6bKoqPsPj2diDu8ykXk3cZMGxeQV9
```

now resolves it from Directory (this time the record exists) and invites it
successfully — no skip, no restart — because the DID was already trusted.

## 8. The other member-source techniques

`--members`/`invite-from` accept three interchangeable spec forms, freely
combinable in one `--members` list:

| Spec | Technique |
|---|---|
| `skill:<skill>` | Discover by capability — `dirctl search --skill` under the hood |
| `did:<did>` | Discover by an already-known DID — `dirctl search --author` |
| `explicit:<name>=<did>[@<endpoint>]` | Fully manual, no Directory round-trip |

```bash
target/debug/shadictl slim create-group \
  --members "skill:agent_orchestration/agent_coordination" \
  --members "did:did:key:z6MkkYR1mqCHqEutWUM6bKoqPsPj2diDu8ykXk3cZMGxeQV9" \
  --members "explicit:trusted-bot=did:key:z6Mk...@10.0.0.5:47560" \
  --dir-server "$SHADI_DIR_SERVER" \
  agntcy/shadi/multi-source-room
```

## Notes / limitations

- **`/slim create`, `/slim invite <name>`, `/slim join` are unchanged.** Every
  command in this demo that isn't `create-group`/`invite-from` is the exact,
  unmodified code path [the other demo](did-agent-group.md) exercises.
- **Membership vs. admission.** Inviting a discovered agent into a *running*
  session (`Session::invite_and_wait`) is fully dynamic — no restart needed.
  *Admission* — whose DID is cryptographically allowed to even connect — is
  fixed for the life of the moderator's `App`; SLIM builds that JWKS once,
  with no live mutation API. `create-group` resolves a deliberately broad
  trust superset up front for exactly this reason; `invite-from` operates
  within it, not around it.
- **Real OASF skill names are required.** `dirctl push` validates records
  against a live OASF schema server — invented skill strings are rejected.
  Browse valid classes at
  [github.com/agntcy/oasf](https://github.com/agntcy/oasf/tree/main/schema/skills)
  if you adapt this demo to different capabilities.
- **`/slim join` blocks** (listening for the moderator's invite) until
  invited or its `--timeout` elapses — give it a generous window, same as the
  other demo.
- **This demo hasn't been captured as a single scripted run** (unlike
  [`run-demo.sh`](run-demo.sh) for the other one) — the discovery/resolution
  steps (2–5, 7's registration+`invite-from` skip path) were verified live
  against a real local `dirctl daemon`; the final join/invite handshake in
  step 6/7 follows the same manual, multi-terminal choreography the other
  demo documents and recommends generous timeouts for.

## Next steps

- Read the design rationale in the plan this demo exercises, or see
  [AgentBridge](../agentbridge.md) for the full CLI coding-agent interconnect.
- See [Secure Agent Group Demo](did-agent-group.md) for the DID-identity and
  A2A-messaging half of this picture — unaffected by anything here.
- Look up exact `shadictl`/`agentbridge` flags in the [CLI Reference](../cli.md).
