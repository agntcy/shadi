# Demo: run a DIR agent skill as a discoverable agent

This walkthrough takes an agent skill stored in the
[AGNTCY Agent Directory](https://github.com/agntcy/dir) (DIR), turns it into a
running A2A agent with `agentbridge register --record`, and finds it again by
skill through **runtime discovery**: the registry of *running* workloads that
`dirctl daemon` keeps next to DIR's registry of records.

It complements [Agent Directory Discovery Demo](dir-group-discovery.md). That
one publishes agent cards as DIR records and forms a group from them; this one
keeps DIR for what is built once (the skill record) and runtime discovery for
what runs (the agent instance), so stopping an agent removes it from
discovery.

The agents use a stand-in harness, `fake-harness`
(`examples/agentbridge-container`), which answers without a model and prints
the skills it was given, so nothing here spends tokens.

## What this shows

- **An agent built from a DIR record** — `register --record <ref>` pulls an
  agent-skill record from a DIR node, writes its skills into a harness that
  starts without your own configuration, and serves it over A2A inside the
  SHADI sandbox.
- **Skills from the record and the command line, nothing else** — the card
  advertises the record's skills and domains plus `--skill` / `--domain` in
  its OASF `discovery` extension, checked against the OASF schema server
  before the listener starts. No skill is added automatically.
- **Announced while it runs** — `--dir-announce` registers the running
  instance with runtime discovery and withdraws it on Ctrl-C or SIGTERM.
  Containers are announced by their labels.
- **Found by skill** — `dirctl runtime list --skill …` lists running agents,
  with the record each was built from.
- **What fails, and how** — invalid skills, unreachable servers, records that
  can't run, and sandbox settings, each stopping before the agent is served.

## Prerequisites

```bash
# 1. Build the CLIs
cargo build -p agntcy-shadi-cli -p agntcy-agentbridge-cli

# 2. Build dirctl with runtime discovery (dirctl daemon + dirctl runtime list)
git clone https://github.com/agntcy/dir.git ../dir
(cd ../dir/cli && go build -o "$HOME/go/bin/dirctl-dev" .)
```

`dirctl runtime list` and process discovery in `dirctl daemon` ship with DIR
1.8.0; the output shown here and the clean-up of stale descriptors need DIR's
`main` branch until the next release, so build `dirctl` as above.

!!! note "Runtime discovery is local for now"
    The runtime discovery API is served by `dirctl daemon`, which runs DIR's
    API server together with dir-runtime on your machine. A Directory deployed
    on Kubernetes (such as the public one) doesn't run dir-runtime yet
    ([agntcy/dir#2309](https://github.com/agntcy/dir/issues/2309)), so `dirctl runtime list` against it answers
    `Unimplemented`. Everything below uses a local `dirctl daemon`.

!!! note "Build dirctl outside /tmp"
    The SHADI sandbox refuses to run programs through the `/tmp` symlink, so a
    `dirctl` there fails inside `shadictl` with `Operation not permitted`. Use
    a path under `$HOME` (as above) or `/private/tmp/…`.

### Start a local Agent Directory node with runtime discovery

**Terminal D** (daemon):

```bash
source docs/content/demos/demo-env-runtime.sh
DIRECTORY_DAEMON_RUNTIME_ENABLED=true "$DIRCTL" daemon start
```

The daemon serves DIR on `localhost:8888` and discovers workloads in two
runtimes: Docker containers, and host processes that write a descriptor to
`~/.agntcy/dir-runtime/workloads.d`. If pushes fail with `403 Forbidden` on
macOS, see the
[port 5000 note](dir-group-discovery.md#start-a-local-agent-directory-node).

## 1. Shared environment (every terminal)

```bash
source docs/content/demos/demo-env-runtime.sh
```

In fish, start a shell that inherits it with
`bash -c 'source docs/content/demos/demo-env-runtime.sh && exec fish'`, or use
[bass](https://github.com/edc/bass) (`bass source …`).

[`demo-env-runtime.sh`](demo-env-runtime.sh) sets:

- **DID auth** (`SHADI_SLIM_AUTH=did`, `SLIM_HUMAN_SEED`), and
  `SLIM_MEMBER_DIDS` with the one DID the demo agents accept tasks from: the
  `avatar` agent `agentbridge delegate` signs as.
- **`SHADI_TMP_DIR`**, the demo's working state, as a real path: each run's
  harness configuration (`agentbridge-record/`), the registry of local
  listeners (`agentbridge-local/`) and the harnesses' work directory
  (`work/`). Agent terminals grant it to the sandbox with
  `--allow "$SHADI_TMP_DIR"`, and every terminal must use the same one.
- **`DIRCTL`** and **`SHADI_DIRCTL_BINARY`**: the `dirctl` you run and the one
  agentbridge runs inside the sandbox; `DIRECTORY_CLIENT_SERVER_ADDRESS` points
  `dirctl` at the local daemon.
- **`PATH`** and **`AGENTBRIDGE_PROFILES_DIR`** for the stand-in harness and
  its profile.

`SHADI_DIRCTL_BINARY` picks the `dirctl` agentbridge runs inside the sandbox,
where an older one (e.g. from Homebrew) can come first on `PATH`.

## 2. Import an agent skill into DIR

**Terminal C** (client):

The sample `code-review` skill from DIR's test data, imported with OASF 1.1.0
classes chosen by the static enricher (no LLM needed). 1.1.0 is the OASF
version agentbridge advertises, so the record's classes join the agent's card.

```bash
cat > "$SHADI_TMP_DIR/import-code-review.yaml" <<EOF
type: agent-skill
file_path: $PWD/../dir/tests/e2e/shared/testdata/code-review
schema_version: "1.1.0"
enricher:
  static:
    skills: [{ name: software_engineering/code_debugging/error_handling }]
    domains: [{ name: technology/software_engineering }]
EOF
"$DIRCTL" import --config "$SHADI_TMP_DIR/import-code-review.yaml"
"$DIRCTL" info code-review --output json
```

```text
=== Import Summary ===
Total records:   1
Imported:        1
Skipped:         0
Failed:          0
{
  "cid":  "baeareigguj5xuzfovhcms2zbgqi56daruq3niucq3iva4iyb7ltwdbu3w4",
  "annotations":  { "name": "code-review", "oasf-version": "1.1.0", "version": "1.0.0" },
  "schemaVersion":  "1.1.0",
  ...
}
```

## 3. Run the skill as an agent

**Terminal R** (record agent):

```bash
source docs/content/demos/demo-env-runtime.sh
target/debug/shadictl --net-block \
  --net-allow 127.0.0.1:19960 --net-allow schema.oasf.outshift.com:443 \
  --net-allow localhost:8888 --read ~/.dir --read ~/.config/dirctl \
  --allow "$SHADI_TMP_DIR" --write ~/.agntcy/dir-runtime/workloads.d \
  -- target/debug/agentbridge register --tool fake-harness \
     --a2a-listen 127.0.0.1:19960 --a2a-binding http+json \
     --record code-review --record-server localhost:8888 --dir-announce
```

```text
[agentbridge] running DIR record code-review 1.0.0 (baeareigguj5x…) from localhost:8888; signature: not trusted (no signatures found)
[agentbridge] provisioned agent skill 'code-review' into …/agentbridge-record/fake-harness-21162/skills/code-review
Registered fake-harness adapter from profile (agent id: fake-harness, dir: …)
[agentbridge] announced to dir-runtime as fake-harness-<DID suffix>-21162 (…/workloads.d/fake-harness-<DID suffix>-21162.json)
Starting A2A HTTP+JSON listener on 127.0.0.1:19960 ...
[agentbridge] ready — A2A HTTP+JSON on http://127.0.0.1:19960
```

What happened before the listener started:

1. `dirctl info` resolved `code-review` to a CID on the DIR node, `dirctl pull`
   fetched the record, and `dirctl verify` reported its signature status. A
   signature isn't required — which skill to run is your choice — but it is
   logged so that choice is informed.
2. Every agent skill in the record (its `core/language_model/agentskills`
   modules) was written into a fresh configuration directory for this run.
   The harness's profile points it there (`isolation` and `provision.skills`
   in `examples/agentbridge-container/profiles/fake-harness.json`), so it
   doesn't see your own skills or settings. The directory is removed when
   `register` stops.
3. The card was built with the record's version, skills and domains, and
   checked against the OASF schema server.
4. `--dir-announce` wrote a process descriptor for runtime discovery, labelled
   with the record's CID (`org.agntcy/agent-record`).

The sandbox flags grant exactly that: the listener and the OASF server
(`--net-allow`), the DIR node and `dirctl`'s own files for `--record`
(`--net-allow localhost:8888 --read ~/.dir --read ~/.config/dirctl`), the
demo's working state (`--allow "$SHADI_TMP_DIR"`), and the descriptor
directory (`--write`).

## 4. Find it by skill

**Terminal C:**

```bash
"$DIRCTL" runtime list --skill "software_engineering/*"
```

```text
fake-harness-<DID suffix>-21162
  runtime:  process
  host:     my-laptop
  agent:    fake-harness 1.0.0
  locators: http://127.0.0.1:19960
  skills:   software_engineering/code_debugging/error_handling
  domains:  technology/software_engineering
  authors:  AGNTCY Contributors
  record:   baeareigguj5xuzfovhcms2zbgqi56daruq3niucq3iva4iyb7ltwdbu3w4

Workloads are listed as announced; nothing here is verified.
```

- The first line is the workload ID: for a process, the agent name, the end
  of its DID and its PID.
- The version, skill and domain come from the record; `authors` is the
  record's author. The card itself names no owner yet.
- `--output raw` prints only workload IDs; `--output json` prints the
  workloads as runtime discovery returns them, A2A card included:

```bash
"$DIRCTL" runtime list --label org.agntcy/agent-record=. --output raw
"$DIRCTL" runtime list --output json \
  | jq '.[0].services.a2a | {version, skills, extensions: .capabilities.extensions}'
```

The card's own A2A `skills` list is empty: OASF classes live only in the
`discovery` extension (`https://schema.oasf.outshift.com/1.1.0/objects/discovery`).

`agentbridge list` shows the same agent from agentbridge's side. It lists
running agents from two sources, merged: listeners on this host, and every
agent the dir-runtime at `--runtime` (default `localhost:8888`) reports:

```bash
target/debug/agentbridge list
target/debug/agentbridge list --skill "software_engineering/*"   # only announced agents carry skills
```

```text
fake-harness  did=did:key:z6Mk…  http+json://127.0.0.1:19960  [local, runtime localhost:8888]
```

Each line says where the agent was found: `local` (this host's listeners) and
`runtime <addr>` for each dir-runtime. `agentbridge` runs `dirctl runtime list`
itself, so it needs a `dirctl` with that command (1.8.0 or later, via
`SHADI_DIRCTL_BINARY`); with an older one it says so and lists only local
listeners.

## 5. Send it a task

**Terminal C:**

```bash
target/debug/agentbridge delegate --to fake-harness "Review: return a / b"
```

```text
Response from 'fake-harness' (488ms):
[fake-harness] received: Review: return a / b
[fake-harness] agent skill: code-review: Toolkit for performing structured code reviews. Covers identifying bugs, security issues, performance problems, and style violations. Use when asked to review code changes, pull requests, or individual files.
```

The harness answered with the skill it was given. `--to fake-harness`
resolves through `agentbridge list --local`, which shows the agent's DID and
locator on this host.

Press **Ctrl-C** in Terminal R: the agent withdraws its announcement, and
`dirctl runtime list` no longer shows it.

## 6. With a real harness

The bundled profiles under `crates/agentbridge/profiles/` drive real coding
CLIs. For a record, prefer the isolated ones:

- **`claude-code-isolated`, `codex-isolated`** run the same CLIs as
  `claude-code` and `codex` with a fresh configuration directory per run
  (`CLAUDE_CONFIG_DIR` / `CODEX_HOME`), holding only the record's skills. The
  harness doesn't see your own skills, settings, MCP servers or login.
- **`claude-code`, `codex`** work too, with a warning: the record's skills go
  into the working directory (`.claude/skills`, `.agents/skills`; an existing
  skill of the same name is never replaced, and they are removed when
  `register` stops), and the harness also reads your own configuration and
  login. Whoever can send it a task can try to make it reveal or use them.

That also means the harness doesn't see your login, so give it a credential
it reads from its environment:

| Harness | Install | Credential | Model API |
| --- | --- | --- | --- |
| `claude-code-isolated` | [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (`claude`) | `ANTHROPIC_API_KEY`, or `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token` | `api.anthropic.com:443` |
| `codex-isolated` | [Codex CLI](https://github.com/openai/codex) (`codex`) | `OPENAI_API_KEY` | `api.openai.com:443` |

**Terminal R**, claude-code-isolated:

```bash
source docs/content/demos/demo-env-runtime.sh
export ANTHROPIC_API_KEY=…            # or CLAUDE_CODE_OAUTH_TOKEN=…
target/debug/shadictl --net-block \
  --net-allow 127.0.0.1:19970 --net-allow schema.oasf.outshift.com:443 \
  --net-allow localhost:8888 --net-allow api.anthropic.com:443 \
  --read ~/.dir --read ~/.config/dirctl \
  --read ~/.local/bin --read ~/.local/share/claude \
  --allow "$SHADI_TMP_DIR" --write ~/.agntcy/dir-runtime/workloads.d \
  -- target/debug/agentbridge register --tool claude-code-isolated \
     --command "$SHADI_TMP_DIR/work" \
     --a2a-listen 127.0.0.1:19970 --a2a-binding http+json \
     --record code-review --record-server localhost:8888 --dir-announce
```

**Terminal R**, codex-isolated:

```bash
source docs/content/demos/demo-env-runtime.sh
export OPENAI_API_KEY=…
target/debug/shadictl --net-block \
  --net-allow 127.0.0.1:19971 --net-allow schema.oasf.outshift.com:443 \
  --net-allow localhost:8888 --net-allow api.openai.com:443 \
  --read ~/.dir --read ~/.config/dirctl \
  --allow "$SHADI_TMP_DIR" --write ~/.agntcy/dir-runtime/workloads.d \
  -- target/debug/agentbridge register --tool codex-isolated \
     --command "$SHADI_TMP_DIR/work" \
     --a2a-listen 127.0.0.1:19971 --a2a-binding http+json \
     --record code-review --record-server localhost:8888 --dir-announce
```

**Terminal C:**

```bash
target/debug/agentbridge delegate --to claude-code-isolated \
  "Review this function: def div(a, b): return a / b"
```

- `--command` is the harness's working directory: the files it may read and
  change for a task. Here it is an empty directory; point it at a checkout to
  review real code, and allow that path too.
- The extra sandbox access is the harness's own: its model API, and for
  claude its install under `~/.local` (Homebrew installs, like `codex`, are
  readable already).
- Without a credential, the task comes back with the harness's own error
  (`Not logged in · Please run /login`, or `401 Unauthorized`), which shows
  everything up to the model call works.

!!! warning "The harness can read its credential"
    Whatever credential you pass, the harness and the tools it runs can read
    it, and a task's reply goes back to whoever sent it. This was already
    true before `--record`: a harness always inherited agentbridge's
    environment. Use a key you can revoke, ideally with a spending limit, and
    only admit DIDs you trust (`SLIM_MEMBER_DIDS`). Keeping the credential
    out of the harness is [shadi#486](https://github.com/agntcy/shadi/issues/486); SHADI's own secrets (such as
    `SLIM_HUMAN_SEED`) are kept out of its environment by [shadi#487](https://github.com/agntcy/shadi/issues/487).

### Harnesses without isolation

`copilot`, `cursor-agent`, `goose` and `opencode` have neither `isolation`
nor a place for skills (`provision.skills`), so they refuse `--record`. They still run as agents from flags (step 7's
command with `--tool <name>`), using your own configuration and login: the
sandbox then has to allow the harness's configuration and wherever its login
is stored. For a login kept in the macOS keychain, that means
`--allow ~/Library/Keychains`, which exposes every keychain item, SHADI's
own included ([shadi#320](https://github.com/agntcy/shadi/issues/320)).

## 7. An agent from the command line

**Terminal F:**

```bash
source docs/content/demos/demo-env-runtime.sh
target/debug/shadictl --net-block \
  --net-allow 127.0.0.1:19950 --net-allow schema.oasf.outshift.com:443 \
  --allow "$SHADI_TMP_DIR" --write ~/.agntcy/dir-runtime/workloads.d \
  -- target/debug/agentbridge register --tool fake-harness \
     --a2a-listen 127.0.0.1:19950 --a2a-binding http+json \
     --skill software_engineering/code_debugging/error_handling \
     --domain technology/networking/network_security \
     --version 1.0.0 --dir-announce
```

**Terminal C:**

```bash
"$DIRCTL" runtime list --domain "technology/*"
```

For a gRPC or SLIM listener, which don't serve the card themselves, add a card
listener and allow its port: `--a2a-binding grpc --card-listen 127.0.0.1:19952`.

## 8. A group of running agents

Agents announced to runtime discovery can form a SLIM group like the
[Agent Directory Discovery Demo](dir-group-discovery.md) does with DIR
records: the `running:<skill>` member source finds them through
`dirctl runtime list` instead of a record search. Use that demo's SLIM setup
(mTLS material, `shadictl slim start-node`, and the moderator's DID in each
agent's `SLIM_MEMBER_DIDS`), and announce each agent with a skill and a SLIM
endpoint:

```bash
target/debug/shadictl --net-block \
  --net-allow "$SLIM_ENDPOINT" --net-allow schema.oasf.outshift.com:443 \
  --allow "$SHADI_TMP_DIR" --write ~/.agntcy/dir-runtime/workloads.d \
  -- target/debug/agentbridge register --tool codex \
     --command "$SHADI_TMP_DIR/work" --slim-endpoint "$SLIM_ENDPOINT" \
     --skill ai_ml_engineering/agent_orchestration/multi_agent_coordination \
     --dir-announce
```

Then the moderator resolves the group from running agents:

```bash
target/debug/shadictl slim create-group \
  --members "running:ai_ml_engineering/agent_orchestration/multi_agent_coordination" \
  --dir-server localhost:8888 \
  agntcy/shadi/runtime-room
```

and continues as in that demo's steps 6–7 (`/slim join`, `/slim invite`,
`/slim invite-from running:…`). Only agents that announced their DID
(`--dir-announce`) become members; containers don't carry one yet.

## 9. Containers

```bash
docker compose -f examples/agentbridge-container/compose.yaml up -d --build
"$DIRCTL" runtime list --runtime docker
docker compose -f examples/agentbridge-container/compose.yaml down
```

Each container runs `agentbridge register` inside `shadictl` with the
discovery labels `org.agntcy/discover=true` and `org.agntcy/agent-type=a2a`.
The card is served on plain HTTP (`--card-listen`, port 8081) for discovery;
`--advertise-url` puts the published A2A port in the card. Delegating to a
container needs a certificate your machine trusts; see the
[example's README](https://github.com/agntcy/shadi/tree/main/examples/agentbridge-container).

## 10. What doesn't work, and how it fails

Each of these stops before any listener starts. Use the `shadictl` prefix from
step 3 unless noted.

| Case | Command | Result |
| --- | --- | --- |
| Invalid skill | `register … --skill software_engineering/not_a_skill` | `skills or domains are not in OASF 1.1.0: skills[0]: Unknown "name" value; no class is defined for not_a_skill.` |
| Domain without a skill | `register … --domain technology/software_engineering` | `--domain needs at least one --skill: the OASF discovery object requires skills` |
| OASF server blocked | step 7 without `--net-allow schema.oasf.outshift.com:443` | `could not reach the OASF server …`, naming the `--net-allow` to add, or `--skip-oasf-validation` |
| Announce without a listener | `agentbridge register --tool fake-harness --dir-announce` | `--dir-announce needs an A2A listener: pass --slim-endpoint or --a2a-listen` |
| Unknown record | `register … --record no-such-skill …` | `could not find record 'no-such-skill' on localhost:8888: … no record found with name "no-such-skill"` |
| `dirctl` blocked by the sandbox | step 3 without `--read ~/.dir --read ~/.config/dirctl` | `dirctl info code-review failed: panic: mkdir …/.dir: file exists`, with the flags to add |
| `dirctl` under `/tmp` | `SHADI_DIRCTL_BINARY=/tmp/dirctl …` | `could not run dirctl (/tmp/dirctl): Operation not permitted …` |
| A record without an agent skill | an A2A-card record (`dirctl import --type=a2a`) as `--record` | `record '…' has no agent skill (core/language_model/agentskills module); only agent-skill records can be run` |
| `$SHADI_TMP_DIR` not allowed | step 3 without `--allow "$SHADI_TMP_DIR"` | `could not create …/agentbridge-record/fake-harness-<pid>: Operation not permitted. Under shadictl, allow it with --allow …` |
| A harness that isn't isolated | `register --tool claude-code … --record code-review …` | starts, with `warning: profile 'claude-code' isn't isolated. The harness also reads your own configuration …`; the skill goes into `<workdir>/.claude/skills` |
| A harness with nowhere to put skills | `register --tool copilot … --record code-review …` | `profile 'copilot' can't run a DIR record: it has no provision.skills section, so there is nowhere to put the record's skills` |
| A record in another OASF version | a record imported with `schema_version: "1.0.0"` | starts, but `warning: record … uses OASF 1.0.0, the card OASF 1.1.0; its skills and domains are not advertised` |

An agent without any skill (no `--skill`, no `--record`) starts, but its card
has no `discovery` extension, so `--skill` filters don't find it.

## Notes and limitations

- **Everything listed is a claim.** Runtime discovery shows what each workload
  announces; nothing verifies it yet. Card signatures will name the agent and
  its owner verifiably ([shadi#482](https://github.com/agntcy/shadi/issues/482)), and a challenge will show that a running
  instance holds its key ([agntcy/dir-runtime#94](https://github.com/agntcy/dir-runtime/issues/94)).
- **Isolated harnesses don't see your login.** A real harness started with
  `--record` gets a fresh configuration, so it needs a credential it can read
  (step 6).
- **Stale announcements clean themselves up.** SIGTERM to `shadictl` (or a
  crash) ends the agent without withdrawing its announcement; `dirctl daemon`
  removes the descriptor once the process is gone, and its `started_at`
  keeps a reused PID from reviving it.
- **One OASF version per card.** A record's classes join the card only when
  the record uses the card's OASF version (`--oasf-schema-version`, 1.1.0).

## Next steps

- `agentbridge list --live`: keep only running agents a trusted human vouches
  for and that answer a challenge for their DID ([shadi#347](https://github.com/agntcy/shadi/issues/347), [shadi#437](https://github.com/agntcy/shadi/issues/437)).
- Card signatures and a challenge before sending ([shadi#482](https://github.com/agntcy/shadi/issues/482), [shadi#437](https://github.com/agntcy/shadi/issues/437)).
