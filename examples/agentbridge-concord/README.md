# A CONCORD negotiation between coding agents

Three coding agents and an initiator reach one decision with CONCORD, over A2A
Collaborate on a SLIM node. Each agent is a real `claude` (Claude Code) running
under the `shadictl` sandbox, and holds its own copy of the negotiation: there
is no central orchestrator. A run takes about two minutes.

The task is the "Coding Agent Team" example of the CONCORD tutorials
(https://ioc-project.github.io/cognition-protocols/tutorials/agentbridge/): a
team is adding a notification-delivery capability and needs one decision on how
to build it that everyone can live with. Three specialists see it differently:

| Agent | Role |
|---|---|
| `microservices` | Wants it as its own deployable service, with its own datastore and release cadence |
| `monolith` | Wants it to add no operational burden: ideally a module of the existing application |
| `pragmatist` | Owns on-call load and cost, and has no architectural preference |

The three use the words "service", "deployment" and "outage" in different
senses, and the negotiation has to bring that out. The roles are in
`agents/<id>/CLAUDE.md`.

The initiator opens the run and takes no part in it. It is a Claude too: it
reads the task and writes the frame of the run: the two anchors (the worst and
the best outcome, as states), the satisfaction threshold, and the shape of one
candidate. The agents then propose, rate each other's proposals, and repair the
weakest one, until a proposal that every agent rates above the threshold is
found, or the budget of repairs is spent.

## What is in this directory

| | |
|---|---|
| `setup.sh` | One-time setup: the mTLS certificates |
| `env.sh` | The environment of every terminal: endpoint, certificates, DID authentication, member DIDs |
| `start-node.sh` | The SLIM node |
| `register.sh <id> <peers>` | One agent, under the sandbox |
| `coordinate.sh` | The initiator: opens the run and prints the report |
| `agents/<id>/CLAUDE.md` | The role of each agent, and a short role for the initiator |
| `profiles/` | One agentbridge profile per agent, for Claude Code |
| `bin/claude-logged` | Runs `claude` and records what it was given and what it answered |

Generated files go to `.tmp/` (certificates) and `.run/` (logs, reports, Claude
sessions). Both are ignored by git.

## Prerequisites

- macOS or Linux, with a sandbox `shadictl` can apply (Seatbelt or Landlock).
- Rust, to build the tools from this repository. CONCORD is behind a feature,
  so `agentbridge` needs it switched on:

  ```sh
  cargo build -p agntcy-agentbridge-cli --features concord
  cargo build -p agntcy-shadi-cli
  ```

  The scripts use `target/debug/agentbridge` and `target/debug/shadictl` when
  they exist, and the ones on your `PATH` otherwise. Set `AGENTBRIDGE` or
  `SHADICTL` to use other binaries.
- `openssl` and `python3`.
- Claude Code (`claude`) installed. The sandbox cannot read the login in your
  keychain, so each agent needs a token in its environment: run
  `claude setup-token`, or use an API key. Export **one** of these in each
  terminal where you start an agent (the three specialists and the initiator):

  ```sh
  export CLAUDE_CODE_OAUTH_TOKEN=...     # or ANTHROPIC_API_KEY=...
  ```

  Type it in the terminal and do not write it to a file. `unset` it when you
  are done.

## Setup

From this directory, once:

```sh
./setup.sh
```

It creates the certificates SLIM and the agents use, in `.tmp/`. SLIM and the
agents authenticate with mutual TLS, and agentbridge refuses to connect
without it, even on loopback.

In every terminal below, start with `source env.sh`. The scripts do it
themselves, but `source env.sh` also lets you run the tools by hand.

## Run it

Use five terminals, all in this directory.

**1. The SLIM node:**

```sh
./start-node.sh
```

**2 to 4. The specialists**, one per terminal, each with the token exported.
The second argument lists the other members of the group, the initiator
included:

```sh
./register.sh microservices monolith,pragmatist,coordinator
./register.sh monolith microservices,pragmatist,coordinator
./register.sh pragmatist microservices,monolith,coordinator
```

Each prints a warning (what the other agents write is read by a local tool, so
join only groups you trust), then:

```
Joined the CONCORD group as microservices; waiting for a run. Press Ctrl-C to stop.
```

Wait for all three.

**5. The initiator**, with the token exported:

```sh
./coordinate.sh
```

## What you should see

The initiator first has Claude write the frame, and prints it. The text is
different on every run. For example:

```
Asking the initiator's harness to write the frame of the run...
Frame of the run:
  x_reject:  Before: users have no way to choose how they are told about events ... After, in the worst case: users receive notifications they did not opt into ...
  x_ideal:   Before: ... After: every user receives exactly the notifications they opted into ...
  schema:    {"type":"string","description":"One candidate decision on how to build the notification service, ..."}
  threshold: 0.6
Opening a CONCORD run as coordinator among microservices, monolith, pragmatist. The members must already be running.
```

Then every agent prints a line per event (`started`, `joined`, `sent`,
`recorded`, `repair owed`, `outcome`, `ended`), and each prints its report as
JSON when the run ends. In a successful run:

- every agent reports the same `outcome` (`SUCCESS`) and the same `winner`;
- the specialists' reports show `"status": "confirmed"`, with `rounds`, the
  `scores` and an empty `mismatches`;
- the initiator's report shows `"status": "unverified"` and no scores: it
  takes no part, so it cannot recompute the result and trusts the agent that
  reported it. It is also written to `.run/report.json`.

If the budget of repairs is spent first, the outcome is `BEST_EFFORT` and the
winner is the best proposal found. If an agent does not answer in time, the run
is `ABORTED` and the initiator exits with an error.

## Read what the agents said

Every Claude call is recorded in `.run/claude-<agent>.log`: the flags, the full
prompt, Claude's JSON reply and how long it took. The logs grow across runs, so
delete them (`rm -f .run/claude-*.log`) before a run to keep one run per file.
Look at:

- **The first call of an agent**, which holds the description of how a run goes,
  the initiator's message and the task. Its reply carries the agent's anchors
  and its own proposal, with the rationale and reasoning.
- **A score call**, where the agent reads the other agents' messages exactly as
  they arrived and rates each proposal with reasons.
- **A repair call**, which goes to the least satisfied agent, with the ratings
  of the incumbent and the proposals already in the run. Different agents repair
  in different rounds.
- **The flags of the later calls.** An agent's calls after the first carry
  `--resume <session id>`, always the same one within a run: the agent keeps one
  conversation per run, so it remembers what it said and what it read.
