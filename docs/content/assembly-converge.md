# ASSEMBLY and CONVERGE

ASSEMBLY and CONVERGE are the two **group** phases in
[SHADI MAS](shadi-mas.md) (`shadi_mas`). A team first builds a shared
model of a problem and derives the update rule it will run, then each
agent applies that rule to its local state while a class engine applies
what the agents announce, and the team decides whether to stop.

The protocol is not limited to numbers. A class may use scores, orders,
stock, code artifacts, or another local state the engine understands.
What must stay true is the group: peers model together, then converge
together. `agentbridge coordinate` drives both phases.

## Why these names

The names must read as group work.

| Name | What the team does | Why not a shorter word |
|------|--------------------|------------------------|
| **ASSEMBLY** | Jointly understand the problem and propose a system model | *Model* can be one agent writing a formalization alone |
| **CONVERGE** | Apply the derived rule to local state, announce the result together, and halt together | *Solve* can be one agent producing the next state alone |

A single agent can model or solve. ASSEMBLY and CONVERGE require peers.

## What this is not

- Not hop-local `COMMIT proposal=`. CONVERGE announces each agent's
  next state, computed with its own rule, in the form the class
  requires; the engine applies those values after a full epoch.
- Not a closed taxonomy. Preference, cascade, resource, and development
  are **implemented examples**. ASSEMBLY may name another class.
- Not “numeric MAS.” Scalar announce is how some example engines speak.
  A class whose state is an artifact, a plan, or another object still
  uses these two phases.
- Not an LLM theorem. Mapping a prompt to `preference` does not prove
  Jacobi or the paper’s preference-linear result. `proves_llm_mas` is
  false.
- Not the two-line Rust fifo demo. That loop is [round-robin collab](demos/collab-rust.md).
- Not a skill pasted into `--text`. Peers load Agent Skills; the hop only
  names the phase.

## Two phases

```mermaid
flowchart TD
  start[Goal plus roster] --> assembly["ASSEMBLY\njoint model · CLASS and UPDATE lines"]
  assembly --> mapped{Implemented class?}
  mapped -->|yes| converge["CONVERGE\napply own rule · announce · halt"]
  mapped -->|Unmapped| stopUnmapped[Halt: no solver]
  converge --> halt{Halt?}
  halt -->|continue| converge
  halt -->|class halt| done[Stop as a team]
```

| Phase | Who speaks | Who computes the next state | Exit |
|-------|------------|-----------------------------|------|
| ASSEMBLY | Every peer | Nobody. Each peer derives a rule; `AssemblySession` infers a class | A `PatternKind` and one rule per peer, or `Unmapped` |
| CONVERGE | Every peer announces its next state and may vote | Each peer, with its own rule; the engine applies what is announced | That engine’s halt |

A class is implemented when SHADI has an engine for it. Today that is
`development` (code artifacts) and the three paper examples
(`preference`, `cascade`, `resource`). Any other `CLASS` token is
`Unmapped`. CONVERGE must not start on `Unmapped`.

`--pattern` selects or seeds the class. ASSEMBLY always runs before a
paper CONVERGE, since that is where each peer's rule comes from;
`--assembly` also runs it before `development`. After ASSEMBLY,
`coordinate` starts the matching CONVERGE engine or refuses if the class
is unmapped.

## ASSEMBLY

ASSEMBLY is joint modeling. Peers debate in natural language: who the
agents are, what they exchange, and what “better” means. Each derives
the update rule it will apply in CONVERGE. They **may** name a class
that SHADI does not implement.

### Line protocol

Each peer ends with exactly two lines:

```text
CLASS <name>
UPDATE <expression>
```

Then `NEXT <peer>` or `DONE`. No other protocol text.

`<expression>` gives the agent's next value over its class's named local
quantities, with numbers, `+ - * /`, parentheses, `max`, `min`, `abs`
and `clamp(x, low, high)`:

| Class | Quantities |
|-------|------------|
| `preference` | `state`, `target`, `beta`, `degree`, `neighbour_sum` |
| `cascade` | `inventory`, `pipeline`, `last_order`, `demand`, `previous_demand`, `target_inventory`, `lead`, `rho`, `gamma` |
| `resource` | `extraction`, `desired`, `price`, `stock`, `eta` |

`coordinate` scores each rule by probing: it evaluates the rule and the
class's reference rule on 64 random points, so a correct rule written
another way still matches. The verdict is `matches`, `differs` (with
the worst gap), `invalid` (it does not parse over those names), or
`missing`. A peer without a usable rule cannot take part, and CONVERGE
does not start.

`<name>` is an implemented token (`development`, `preference`,
`cascade`, `resource`) or another short token (`matching-markets`, …).
A token SHADI does not implement becomes `PatternKind::Unmapped`.

### Inference

`AssemblySession` is soft. Prose is the debate; the hypothesis is
inferred.

1. A `CLASS <name>` or `CLASS=<name>` line wins.
2. Otherwise keywords may vote among the paper examples (for example
   “neighbor” / “quadratic” → preference; “inventory” / “pipeline” →
   cascade; “extraction” / “quota” → resource). A tie or no hits leaves
   the last stable hypothesis unchanged.
3. `remap()` clears the hypothesis and re-ingests. Use that when the
   team changes its mind.

Do not leak a global optimum or a full instance during ASSEMBLY. For the
paper examples that means no `z*`, full demand path, bullwhip, or
terminal stock forecast. Deriving the rule is not computing the answer.

## CONVERGE

CONVERGE is a group solve. Each epoch:

1. Every peer sees its rule and its **local** quantities by name,
   applies the rule, and announces the next state it computed.
2. The matching engine applies the announced values once the epoch is
   full.
3. The team records progress (an improvement signal, a quorum, or
   another class-specific check).
4. Peers vote whether to continue, when the class uses ballots.
5. The team halts together.

The engine never computes a peer's next state. A wrong rule, or a
wrong application of a right one, shows up in the trajectory.

### Class-specific announce

The hop prints `phase=CONVERGE`, the peer's rule and its named
quantities, with no next value suggested. The announce *form* belongs
to the class.

**Scalar paper examples** (preference, cascade, resource):

```text
ANNOUNCE value=<f64> agent=<id> epoch=<k>
VOTE CONTINUE
```

or `VOTE STOP`. Then `NEXT <peer>` or `DONE`. A reply with no readable
`ANNOUNCE` line, or a failed call, is asked once more with the reason;
if that also fails the run halts with `unreadable-announcement`. No
value is ever substituted.

`COMMIT proposal=` is still parsed as an announce alias so older
transcripts do not break. New hops should use `ANNOUNCE`.

**Development** (code artifacts): each peer proposes `ExternalBytes`
and endorses via `ToolResult`. Halt is quorum on the winning artifact,
or `--max-rounds`. See
[AgentBridge → DevelopmentEngine](agentbridge.md#developmentengine).

A future class uses the same phase and a new announce form. Do not
force every class through `value=<f64>`.

### Halt on the paper examples

Those three engines share `ConvergeController`. It stops on the first
of:

| Halt | Meaning |
|------|---------|
| `MajorityStop` | Strict majority of the roster voted `STOP` this epoch |
| `Plateau` | Metric failed to improve for `plateau_k` epochs (default 3 in `coordinate`) |
| `NoSolution` | Plateau after at least one compared epoch with no improvement |
| `PaperHorizon` | Epochs reached the class horizon |
| `Unmapped` | ASSEMBLY named a class with no engine |

`coordinate` adds two halts of its own: `missing-update-rule` (a peer
gave no usable rule, so CONVERGE never starts) and
`unreadable-announcement` (a peer's reply could not be read twice).
With `--report`, the run records derivation (each peer's rule and its
verdict) apart from execution (how far each announcement was from the
peer's own rule, and from the reference).

Preference treats lower metric as better (`‖z − z*‖₂`). Cascade uses
accumulated cost (lower is better). Resource uses remaining stock
(higher is better). Other classes may halt on a different signal.

## Implemented example classes

These are examples, not a closed set. ASSEMBLY may name something else;
that is a successful modeling outcome and an `Unmapped` CONVERGE
refusal.

| Class | `PatternKind` | Announced | Reference rule (scoring only) | Default horizon in `coordinate` |
|-------|---------------|-----------|-------------------------------|----------------------------------|
| Development | `Development` | code artifact | Endorse proposals; most votes wins | `--max-rounds` |
| Preference aggregation | `Preference` | next `z_i` | Synchronous Jacobi on the neighbor values | `--max-rounds` |
| Supply-chain cascades | `Cascade` | next order | Order-up-to + smoothing; the engine owns the plant | `min(--max-rounds, demand length)` (paper demand is 8) |
| Sustainable resource | `Resource` | next extraction `e_i` | Dual step on `e_i`; the engine owns `λ` and the stock | `min(--max-rounds, 12)` |

### Development (`DevelopmentEngine`)

`--pattern development` (the `coordinate` default) is CONVERGE for a
shared code artifact. Peers propose implementations and endorse one.
Finalization selects the artifact with the most endorsements when
quorum is met.

### Preference (`PreferenceEngine`)

Line graph, private scores `c`, coupling `β` (default `0.75`). Each
epoch every node announces its next `z_i`, and the engine applies the
announced values together. The reference a node's rule is scored
against is the simultaneous (Jacobi, not Gauss–Seidel) step:

```text
z_i ← (c_i + 2β Σ_{j∈N_i} z_j) / (1 + 2β d_i)
```

The unique fixed point is `z* = (I + 2β L)⁻¹ c`. This is **not** a
median vote (that is a different object in the paper).

### Cascade (`CascadeEngine`)

Stages in a chain. Downstream orders become upstream demand. Paper
constants: lead `L = 2`, target inventory `I = 8`, demand
`[4, 4, 4, 8, 8, 8, 4, 4]`, smoothing `0.5`. Agents announce their
next order. The engine places it and owns inventory and pipeline.

### Resource (`ResourceEngine`)

Peers share a renewable stock. Paper constants: `R⁰ = 24`, capacity 30,
regen `0.2`, quota fraction `0.25`, `α = 0.35`, `η = 0.4`, 12 rounds.
Agents announce their next extraction. The engine applies the price
step and the stock's regrowth. With every agent on the reference rule,
coordinated `α > 0` retains more stock than uncontrolled greedy on the
paper instance.

## Agent Skills

Peers are instrumented with Agent Skills, using the same install map as
[`skills/agentbridge`](https://github.com/agntcy/shadi/tree/main/skills/agentbridge).
Copy the folder. The folder name must match. Do not paste `SKILL.md`
into `--text`.

| Skill | Folder | When it applies |
|-------|--------|-----------------|
| ASSEMBLY | [`skills/assembly/`](../../skills/assembly/SKILL.md) | Hop prints `phase=ASSEMBLY` |
| CONVERGE | [`skills/converge/`](../../skills/converge/SKILL.md) | Hop prints `phase=CONVERGE` and the class uses a printed local view |

The skills carry the instructions, including the table of quantity
names; a test keeps that table equal to the names each engine accepts.
`skills/converge` as shipped teaches applying the rule and the scalar
announce / `VOTE` form. A class with a different state type (including development)
keeps the same phase name and uses that class’s announce form.

| Host | Destination |
|------|-------------|
| Claude Code | `~/.claude/skills/<name>/` or `.claude/skills/<name>/` |
| Cursor | `.cursor/skills/<name>/` |
| GitHub Copilot | `~/.copilot/skills/<name>/` |
| Goose | `~/.config/goose/skills/<name>/` |
| OpenCode | `~/.config/opencode/skills/<name>/` |
| Codex / others | that host’s skills directory, same folder name |

A mesh job copies both folders into the job-local
`$XDG_CONFIG_HOME/goose/skills/` tree. The hop names the phase; it does
not inline the skill body.

Do not invent agentbridge or Goose flags in the skill text.

## CLI

```bash
# ASSEMBLY, then CONVERGE on whatever class the team names
agentbridge coordinate \
  --goal "implement a JSON parser in Rust" \
  --agents claude-code,copilot,codex \
  --pattern unmapped \
  --assembly \
  --quorum 2 \
  --max-rounds 5

# Seed the class; ASSEMBLY still runs, for each peer's rule
agentbridge coordinate \
  --goal "stages in a chain order from inventory" \
  --agents slim:goose-0,slim:goose-1,slim:goose-2,slim:goose-3 \
  --pattern cascade \
  --max-rounds 8 \
  --slim-endpoint 127.0.0.1:47357
```

| Flag | Role |
|------|------|
| `--pattern development` | Default. CONVERGE on `DevelopmentEngine` |
| `--pattern preference\|cascade\|resource` | CONVERGE on that paper engine |
| `--pattern unmapped` | Force ASSEMBLY; CONVERGE starts only if an implemented class is inferred |
| `--assembly` | Run ASSEMBLY before `development` too (it always runs before a paper class) |
| `--max-rounds` | CONVERGE horizon cap |
| `--quorum` | Endorsement quorum for `DevelopmentEngine` |

`--agents` specs are the same as the rest of agentbridge (`goose`,
`slim:<id>`, …). Listeners still come from `agentbridge register`.
Identity is DID-only; see
[AgentBridge → DID authentication](agentbridge.md#did-authentication).

In the CLI, `PatternKind::is_converge_class()` means “use the scalar
paper driver (`ConvergeController`)”. Development is still CONVERGE; it
uses the artifact driver.

## Honest claims

| Claim | Holds when | Does not mean |
|-------|------------|---------------|
| A peer derived the rule | Its `UPDATE` verdict is `matches` | It derived rather than recalled it: these are textbook problems |
| Hold equals Ideal | Every peer's rule matches and its execution gap is zero, on the intended class, for that class horizon | Every class has an Ideal |
| ASSEMBLY mapped the intended class | `CLASS` / keywords inferred the intended label | The class set is closed, or the map is a proof |
| Unmapped is success for modeling | The team named a class SHADI does not solve | A solver ran |
| Mesh is live | Peers admitted, every peer recvs, NEXT/HANDOFF on the ring, hops use `slim://` | Hold vs Ideal |

Do not claim Gemma (or any other model) discovered Jacobi or proved
preference-linear.

## Types and files

| Item | Location |
|------|----------|
| `ProtocolPhase::{Assembly, Converge}` | `crates/shadi_mas/src/types.rs` |
| `PatternKind`, `ConvergeBallot`, `ConvergeHalt`, `ConvergeSignal` | same |
| `AssemblySession`, `infer_pattern` | `crates/shadi_mas/src/assembly.rs` |
| `ConvergeController`, `ConvergeSurface` | `crates/shadi_mas/src/engines/converge.rs` |
| Class engines | `engines/development.rs`, `preference.rs`, `cascade.rs`, `resource.rs` |
| CLI driver | `crates/agentbridge_cli/src/commands/coordinate.rs` |
| Skills | `skills/assembly/`, `skills/converge/` |

## Next steps

- Runtime, engines, and adapters: [SHADI MAS](shadi-mas.md).
- Install listeners and DID auth from [AgentBridge](agentbridge.md).
- For transport and group admission see [SLIM and A2A](slim_a2a.md).
