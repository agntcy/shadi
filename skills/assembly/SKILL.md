---
name: assembly
description: >-
  ASSEMBLY phase: jointly understand a problem, propose a system model, name
  a class, and derive the update rule each agent will apply. Use when the hop
  says phase=ASSEMBLY or the team must model a problem before solving it.
---

# ASSEMBLY — model the problem together

You are one peer on a SHADI mesh. MCP is off. This phase is **group
modeling**, not a single agent solving.

Understand the problem with your peers. Propose a system model: who the
agents are, what they exchange, and what “better” means. Then derive the
update rule: how one agent computes its next value from what it can see.

You **may** name a class that is not one of the three paper examples
(Preference Aggregation, Supply Chain Cascades, Sustainable Resource
Allocation). Those three are examples, not a closed set.

## The update rule

In CONVERGE you apply the rule you give here yourself, every epoch.
Nothing else computes your next value, and a wrong rule is applied as
given.

Write it over your class's named local quantities only:

| Class | Quantities |
|---|---|
| `preference` | `state`, `target`, `beta`, `degree`, `neighbour_sum` |
| `cascade` | `inventory`, `pipeline`, `last_order`, `demand`, `previous_demand`, `target_inventory`, `lead`, `rho`, `gamma` |
| `resource` | `extraction`, `desired`, `price`, `stock`, `eta` |

Use numbers, `+ - * /`, parentheses, `max`, `min`, `abs`, and
`clamp(x, low, high)`. For example `max(0, a - b) / (1 + c)`, with your
class's names in place of `a`, `b` and `c`.

Deriving the rule is not computing the answer. Give the rule, never a
solution.

## Line protocol

End with exactly two lines:

`CLASS <name>`
`UPDATE <expression>`

`<name>` is `preference`, `cascade`, `resource`, or another short token
if you believe the problem is a different class. Then `NEXT goose-<n>`
or `DONE`. No other text.

## Forbidden

- Do not compute or mention a global target vector, `z*`, a full demand
  path, bullwhip, or a terminal stock forecast.
- Do not start MCP, desktop, or Summon.
- Do not invent agentbridge or Goose flags.

## Install this skill

Copy the `skills/assembly/` folder to the host skills directory. The folder
name must be `assembly`.

| Host | Destination |
|---|---|
| Claude Code | `~/.claude/skills/assembly/` or `.claude/skills/assembly/` |
| Cursor | `.cursor/skills/assembly/` |
| GitHub Copilot | `~/.copilot/skills/assembly/` |
| Goose | `~/.config/goose/skills/assembly/` |
| OpenCode | `~/.config/opencode/skills/assembly/` |
| Codex / others | that host’s skills directory, same folder name |
