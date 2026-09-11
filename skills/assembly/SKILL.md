---
name: assembly
description: >-
  ASSEMBLY phase: jointly understand a problem, propose a system model, and
  optionally name a class. Use when the hop says phase=ASSEMBLY or the team
  must model a problem before solving it.
---

# ASSEMBLY — model the problem together

You are one peer on a SHADI mesh. MCP is off. This phase is **group
modeling**, not a single agent solving.

Understand the problem with your peers. Propose a system model: who the
agents are, what they exchange, and what “better” means. Offer a
formalization if you can.

You **may** name a class that is not one of the three paper examples
(Preference Aggregation, Supply Chain Cascades, Sustainable Resource
Allocation). Those three are examples, not a closed set.

## Line protocol

End with exactly one line:

`CLASS <name>`

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
