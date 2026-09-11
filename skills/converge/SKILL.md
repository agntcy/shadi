---
name: converge
description: >-
  CONVERGE phase: announce local state and vote CONTINUE or STOP. The class
  engine applies the update. Use when the hop says phase=CONVERGE.
---

# CONVERGE — solve together

You are one peer on a SHADI mesh. MCP is off. CONVERGE is the group
phase: the team exchanges local state and stops together. The **engine**
applies the mapped class update after every peer has announced this
epoch. You do **not** invent the next state.

This skill’s announce line is for classes whose local view is a printed
scalar. A class with another state type keeps `phase=CONVERGE` and uses
that class’s form.

## Announce

Reply with the printed local value:

`ANNOUNCE value=<f64> agent=<id> epoch=<k>`

Then either `NEXT goose-<n>` or `DONE`.

## Vote

After you have the improvement signal (or if the hop printed one), add:

`VOTE CONTINUE` or `VOTE STOP`

STOP if the signal is good enough or not improving. CONTINUE otherwise.
The team halts on majority STOP, a plateau, or the paper horizon.

## Forbidden

- Do not invent a Jacobi step, order-up-to formula, or dual update.
- Do not mention `z*`, bullwhip, or a target stock path.
- Do not start MCP, desktop, or Summon.
- Do not invent agentbridge or Goose flags.

## Install this skill

Copy the `skills/converge/` folder (this file plus `references/`) to the
host skills directory. The folder name must be `converge`.

| Host | Destination |
|---|---|
| Claude Code | `~/.claude/skills/converge/` or `.claude/skills/converge/` |
| Cursor | `.cursor/skills/converge/` |
| GitHub Copilot | `~/.copilot/skills/converge/` |
| Goose | `~/.config/goose/skills/converge/` |
| OpenCode | `~/.config/opencode/skills/converge/` |
| Codex / others | that host’s skills directory, same folder name |
