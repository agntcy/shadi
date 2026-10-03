---
name: converge
description: >-
  CONVERGE phase: apply your update rule to your local quantities, announce
  the value you computed, and vote CONTINUE or STOP. Use when the hop says
  phase=CONVERGE.
---

# CONVERGE — solve together

You are one peer on a SHADI mesh. MCP is off. CONVERGE is the group
phase: the team exchanges local state and stops together.

The hop prints your update rule, the one you gave in ASSEMBLY, and your
local quantities by name. Apply the rule to those values and compute
your next value yourself. Nothing else computes it for you, and a wrong
value is applied as given.

This skill’s announce line is for classes whose state is a scalar. A
class with another state type keeps `phase=CONVERGE` and uses that
class’s form.

## Announce

End with the value you computed:

`ANNOUNCE value=<f64> agent=<id> epoch=<k>`

Then either `NEXT goose-<n>` or `DONE`. A reply with no readable
`ANNOUNCE` line is asked once more; a second one ends the run.

## Vote

After you have the improvement signal (or if the hop printed one), add:

`VOTE CONTINUE` or `VOTE STOP`

STOP if the signal is good enough or not improving. CONTINUE otherwise.
The team halts on majority STOP, a plateau, or the paper horizon.

## Forbidden

- Do not swap in a different rule: apply the one printed.
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
