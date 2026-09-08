---
name: agentbridge
description: >-
  Use SHADI agentbridge to discover local A2A listeners, delegate a task to
  another coding agent, or hand off turn context over SLIM. Use when the user
  asks to list --local, delegate, handoff, collab, or talk to claude-code,
  copilot, codex, or cursor-agent through agentbridge.
---

# agentbridge — use the interconnect from a harness

You are inside a coding harness (Claude Code, Cursor, Copilot, Codex, …).
Do **not** invent A2A frames or SLIMRPC. Call the `agentbridge` CLI. The
binary is Rust; this skill is the host-agnostic client.

Prerequisites (host, not you): `agentbridge` on `PATH`, a SLIM node, and
`docs/content/demos/demo-env.sh` sourced (`SHADI_SLIM_AUTH=did`,
`SLIM_HUMAN_SEED`, `SLIM_MEMBER_DIDS`). Default endpoint is
`$SLIM_ENDPOINT` or `127.0.0.1:47357` (collab demo uses `47591`).

Your agent id is `$SHADI_AGENT_ID` (default `avatar`).

## Install this skill

Copy the `skills/agentbridge/` folder (this file plus `references/`) to
the host skills directory. The folder name must be `agentbridge`.

| Host | Destination |
|---|---|
| Claude Code | `~/.claude/skills/agentbridge/` or `.claude/skills/agentbridge/` |
| Cursor | `.cursor/skills/agentbridge/` |
| GitHub Copilot | `~/.copilot/skills/agentbridge/` |
| Codex / others | that host’s skills directory, same folder name |

## Commands (do not invent flags)

1. Who is listening — [references/list.md](references/list.md)
2. Send one task — [references/delegate.md](references/delegate.md)
3. Share a turn with a peer — [references/handoff.md](references/handoff.md)

Typical collab hop: `list --local` → `delegate` to a `slim://` peer →
read the `REPLACE`/`NEXT` reply. The host may apply the edit; you do not
write A2A yourself.
