# handoff

Share session context with another peer over A2A. Prefer `slim:` so the
call uses SLIM, not a local subprocess.

When **you** are the finishing agent (your `$SHADI_AGENT_ID` matches
`--from`):

```bash
SHADI_AGENT_ID=claude-code agentbridge handoff \
  --from slim:claude-code \
  --to slim:copilot \
  --slim-endpoint "${SLIM_ENDPOINT:-127.0.0.1:47357}"
```

Snapshot stays local so you do not `SendMessage` to your own listener.
Only the destination inject is an A2A task.

A collab listener with `AGENTBRIDGE_A2A_FORWARD=1` may already dispatch
`NEXT` itself. Do not double-handoff unless the user asks.

Bare names (`--from claude-code --to copilot`) open local CLI adapters,
not A2A. Use those only when both tools run in this process.
