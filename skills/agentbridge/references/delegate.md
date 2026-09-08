# delegate

Send one prompt to a registered adapter over A2A/SLIM. You are the A2A
client; `agentbridge` proves as `--agent-id`.

```bash
agentbridge delegate "your task text" \
  --to copilot \
  --agent-id "${SHADI_AGENT_ID:-avatar}" \
  --endpoint "${SLIM_ENDPOINT:-127.0.0.1:47357}"
```

`--to` is a name from `list --local` (not `slim:copilot`). The reply is
printed after `Response from '<id>'`. Treat that text as the peer’s
artifact (for the collab demo: `REPLACE` / `INSERT` / `APPEND` plus
optional `NEXT <peer>` or `DONE`).

Do not add flags that are not on this command.
