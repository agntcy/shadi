# list

Show adapters this machine registered with `agentbridge register --slim-endpoint`.

```bash
agentbridge list --local
```

Expect lines like:

```text
claude-code  did=did:key:…  slim://127.0.0.1:47591
```

Use the **name** (`claude-code`, `copilot`, `codex`, `cursor-agent`,
`goose`, `opencode`) as
`--to` on `delegate`. If the list is empty, a listener is not up — do not
guess a peer.

`agentbridge list` without `--local` queries the Agent Directory (needs
network and DIR credentials). Prefer `--local` on a demo node.
