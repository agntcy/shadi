# list

Show adapters this machine registered with `agentbridge register
--slim-endpoint` and/or `--a2a-listen` (`--a2a-binding grpc|jsonrpc|http+json`).

```bash
agentbridge list --local
```

Expect lines like:

```text
claude-code  did=did:key:…  slim://127.0.0.1:47591
copilot  did=did:key:…  grpc://127.0.0.1:50051
goose    did=did:key:…  jsonrpc://127.0.0.1:8080
```

Use the **DID** (`did=did:key:…`) as `--to` on `delegate` — it stays valid
if the agent moves. The tool name (`copilot`) is a local alias for whoever
currently holds that lease. If the list is empty, a listener is not up —
do not guess a peer.

`agentbridge list` without `--local` queries the Agent Directory (needs
network and DIR credentials). Prefer `--local` on a demo node.
