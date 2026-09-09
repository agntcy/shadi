# delegate

Send one prompt to a registered adapter over A2A. You are the A2A
client; `agentbridge` proves as `--agent-id`.

`--to` is the **portable name**: a DID from `list --local`, a local
alias (`copilot`), or the SLIM channel (`agntcy/shadi/copilot-a2a`).
The locator is the local SLIM node (`slim://host:port`) and/or a unicast
URL; look the DID up again (or pass `--a2a-url` as an override).

SLIMRPC (needs a SLIM node; `--to` still resolves to a DID):

```bash
agentbridge delegate "your task text" \
  --to copilot \
  --agent-id "${SHADI_AGENT_ID:-avatar}" \
  --endpoint "${SLIM_ENDPOINT:-127.0.0.1:47357}"
```

Unicast (no SLIM node). Prefer the DID so a port/host/binding change still
finds the same agent:

```bash
agentbridge list --local
# copilot  did=did:key:z…  grpc://127.0.0.1:50051
# goose    did=did:key:z…  jsonrpc://127.0.0.1:8080

agentbridge delegate "your task text" \
  --to did:key:z… \
  --agent-id "${SHADI_AGENT_ID:-avatar}"
```

`--a2a-url` is only a locator override, and only with `--to did:key:…`.
Accepts `slim://host:port`, `grpc://host:port`, `jsonrpc://host:port`,
`http+json://host:port`, or a bare `http(s)://` URL plus `--a2a-binding`.
A bare `http://` without a binding still means gRPC. Do not treat the
locator as the name: two agents can share one SLIM node or one URL;
the destination DID on the message selects which one runs the task.

The reply is printed after `Response from '<id>'`. Treat that text as
the peer’s artifact (for the collab demo: `REPLACE` / `INSERT` /
`APPEND` plus optional `NEXT <peer>` or `DONE`).

Do not add flags that are not on this command. `https://` gRPC is not
supported yet; JSON-RPC and HTTP+JSON may use HTTPS.
