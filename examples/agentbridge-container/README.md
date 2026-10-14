# Announcing agentbridge agents to runtime discovery

Run agentbridge agents as host processes and as Docker containers, and find them by OASF skill through runtime discovery (dir-runtime, embedded in `dirctl daemon`). The agents use a fake harness (`fake-harness`) that answers without a model, so nothing here spends tokens.

| File | What it is |
| --- | --- |
| `fake-harness` | The stand-in harness: prints the prompt, the agent's name and its skills |
| `profiles/fake-harness.json` | The agentbridge profile that runs it (`--tool fake-harness`) |
| `Dockerfile`, `entrypoint.sh` | An image with `agentbridge`, `shadictl` and the fake harness |
| `compose.yaml` | Two containerised agents with Docker discovery labels |

## How an agent is found

1. `agentbridge register` serves its A2A card, which lists its OASF skills and domains in the OASF `discovery` extension (`<schema URL>/<version>/objects/discovery`) and its DIDs in the `identity` extension. Skills and domains are checked against the OASF server first.
2. Runtime discovery learns the workload exists:
   - **Host process:** `--dir-announce` writes a descriptor to `~/.agntcy/dir-runtime/workloads.d` and deletes it when `register` stops.
   - **Container:** the `org.agntcy/discover=true` and `org.agntcy/agent-type=a2a` labels.
3. dir-runtime fetches `/.well-known/agent-card.json` from the workload's HTTP endpoints. SLIM and gRPC don't serve it, so `register` adds a card listener (`--card-listen`; with `--dir-announce` a free loopback port is used by default).
4. `dirctl runtime list --skill …` lists the workloads whose card carries the skill.

## Prerequisites

- `dirctl` with runtime discovery that lists host processes and filters by agent (agntcy/dir#2352 and #2353), started with runtime discovery on:

  ```sh
  DIRECTORY_DAEMON_RUNTIME_ENABLED=true dirctl daemon start
  export DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888
  ```

- `agentbridge` and `shadictl` built from this repository (`cargo build -p agntcy-agentbridge-cli -p agntcy-shadi-cli`). Listeners only start inside the SHADI sandbox.
- DID auth for the listener. Any seed works for trying this out; the member list must name at least one DID:

  ```sh
  export SHADI_SLIM_AUTH=did SLIM_HUMAN_SEED=demo-human-seed \
         SLIM_MEMBER_DIDS=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
  ```

## A host process

```sh
export AGENTBRIDGE_PROFILES_DIR=$PWD/examples/agentbridge-container/profiles
export PATH=$PWD/examples/agentbridge-container:$PATH   # puts fake-harness on PATH

shadictl --net-block \
  --net-allow 127.0.0.1:19950 --net-allow schema.oasf.outshift.com:443 \
  --write ~/.agntcy/dir-runtime/workloads.d \
  -- agentbridge register --tool fake-harness \
     --a2a-listen 127.0.0.1:19950 --a2a-binding http+json \
     --skill software_engineering/code_debugging/error_handling \
     --domain technology/networking/network_security \
     --version 1.0.0 \
     --dir-announce
```

The sandbox needs write access to the descriptor directory (`--write`) and outbound access to the OASF server for validation (or pass `--skip-oasf-validation`). For a gRPC or SLIM binding, also allow the card listener's address and pass it with `--card-listen`, e.g. `--card-listen 127.0.0.1:19952`.

In another terminal:

```sh
dirctl runtime list
dirctl runtime list --skill "software_engineering/*" --runtime process
dirctl runtime list --domain "technology/*" --output json
```

Ctrl-C (or SIGTERM to `agentbridge`) withdraws the announcement; the agent disappears from the list. If the process dies without cleaning up, dir-runtime drops it once it notices the PID is gone.

## Containers

```sh
docker build -f examples/agentbridge-container/Dockerfile -t agentbridge-fake .
docker compose -f examples/agentbridge-container/compose.yaml up -d
```

Each container runs `agentbridge register` inside `shadictl`, with the A2A listener on HTTP+JSON over a self-signed certificate (port 8443) and the card on plain HTTP (port 8081), both published to the host. `--advertise-url` puts the published A2A port in the card (`https://127.0.0.1:18443`), since the listen address `0.0.0.0:8443` isn't reachable from the host. `dirctl daemon` discovers the containers by their labels and reads their cards from the published ports:

```sh
dirctl runtime list --runtime docker
dirctl runtime list --skill "language_processing/*"
dirctl runtime list --name fake-harness --output json
docker compose -f examples/agentbridge-container/compose.yaml down   # they disappear
```

Discovery only needs the card, which is plain HTTP. Sending a container a task goes to its A2A listener, whose self-signed certificate the caller won't trust. To delegate to a container, give it a certificate your machine trusts, e.g. with [mkcert](https://github.com/FiloSottile/mkcert), and mount it:

```sh
mkcert -install && mkcert -cert-file /tmp/agent.pem -key-file /tmp/agent-key.pem localhost 127.0.0.1
docker run … -v /tmp/agent.pem:/tls/cert.pem:ro -v /tmp/agent-key.pem:/tls/key.pem:ro \
  -e A2A_TLS_CERT=/tls/cert.pem -e A2A_TLS_KEY=/tls/key.pem agentbridge-fake …
agentbridge delegate --to <agent DID from the card> --a2a-url https://127.0.0.1:38443 --a2a-binding http+json "…"
```

To run one container by hand, pass the labels and any `register` flags:

```sh
docker run -d --name my-agent -p 38443:8443 -p 38081:8081 \
  --label org.agntcy/discover=true --label org.agntcy/agent-type=a2a \
  -e SHADI_SLIM_AUTH=did -e SLIM_HUMAN_SEED=demo-human-seed \
  -e SLIM_MEMBER_DIDS=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK \
  agentbridge-fake --skill software_engineering/code_generation \
  --advertise-url https://127.0.0.1:38443
```

## Using a local OASF server

Point both sides at it. agentbridge validates against it and names the `discovery` extension after it; `dirctl daemon` must accept it, or it ignores the extension:

```sh
agentbridge register … --oasf-schema-url http://localhost:8080
DIRECTORY_DAEMON_RUNTIME_OASF_SCHEMA_URLS=https://schema.oasf.outshift.com,http://localhost:8080 dirctl daemon start
dirctl runtime list --oasf-schema-url https://schema.oasf.outshift.com --oasf-schema-url http://localhost:8080 --skill …
```

## Notes

- Everything listed is a claim made by whoever started the workload; nothing is verified yet (agntcy/dir-runtime#94).
- The card names no author yet, so `dirctl runtime list --author` finds no agentbridge agents; the author comes with card signatures (#482).
- Skill names are OASF 1.1.0 classes. An agent advertises only the skills it is given (`--skill`, or a `--record`); without one it has no `discovery` extension and isn't found by skill.
- SIGTERM sent to `shadictl` (rather than to `agentbridge`) ends the agent without withdrawing the announcement; dir-runtime still drops it by its PID.
