# Demo walkthrough

This walkthrough shows a real, end-to-end SLIM A2A demo: two SecOps agents and
one human (Avatar) in the same group channel, backed by a local SLIM node.

## 1) Start a local SLIM node

Use the launcher to start the local SLIM instance configured for the demo:

```bash
just launch-slim-example
```

## 2) Seed SLIM shared secret in SHADI

Both SecOps agents and the Avatar agent use the same shared secret stored in
SHADI. Import it once using the bootstrap script:

```bash
export SHADI_OPERATOR_PRESENTATION="local-operator"
export SLIM_SHARED_SECRET="$(openssl rand -hex 32)"

just import-secops-secrets
```

## 3) Run two SecOps agents on the same channel

The demo ships per-agent configs under `./.tmp`. Start each agent in its own
terminal:

```bash
just launch-secops-a2a-example
```

To start a second agent, set `SHADI_AGENT_ID=secops-b` and point
`SHADI_SECOPS_CONFIG` to `./.tmp/secops-b.toml` before running the launcher.

## 4) Connect as a human using the Avatar ADK agent

```bash
just launch-avatar-example
```

In the Avatar prompt, ask for actions like:

```
scan dependabot for the allowlist
report
```

## 5) Key and DID utilities

SHADI can ingest OpenPGP keys without shelling out to `gpg`. Store a human
OpenPGP secret key, then derive an agent DID and keypair in the secret store:

```bash
cargo run -p shadictl -- \
  put-key --key human/gpg --in /path/to/human-secret.asc

cargo run -p shadictl -- \
  derive-agent-did \
  --secret human/gpg \
  --name agent-a \
  --prefix agents \
  --out agent-a.did.json
```

You can also create a DID document from a public OpenPGP key file:

```bash
cargo run -p shadictl -- \
  did-from-gpg --in /path/to/human-public.asc --out human.did.json
```

Notes:
- Keys and DIDs are stored in the SHADI secret store.
- OpenPGP parsing uses `sequoia-openpgp`, not the OS `gpg` binary.

## Notes
- The SecOps A2A servers and Avatar agent share the same SLIM endpoint and
  shared secret in SHADI.
- Adjust `secops.toml` or the per-agent configs if you want different identities
  or endpoints.
