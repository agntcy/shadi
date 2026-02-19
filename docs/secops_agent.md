# SecOps Agent

The SecOps agent runs locally under SHADI sandbox constraints and monitors
GitHub security signals for an allowlist of repositories. It writes a report
and can be extended to open remediation PRs.

## Prerequisites
- SHADI Python extension installed in your `uv` environment.
- GitHub token stored in SHADI.
- Operator presentation set via `SHADI_OPERATOR_PRESENTATION`.

## Configure
Configuration lives in secops.toml at the repo root:
- `secops.allowlist`
- `secops.token_key`
- `secops.workspace_key`
- `github.api_base`

## Load secrets
```bash
source ~/.env-phoenix
export GITHUB_TOKEN="$(gh auth token)"
export SHADI_OPERATOR_PRESENTATION="local-operator"
uv run agents/secops/import_secops_secrets.py
```

If `SECOPS_MEMORY_KEY` is unset, the importer generates a key and stores it in
SHADI so it never leaves the secret store.

## Run the agent
```bash
SHADI_OPERATOR_PRESENTATION="local-operator" uv run agents/secops/secops.py
```

The report is written to:
- `${SHADI_TMP_DIR:-./.tmp}/shadi-secops/secops_security_report.md`

## Long-running operation
For continuous monitoring, run on a schedule and manage memory:

### Short-term memory
- Keep recent alerts and tool state in process memory.

### Long-term memory
- Persist summaries to the allowlisted workspace directory.
- Store remediation history in a local file or external store allowed by policy.
- The ADK agent uses `PreloadMemoryTool` and `load_memory` to recall prior runs.
- Sessions are saved to ADK memory automatically after each run.

### Continuous runner
```python
import time

POLL_SECONDS = 900

while True:
	# invoke the skill or ADK agent
	time.sleep(POLL_SECONDS)
```

Ensure the sandbox policy allows workspace read/write and network access to
GitHub and the ADK model endpoint.

To use persistent ADK memory (Vertex AI Memory Bank), run the ADK agent with a
memory service URI:

```bash
adk run agents/secops/adk_agent --memory_service_uri "agentengine://YOUR_ENGINE_ID"
```

## List secrets
```bash
cargo run -p shadictl -- --list-keychain --list-prefix secops/
```

## Secret store helpers
`shadictl` can read secrets and store OpenPGP keys used for agent identity:

```bash
cargo run -p shadictl -- put-key --key human/gpg --in /path/to/human-secret.asc
```

Avoid exporting secret values. For SQLCipher memory, use the helper below so
the key is resolved from SHADI without printing it.

## List enforced policy
```bash
cargo run -p shadictl -- --policy policies/demo/secops-a.json --print-policy
```

## Skill definition
The skill lives in:
- agents/secops/SKILL.md

To run via ADK:
```bash
uv pip install google-adk
adk run agents/secops/adk_agent
```

Local-only run with in-memory ADK memory service:

```bash
uv run agents/secops/adk_agent/run_local.py
```

## Encrypted local memory (SQLCipher)
The SecOps agent uses the Python bindings (`SqlCipherMemoryStore`) for the
encrypted store. Use the helper below to inspect or seed entries without
exporting keys.

```bash
cargo run -p shadictl -- -- memory init --db "$SHADI_SECOPS_MEMORY_DB"
```

Set the database path and write summaries from the SecOps skill:

```bash
export SHADI_TMP_DIR="./.tmp"
export SHADI_SECOPS_MEMORY_DB="${SHADI_TMP_DIR}/${SHADI_AGENT_ID:-secops_agent}/shadi-secops/secops_memory.db"
```

Always reuse the same full path when listing or searching; using a relative
path like `secops_memory.db` will point to a different database.

Store a summary via the CLI:

```bash
cargo run -p shadictl -- -- memory put --db "$SHADI_SECOPS_MEMORY_DB" \
	--key-name secops/memory_key \
	--scope secops --entry-key security_report --payload '{"status":"ok"}'
```

Search memory:

```bash
cargo run -p shadictl -- -- memory search --db "$SHADI_SECOPS_MEMORY_DB" \
	--key-name secops/memory_key \
	--scope secops --query "dependabot"
```

List memory:

```bash
cargo run -p shadictl -- -- memory list --db "$SHADI_SECOPS_MEMORY_DB" \
	--key-name secops/memory_key \
	--scope secops
```
