# SecOps Agent

The SecOps agent is a demo workload built on top of SHADI. It is useful for
exercising the runtime against a realistic GitHub- and SLIM-backed workflow,
but it is not a core component of the SHADI platform itself.

It runs locally under SHADI sandbox constraints, monitors GitHub security
signals for an allowlist of repositories, writes a report, and can open
remediation issues or PRs depending on what the finding supports.

!!! note

	Use this page as a workload-specific runbook. For the core runtime surface,
	start with [Architecture](architecture.md), [Sandbox and Policies](sandbox.md),
	and [API Guide](api_integration.md).

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

For PR creation and signed commits, SecOps can also use:
- `secops.human_github`
- `secops.git_name`
- `secops.git_email`
- `secops.git_signing_key`

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

Select a provider explicitly:

```bash
just secops-run PROVIDER="google"
just secops-run PROVIDER="azure"
just secops-run PROVIDER="anthropic"
```

Run remediation mode:

```bash
just secops-run PROVIDER="google" REMEDIATE="true"
```

The report is written to:
- `${SHADI_TMP_DIR:-./.tmp}/shadi-secops/secops_security_report.md`

Pending PR requests are written to:
- `${workspace_dir}/secops_pending_prs.json`

Approve queued PR creations later:

```bash
just secops-approve-prs
```

## What SecOps remediates today

SecOps consumes three classes of GitHub signal:
- Dependabot alerts
- Security-labeled issues
- Code-scanning alerts such as Trivy container findings

The remediation behavior is intentionally different by finding type:

- Dependency alerts: update supported manifests in-place, commit repo-relative changes, and optionally open a PR.
- Container CVEs: inspect the alert, map it to the container build definition, and recommend a rebuild or base-image refresh.

Container remediation no longer injects ad-hoc package installation or upgrade lines into Dockerfiles. If the scan points at the base image lineage, the expected fix is to refresh the `FROM` image or rebuild the image so the next container scan picks up the upstream fix.

## Dockerfile discovery

For container findings, SecOps resolves the target Dockerfile in this order:

1. Direct Dockerfile path in the alert, if present.
2. `.github/workflows/*.yml` and `.github/workflows/*.yaml` as the authoritative source of build definitions.
3. Portable Python filesystem traversal of the cloned repository.
4. Single-Dockerfile fallback if the repository has only one candidate.

Workflow metadata is preferred because `docker/build-push-action` already carries the real `dockerfile:` and `context:` paths used in CI.

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

For A2A deployments, Avatar and SecOps must also agree on the SLIM endpoint,
shared secret, identity values, and TLS configuration.

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

## Test the Python remediation logic

Run the focused unit suite with `uv`:

```bash
just secops-test-python
```

This covers remediation behavior such as:
- workflow-first Dockerfile resolution,
- repo-relative staging for dependency updates,
- and container CVE guidance that prefers rebuilds or base-image refreshes.

## Scan the skill package

Run Cisco's Skill Scanner against a sanitized copy of the SecOps skill package:

```bash
just secops-skill-scan
```

This target excludes local development artifacts such as `.venv`, `__pycache__`,
`.pytest_cache`, `tests`, and `evals` before scanning, then writes a Markdown
report to:

- `${PWD}/.tmp/skill-scanner/secops-scan.md`

## Encrypted local memory (SQLCipher)
The SecOps agent uses the Python bindings (`SqlCipherMemoryStore`) for the
encrypted store. Use the helper below to inspect or seed entries without
exporting keys.

```bash
cargo run -p shadictl -- memory init --db "$SHADI_SECOPS_MEMORY_DB"
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
cargo run -p shadictl -- memory put --db "$SHADI_SECOPS_MEMORY_DB" \
	--key-name secops/memory_key \
	--scope secops --entry-key security_report --payload '{"status":"ok"}'
```

Search memory:

```bash
cargo run -p shadictl -- memory search --db "$SHADI_SECOPS_MEMORY_DB" \
	--key-name secops/memory_key \
	--scope secops --query "dependabot"
```

List memory:

```bash
cargo run -p shadictl -- memory list --db "$SHADI_SECOPS_MEMORY_DB" \
	--key-name secops/memory_key \
	--scope secops
```

## Operational notes

- When `SHADI_SECRET_BACKEND=onepassword`, the launch scripts pre-read required secrets before entering the sandbox because the sandbox may block the `op` CLI biometric/background flow.
- If Avatar reports a SLIM session handshake failure, check that the SecOps A2A server is running and that both sides share the same endpoint, shared secret, identity, and TLS settings.
