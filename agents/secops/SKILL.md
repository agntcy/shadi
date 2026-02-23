---
name: secops
description: Collects security alerts and issues for allowlisted GitHub repos, writes a report, and supports remediation planning. Use when you need a SecOps agent to monitor Dependabot alerts or security-labeled issues under SHADI sandbox constraints.
license: Apache-2.0
compatibility: Requires git, internet access to api.github.com, SHADI Python extension, and a GitHub token stored in SHADI.
metadata:
  framework: google-adk
  version: "1.0"
---

# SecOps Autonomous Remediation (Google ADK)

## Overview
This skill enables a SecOps agent to monitor GitHub security alerts for an
allowlist of repositories, generate remediation plans, and open pull requests
using credentials stored in SHADI. The agent is designed to run locally inside
SHADI sandbox constraints.

## Scope
- Repo allowlist only (no org-wide access).
- Security signals: Dependabot alerts (open).
- Actions: report, triage, plan; optional PR creation for safe upgrades.
- Human-in-the-loop: required before merge.

## Inputs
- SHADI secrets
  - GitHub token: `secops/github_token`
  - Workspace dir: `secops/workspace_dir`
  - LLM provider: `secops/llm/provider` (prefer `openai`)
  - LLM keys under `secops/llm/`:
    - OpenAI (also used for Google proxy): `openai_api_key`, `openai_endpoint`, `openai_model`
    - Google (proxy-native): `google_api_key`, `google_endpoint`, `google_model`
    - Anthropic (proxy-native): `claude_api_key`, `claude_endpoint`, `claude_model`
    - OpenAI/Azure: `azure_openai_api_key`, `azure_openai_endpoint`, `azure_openai_deployment_name`, `azure_openai_api_version`
- Config: secops.toml
  - `secops.allowlist`
  - `github.api_base`
  - SLIM A2A:
    - `secops.slim_identity`
    - `secops.slim_endpoint`
    - `secops.slim_shared_secret_key`
    - `secops.slim_local_did_key`
    - `secops.slim_remote_did_key`
    - `secops.slim_tls_insecure`
- Environment
  - `SHADI_OPERATOR_PRESENTATION` (required)
  - `SHADI_HUMAN_GITHUB` (required for remediation PRs)
  - Human DID stored in SHADI at `github/<handle>/did`

## Outputs
- `secops_security_report.md` in the workspace directory.
- Optional remediation PRs (if enabled), including Docker base image updates and `uv.lock` bumps when Dependabot provides patched versions.
- Optional remediation issue per repo (when PRs are created).
- Optional human DID metadata added to the report.
- Optional SLIM A2A interface for human-in-the-loop commands.

## Preconditions
- SHADI Python extension installed in the runtime environment.
- GitHub token has minimal required scopes for the allowlisted repos.
- Operator presentation is set in `SHADI_OPERATOR_PRESENTATION`.

## Permissions
- GitHub API: read Dependabot alerts.
- GitHub repo access: read contents, create issues, create PRs (when enabled).
- Fork access: create and update forks under `SHADI_HUMAN_GITHUB`.
- `gh` CLI installed for PR/issue creation; uses `GH_TOKEN` from SHADI (no interactive login required).

## Safety & Policy
- Never operate on repos outside the allowlist.
- Do not merge PRs automatically.
- No secrets should be written to disk.
- All actions must be logged in the workspace report.

## Workflow
1. Load config and SHADI secrets.
2. Fetch open Dependabot alerts for each allowlisted repo.
3. Write report Markdown in the workspace, including remediation plans per repo.
4. (Optional) Resolve human DID from `github/<handle>/did` using `SHADI_HUMAN_GITHUB` and attach it to the report.
5. (Optional) For critical alerts, attempt dependency updates and open PRs; if no patch is available, document the block.
6. (Optional) If PRs are created:
  - Create a remediation issue on the upstream repo.
  - Ensure a fork exists under `SHADI_HUMAN_GITHUB` and sync it with upstream.
  - Commit changes on the fork using Conventional Commits and `--signoff`.
  - Open a PR from the fork and bind it to the issue using `Fixes #<issue>`.
7. (Optional) If human approval is required, store pending PR data in `secops_pending_prs.json` for later approval.

## Long-running operation
For continuous monitoring, run the agent on a schedule and retain memory:

### Short-term memory
- Keep recent alert summaries in process memory.
- Reset on restart to avoid stale state.

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

### OpenAI proxy for Google/Claude
If your provider is behind an OpenAI-compatible proxy, set the native provider
keys (`GOOGLE_*` or `CLAUDE_*`). The SecOps loader will mirror them into
`openai_*` secrets so ADK runs through the OpenAI client. For example:

```
GOOGLE_MODEL=vertex_ai/gemini-3-pro-preview
GOOGLE_ENDPOINT=https://litellm.prod.outshift.ai
GOOGLE_API_KEY=sk-...
```

To use persistent ADK memory (Vertex AI Memory Bank), run the ADK agent with a
memory service URI:

```bash
adk run agents/secops/adk_agent --memory_service_uri "agentengine://YOUR_ENGINE_ID"
```

## Example run
```bash
export GITHUB_TOKEN="$(gh auth token)"
export SHADI_OPERATOR_PRESENTATION="local-operator"
uv run agents/secops/import_secops_secrets.py
uv run agents/secops/secops.py

# Enable automated remediation + PRs
uv run agents/secops/secops.py --remediate

# Approve pending PRs after human review
uv run agents/secops/secops.py --approve-prs
```

## SLIM A2A interface (human-in-the-loop)
Start the A2A server on a SLIM channel:

```bash
./scripts/launch_secops_a2a.sh
```

Send commands over SLIM A2A using the common secure channel. Supported commands:
- `scan`
- `remediate`
- `approve_prs`
- `report`

Each command can be a JSON payload with optional fields: `provider`, `labels`, `report_name`.

## ADK agent usage
Install ADK:

```bash
uv pip install google-adk
```

Run the agent:

```bash
adk run agents/secops/adk_agent
```

For a local-only run that uses ADK's in-memory memory service explicitly:

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

Set the database path:

```bash
export SHADI_TMP_DIR="./.tmp"
export SHADI_SECOPS_MEMORY_DB="$SHADI_TMP_DIR/${SHADI_AGENT_ID:-secops_agent}/shadi-secops/secops_memory.db"
```

Always reuse the same full path when listing or searching; using a relative
path like `secops_memory.db` will point to a different database.

Store a summary:

```bash
cargo run -p shadictl -- -- memory put --db "$SHADI_SECOPS_MEMORY_DB" \
  --key-name secops/memory_key \
  --scope secops --entry-key security_report --payload '{"status":"ok"}'
```

List memory:

```bash
cargo run -p shadictl -- -- memory list --db "$SHADI_SECOPS_MEMORY_DB" \
  --key-name secops/memory_key \
  --scope secops
```

## Example report
```markdown
## Executive summary
- No critical vulnerabilities detected across 4 repositories.
- 0 Dependabot alerts and 0 labeled security issues.

## Critical vulnerabilities
- None.

## Remediation plan
- No remediation required at this time.

## Risk notes
- Continue monitoring Dependabot alerts and security-labeled issues.
```

## Notes for ADK integration
- Use this skill as a tool in an ADK agent plan.
- Bind the allowlist and token key names from secops.toml.
- Require operator confirmation before opening PRs.
