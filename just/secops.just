[group('secops')]
[doc('Run the main SHADI CLI crate.')]
shadi:
  cargo run -p shadi_cli --

[group('secops')]
[doc('Run the sandboxed SecOps demo with inline policy flags.')]
demo:
  cargo run -p shadi_cli -- \
    --allow . \
    --read / \
    --net-block \
    --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
    -- \
    {{demo_python}} agents/secops/secops.py

[group('secops')]
[doc('Run the SecOps demo with the demo policy file.')]
demo-policy:
  cargo run -p shadi_cli -- \
    --policy policies/demo/secops-a.json \
    --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
    -- \
    {{demo_python}} agents/secops/secops.py

[group('secops')]
[doc('Run the SecOps Python entrypoint directly with the demo policy path.')]
demo-steps:
  {{ if os() == "windows" {
    "$env:SHADI_POLICY_PATH = \"policies/demo/secops-a.json\"; " + demo_python + " agents/secops/secops.py"
  } else {
    "SHADI_POLICY_PATH=policies/demo/secops-a.json " + demo_python + " agents/secops/secops.py"
  } }}

[group('secops')]
[doc('Import SecOps secrets into the configured backend for local runs.')]
secops-import:
  {{ if os() == "windows" {
    "$env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; uv run --no-project --python " + venv_python + " agents/secops/import_secops_secrets.py"
  } else {
    "source ~/.env-phoenix && export SHADI_OPERATOR_PRESENTATION=\"local-operator\" && uv run --no-project --python " + venv_python + " agents/secops/import_secops_secrets.py"
  } }}

[group('secops')]
[doc('Run the SecOps workflow with the selected LLM provider.')]
secops-run:
  {{ if os() == "windows" {
    "$env:SHADI_LLM_TIMEOUT = \"" + TIMEOUT + "\"; uv run --no-project --python " + venv_python + " agents/secops/secops.py --provider " + PROVIDER + if REMEDIATE == "true" { " --remediate" } else { "" }
  } else {
    "SHADI_LLM_TIMEOUT=" + TIMEOUT + " uv run --no-project --python " + venv_python + " agents/secops/secops.py --provider " + PROVIDER + if REMEDIATE == "true" { " --remediate" } else { "" }
  } }}

[group('secops')]
[doc('Approve PRs recorded in the SecOps pending approvals file.')]
secops-approve-prs:
  uv run --no-project --python {{venv_python}} agents/secops/secops.py --approve-prs

[group('secops')]
[doc('Run the focused Python test suite for SecOps skills.')]
secops-test-python:
  uv run --with pytest pytest agents/secops/tests/test_skills.py

[group('secops')]
[doc('Prepare and scan the SecOps skill package with the skill scanner.')]
secops-skill-scan:
  {{ if os() == "windows" {
    "if (Test-Path .tmp/skill-scanner/secops) { Remove-Item .tmp/skill-scanner/secops -Recurse -Force }"
  } else {
    "rm -rf .tmp/skill-scanner/secops"
  } }}
  uv run --no-project --python {{venv_python}} tools/prepare_skill_scan.py --source agents/secops --dest .tmp/skill-scanner/secops
  uvx --from cisco-ai-skill-scanner skill-scanner scan .tmp/skill-scanner/secops --format summary --format markdown --detailed --output-markdown .tmp/skill-scanner/secops-scan.md

[group('secops')]
[doc('Start the SecOps A2A server.')]
secops-a2a:
  uv run --no-project --python {{venv_python}} agents/secops/a2a_server.py

[group('secops')]
[doc('Run the prompt helper against the current SHADI environment.')]
shadi-prompt:
  uv run --no-project --python {{venv_python}} tools/shadi_prompt.py

[group('secops')]
[doc('Run SecOps with the Google provider preset.')]
secops-run-google:
  just secops-run PROVIDER="google"

[group('secops')]
[doc('Run SecOps with the Azure provider preset.')]
secops-run-azure:
  just secops-run PROVIDER="azure"

[group('secops')]
[doc('Run SecOps with the Anthropic provider preset.')]
secops-run-anthropic:
  just secops-run PROVIDER="anthropic"

[group('secops')]
[doc('List SecOps secrets from the configured default backend.')]
secops-secrets:
  cargo run -p shadictl -- --list-keychain --list-prefix secops/

[group('secops')]
[doc('List SecOps secrets from the 1Password backend.')]
secops-secrets-op:
  {{ if os() == "windows" {
    "$opAccount = \"" + SHADI_OP_ACCOUNT + "\"; op vault list --account $opAccount | Out-Null; if ($LASTEXITCODE -ne 0) { Write-Error \"ERROR: 1Password not unlocked for $opAccount. Open the 1Password app and authenticate, or run op signin for that account first.\"; exit 1 }; $env:SHADI_SECRET_BACKEND = \"onepassword\"; $env:SHADI_OP_ACCOUNT = $opAccount; cargo run -p shadictl -- --list-keychain --list-prefix secops/"
  } else {
    "OP_ACCOUNT=\"" + SHADI_OP_ACCOUNT + "\"; op vault list --account \"$OP_ACCOUNT\" >/dev/null 2>&1 || { echo \"ERROR: 1Password not unlocked for $OP_ACCOUNT. Open the 1Password app and authenticate, or run op signin first.\"; exit 1; }; SHADI_SECRET_BACKEND=onepassword SHADI_OP_ACCOUNT=\"" + SHADI_OP_ACCOUNT + "\" cargo run -p shadictl -- --list-keychain --list-prefix secops/"
  } }}

[group('secops')]
[doc('Print the demo SecOps policy through shadictl.')]
secops-policy:
  cargo run -p shadictl -- --policy policies/demo/secops-a.json --print-policy

[group('secops')]
[doc('List SecOps encrypted memory entries.')]
secops-memory-list:
  cargo run -p shadictl -- -- memory list --db "{{secops_memory_db}}" --key-name secops/memory_key --scope secops

[group('secops')]
[doc('Initialize the SecOps encrypted memory database.')]
secops-memory-init:
  cargo run -p shadictl -- -- memory init --db "{{secops_memory_db}}" --key-name secops/memory_key

[group('secops')]
[doc('Fetch the latest saved SecOps security report from memory.')]
secops-memory-get:
  cargo run -p shadictl -- -- memory get --db "{{secops_memory_db}}" --key-name secops/memory_key --scope secops --entry-key security_report