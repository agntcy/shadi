set shell := ["bash", "-uc"]
set windows-shell := ["pwsh", "-NoLogo", "-Command"]
set dotenv-load := true
set dotenv-filename := ".just.env"

python_prefix := if os() == "windows" { "" } else { `command -v brew >/dev/null 2>&1 && brew --prefix python@3.12 || true` }
python312 := if os() == "windows" { if env_var_or_default("PYO3_PYTHON", "") != "" { env_var("PYO3_PYTHON") } else { `uv python find 3.12` } } else { if python_prefix != "" { python_prefix + "/bin/python3.12" } else { "python3.12" } }
python_rustflags := if os() == "macos" { "-C link-arg=-L" + python_prefix + "/Frameworks/Python.framework/Versions/3.12/lib/python3.12/config-3.12-darwin -C link-arg=-lpython3.12 -C link-arg=-framework -C link-arg=CoreFoundation" } else { "" }
PROVIDER := env_var_or_default("PROVIDER", "google")
TIMEOUT := env_var_or_default("TIMEOUT", "60")
REMEDIATE := env_var_or_default("REMEDIATE", "false")
AGENTIC_APPS_PATH := env_var_or_default("AGENTIC_APPS_PATH", "")
TOURIST_CMD := env_var_or_default("TOURIST_CMD", "")
SHADI_OP_ACCOUNT := env_var_or_default("SHADI_OP_ACCOUNT", "my.1password.com")
venv_python := if os() == "windows" { ".venv\\Scripts\\python.exe" } else { ".venv/bin/python" }
demo_python := if os() == "windows" { ".venv-py312\\Scripts\\python.exe" } else { "./.venv-py312/bin/python" }

build:
  PYO3_PYTHON="{{python312}}" RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup" cargo build
  cp target/debug/libshadi.dylib .venv/lib/python3.12/site-packages/shadi/shadi.cpython-312-darwin.so
  codesign --sign - --force .venv/lib/python3.12/site-packages/shadi/shadi.cpython-312-darwin.so

windows-build:
  $env:PYO3_PYTHON = "{{python312}}"; cargo build

windows-test:
  $env:PYO3_PYTHON = "{{python312}}"; cargo test --workspace

test:
  PYO3_PYTHON="{{python312}}" RUSTFLAGS="-C link-arg=-L{{python_prefix}}/Frameworks/Python.framework/Versions/3.12/lib/python3.12/config-3.12-darwin -C link-arg=-lpython3.12 -C link-arg=-framework -C link-arg=CoreFoundation" cargo test

lint:
  PYO3_PYTHON="{{python312}}" RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup" cargo clippy --all-targets --all-features

clean:
  cargo clean

coverage:
  {{ if os() == "windows" {
    ".\\scripts\\run_coverage.ps1 -Mode lcov -PythonBin \"" + python312 + "\" -RustflagsValue \"" + python_rustflags + "\""
  } else {
    "SHADI_KEYCHAIN_TESTS=1 scripts/run_coverage.sh lcov \"" + python312 + "\" \"" + python_rustflags + "\""
  } }}

coverage-html:
  {{ if os() == "windows" {
    ".\\scripts\\run_coverage.ps1 -Mode html -PythonBin \"" + python312 + "\" -RustflagsValue \"" + python_rustflags + "\""
  } else {
    "SHADI_KEYCHAIN_TESTS=1 scripts/run_coverage.sh html \"" + python312 + "\" \"" + python_rustflags + "\""
  } }}

shadi:
  cargo run -p shadi_cli --

demo:
  cargo run -p shadi_cli -- \
    --allow . \
    --read / \
    --net-block \
    --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
    -- \
    {{demo_python}} agents/secops/secops.py

demo-policy:
  cargo run -p shadi_cli -- \
    --policy policies/demo/secops-a.json \
    --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
    -- \
    {{demo_python}} agents/secops/secops.py

demo-steps:
  {{ if os() == "windows" {
    "$env:SHADI_POLICY_PATH = \"policies/demo/secops-a.json\"; " + demo_python + " agents/secops/secops.py"
  } else {
    "SHADI_POLICY_PATH=policies/demo/secops-a.json " + demo_python + " agents/secops/secops.py"
  } }}

secops-import:
  {{ if os() == "windows" {
    "$env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; uv run --no-project --python " + venv_python + " agents/secops/import_secops_secrets.py"
  } else {
    "source ~/.env-phoenix && export SHADI_OPERATOR_PRESENTATION=\"local-operator\" && uv run --no-project --python " + venv_python + " agents/secops/import_secops_secrets.py"
  } }}

secops-run:
  {{ if os() == "windows" {
    "$env:SHADI_LLM_TIMEOUT = \"" + TIMEOUT + "\"; uv run --no-project --python " + venv_python + " agents/secops/secops.py --provider " + PROVIDER + if REMEDIATE == "true" { " --remediate" } else { "" }
  } else {
    "SHADI_LLM_TIMEOUT=" + TIMEOUT + " uv run --no-project --python " + venv_python + " agents/secops/secops.py --provider " + PROVIDER + if REMEDIATE == "true" { " --remediate" } else { "" }
  } }}

secops-approve-prs:
  uv run --no-project --python {{venv_python}} agents/secops/secops.py --approve-prs

secops-test-python:
  uv run --with pytest pytest agents/secops/tests/test_skills.py

secops-skill-scan:
  rm -rf .tmp/skill-scanner/secops
  uv run --no-project --python {{venv_python}} tools/prepare_skill_scan.py --source agents/secops --dest .tmp/skill-scanner/secops
  uvx --from cisco-ai-skill-scanner skill-scanner scan .tmp/skill-scanner/secops --format summary --format markdown --detailed --output-markdown .tmp/skill-scanner/secops-scan.md

secops-a2a:
  uv run --no-project --python {{venv_python}} agents/secops/a2a_server.py

shadi-prompt:
  uv run --no-project --python {{venv_python}} tools/shadi_prompt.py

secops-run-google:
  just secops-run PROVIDER="google"

secops-run-azure:
  just secops-run PROVIDER="azure"

secops-run-anthropic:
  just secops-run PROVIDER="anthropic"

secops-secrets:
  cargo run -p shadictl -- --list-keychain --list-prefix secops/

secops-secrets-op:
  SHADI_SECRET_BACKEND=onepassword cargo run -p shadictl -- --list-keychain --list-prefix secops/

secops-policy:
  cargo run -p shadictl -- --policy policies/demo/secops-a.json --print-policy

secops-memory-list:
  cargo run -p shadictl -- -- memory list \
    --db "${SHADI_SECOPS_MEMORY_DB:-${SHADI_MEMORY_DB:-${SHADI_TMP_DIR:-./.tmp}/${SHADI_AGENT_ID:-${SHADI_OPERATOR_AGENT_ID:-secops_agent}}/shadi-secops/secops_memory.db}}" \
    --key-name secops/memory_key --scope secops

secops-memory-init:
  cargo run -p shadictl -- -- memory init \
    --db "${SHADI_SECOPS_MEMORY_DB:-${SHADI_MEMORY_DB:-${SHADI_TMP_DIR:-./.tmp}/${SHADI_AGENT_ID:-${SHADI_OPERATOR_AGENT_ID:-secops_agent}}/shadi-secops/secops_memory.db}}" \
    --key-name secops/memory_key

secops-memory-get:
  cargo run -p shadictl -- -- memory get \
    --db "${SHADI_SECOPS_MEMORY_DB:-${SHADI_MEMORY_DB:-${SHADI_TMP_DIR:-./.tmp}/${SHADI_AGENT_ID:-${SHADI_OPERATOR_AGENT_ID:-secops_agent}}/shadi-secops/secops_memory.db}}" \
    --key-name secops/memory_key \
    --scope secops --entry-key security_report

demo-tourist:
  AGENTIC_APPS_PATH={{AGENTIC_APPS_PATH}} \
  TOURIST_CMD={{TOURIST_CMD}} \
  SHADI_POLICY_PATH=policies/demo/tourist.json \
  ./.venv-py312/bin/python agents/adk_demo/run_tourist_demo.py

windows-integration:
  $env:PYO3_PYTHON = "{{python312}}"; $env:SHADI_WINDOWS_INTEGRATION = "1"; cargo test --workspace

docs-build:
  mkdocs build

docs-serve:
  mkdocs serve

launch-slim:
  {{ if os() == "windows" {
    ".\\scripts\\launch_slim.ps1"
  } else {
    "./scripts/launch_slim.sh"
  } }}

launch-slim-example:
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; .\\scripts\\launch_slim.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" ./scripts/launch_slim.sh"
  } }}

launch-secops-a2a:
  {{ if os() == "windows" {
    ".\\scripts\\launch_secops_a2a.ps1"
  } else {
    "./scripts/launch_secops_a2a.sh"
  } }}

launch-secops-a2a-example:
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\import_secops_secrets.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/import_secops_secrets.sh"
  } }}
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_secops_a2a.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_secops_a2a.sh"
  } }}

launch-secops-a2a-example-op:
  {{ if os() == "windows" {
    "$env:SHADI_SECRET_BACKEND = \"onepassword\"; $env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\import_secops_secrets.ps1"
  } else {
    "SHADI_SECRET_BACKEND=onepassword SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/import_secops_secrets.sh"
  } }}
  {{ if os() == "windows" {
    "$env:SHADI_SECRET_BACKEND = \"onepassword\"; $env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_secops_a2a.ps1"
  } else {
    "SHADI_SECRET_BACKEND=onepassword SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_secops_a2a.sh"
  } }}

launch-avatar:
  {{ if os() == "windows" {
    ".\\scripts\\launch_avatar.ps1"
  } else {
    "./scripts/launch_avatar.sh"
  } }}

# Launch the interactive Avatar agent (foreground REPL).
demo-avatar:
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"avatar-1\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_avatar.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"avatar-1\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_avatar.sh"
  } }}

# Same as demo-avatar but uses 1Password as the secret backend.
demo-avatar-op:
  {{ if os() == "windows" {
    "$opAccount = \"{{SHADI_OP_ACCOUNT}}\"; op vault list --account $opAccount | Out-Null; $env:SHADI_SECRET_BACKEND = \"onepassword\"; $env:SHADI_OP_ACCOUNT = $opAccount; $env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"avatar-1\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_avatar.ps1"
  } else {
    "OP_ACCOUNT=\"{{SHADI_OP_ACCOUNT}}\"; op vault list --account \"$OP_ACCOUNT\" >/dev/null 2>&1 || { echo \"ERROR: 1Password not unlocked for $OP_ACCOUNT. Open the 1Password app and authenticate (Touch ID) first.\"; exit 1; }; SHADI_SECRET_BACKEND=onepassword SHADI_OP_ACCOUNT=\"{{SHADI_OP_ACCOUNT}}\" SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"avatar-1\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_avatar.sh"
  } }}

# Tail background demo logs (SLIM + SecOps A2A).
demo-logs:
  tail -f .tmp/slim.log .tmp/secops-a2a.log

secure-profile-strict:
  cargo run -p shadictl -- --profile strict --print-policy

secure-profile-balanced:
  cargo run -p shadictl -- --profile balanced --print-policy

secure-profile-connected:
  cargo run -p shadictl -- --profile connected --print-policy
