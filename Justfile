set shell := ["zsh", "-uc"]
set windows-shell := ["pwsh", "-NoLogo", "-Command"]

python_prefix := if os() == "windows" { "" } else { `brew --prefix python@3.12` }
python312 := if os() == "windows" { if env_var_or_default("PYO3_PYTHON", "") != "" { env_var("PYO3_PYTHON") } else { `uv python find 3.12` } } else { python_prefix + "/bin/python3.12" }
PROVIDER := "google"
TIMEOUT := "60"
REMEDIATE := "false"

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
  mkdir -p coverage
  LLVM_SYSROOT="$(rustc --print sysroot)" \
  LLVM_HOST="$(rustc -Vv | awk '/host/ {print $2}')" \
  LLVM_BREW="$(brew --prefix llvm 2>/dev/null || true)" \
  LLVM_BREW_VERSIONED="$(brew --prefix llvm@21 2>/dev/null || true)" \
  LLVM_COV="$(command -v llvm-cov || true)" \
  LLVM_PROFDATA="$(command -v llvm-profdata || true)"; \
  if [ -z "$LLVM_COV" ]; then \
    if [ -x "$LLVM_BREW/bin/llvm-cov" ]; then LLVM_COV="$LLVM_BREW/bin/llvm-cov"; \
    elif [ -x "$LLVM_BREW_VERSIONED/bin/llvm-cov" ]; then LLVM_COV="$LLVM_BREW_VERSIONED/bin/llvm-cov"; \
    else LLVM_COV="$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-cov"; fi; \
  fi; \
  if [ -z "$LLVM_PROFDATA" ]; then \
    if [ -x "$LLVM_BREW/bin/llvm-profdata" ]; then LLVM_PROFDATA="$LLVM_BREW/bin/llvm-profdata"; \
    elif [ -x "$LLVM_BREW_VERSIONED/bin/llvm-profdata" ]; then LLVM_PROFDATA="$LLVM_BREW_VERSIONED/bin/llvm-profdata"; \
    else LLVM_PROFDATA="$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-profdata"; fi; \
  fi; \
  SHADI_KEYCHAIN_TESTS=1 \
  PYO3_PYTHON="{{python312}}" RUSTFLAGS="-C link-arg=-L{{python_prefix}}/Frameworks/Python.framework/Versions/3.12/lib/python3.12/config-3.12-darwin -C link-arg=-lpython3.12 -C link-arg=-framework -C link-arg=CoreFoundation" \
  LLVM_COV="$LLVM_COV" LLVM_PROFDATA="$LLVM_PROFDATA" \
  cargo llvm-cov --workspace --features coverage --lcov --output-path coverage/lcov.info --ignore-filename-regex "/rustc-[^/]+/"

coverage-html:
  mkdir -p coverage
  LLVM_SYSROOT="$(rustc --print sysroot)" \
  LLVM_HOST="$(rustc -Vv | awk '/host/ {print $2}')" \
  LLVM_BREW="$(brew --prefix llvm 2>/dev/null || true)" \
  LLVM_BREW_VERSIONED="$(brew --prefix llvm@21 2>/dev/null || true)" \
  LLVM_COV="$(command -v llvm-cov || true)" \
  LLVM_PROFDATA="$(command -v llvm-profdata || true)"; \
  if [ -z "$LLVM_COV" ]; then \
    if [ -x "$LLVM_BREW/bin/llvm-cov" ]; then LLVM_COV="$LLVM_BREW/bin/llvm-cov"; \
    elif [ -x "$LLVM_BREW_VERSIONED/bin/llvm-cov" ]; then LLVM_COV="$LLVM_BREW_VERSIONED/bin/llvm-cov"; \
    else LLVM_COV="$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-cov"; fi; \
  fi; \
  if [ -z "$LLVM_PROFDATA" ]; then \
    if [ -x "$LLVM_BREW/bin/llvm-profdata" ]; then LLVM_PROFDATA="$LLVM_BREW/bin/llvm-profdata"; \
    elif [ -x "$LLVM_BREW_VERSIONED/bin/llvm-profdata" ]; then LLVM_PROFDATA="$LLVM_BREW_VERSIONED/bin/llvm-profdata"; \
    else LLVM_PROFDATA="$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-profdata"; fi; \
  fi; \
  SHADI_KEYCHAIN_TESTS=1 \
  PYO3_PYTHON="{{python312}}" RUSTFLAGS="-C link-arg=-L{{python_prefix}}/Frameworks/Python.framework/Versions/3.12/lib/python3.12/config-3.12-darwin -C link-arg=-lpython3.12 -C link-arg=-framework -C link-arg=CoreFoundation" \
  LLVM_COV="$LLVM_COV" LLVM_PROFDATA="$LLVM_PROFDATA" \
  cargo llvm-cov --workspace --features coverage --html --output-dir coverage/html --ignore-filename-regex "/rustc-[^/]+/"

shadi:
  cargo run -p shadi_cli --

demo:
  cargo run -p shadi_cli -- \
    --allow . \
    --read / \
    --net-block \
    --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
    -- \
    ./.venv-py312/bin/python agents/secops/secops.py

demo-policy:
  cargo run -p shadi_cli -- \
    --policy policies/demo/secops-a.json \
    --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
    -- \
    ./.venv-py312/bin/python agents/secops/secops.py

demo-steps:
  SHADI_POLICY_PATH=policies/demo/secops-a.json ./.venv-py312/bin/python agents/secops/secops.py

secops-import:
  source ~/.env-phoenix && export SHADI_OPERATOR_PRESENTATION="local-operator" && \
  uv run --no-project --python .venv/bin/python agents/secops/import_secops_secrets.py

secops-run:
  SHADI_LLM_TIMEOUT={{ replace(TIMEOUT, "TIMEOUT=", "") }} \
  uv run --no-project --python .venv/bin/python agents/secops/secops.py \
    --provider {{ replace(PROVIDER, "PROVIDER=", "") }} \
    {{ if replace(REMEDIATE, "REMEDIATE=", "") == "true" { "--remediate" } else { "" } }}

secops-approve-prs:
  uv run --no-project --python .venv/bin/python agents/secops/secops.py --approve-prs

secops-test-python:
  uv run --with pytest pytest agents/secops/tests/test_skills.py

secops-skill-scan:
  rm -rf .tmp/skill-scanner/secops
  uv run --no-project --python .venv/bin/python tools/prepare_skill_scan.py --source agents/secops --dest .tmp/skill-scanner/secops
  uvx --from cisco-ai-skill-scanner skill-scanner scan .tmp/skill-scanner/secops --format summary --format markdown --detailed --output-markdown .tmp/skill-scanner/secops-scan.md

secops-a2a:
  uv run --no-project --python .venv/bin/python agents/secops/a2a_server.py

shadi-prompt:
  uv run --no-project --python .venv/bin/python tools/shadi_prompt.py

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
  AGENTIC_APPS_PATH={{env_var_or_default("AGENTIC_APPS_PATH", "")}} \
  TOURIST_CMD={{env_var_or_default("TOURIST_CMD", "")}} \
  SHADI_POLICY_PATH=policies/demo/tourist.json \
  ./.venv-py312/bin/python agents/adk_demo/run_tourist_demo.py

windows-integration:
  SHADI_WINDOWS_INTEGRATION=1 cargo test -p shadi_sandbox

docs-build:
  mkdocs build

docs-serve:
  mkdocs serve

launch-slim:
  ./scripts/launch_slim.sh

launch-slim-example:
  SHADI_TMP_DIR="./.tmp" ./scripts/launch_slim.sh

launch-secops-a2a:
  ./scripts/launch_secops_a2a.sh

launch-secops-a2a-example:
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/import_secops_secrets.sh
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/launch_secops_a2a.sh

launch-secops-a2a-example-op:
  SHADI_SECRET_BACKEND=onepassword SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/import_secops_secrets.sh
  SHADI_SECRET_BACKEND=onepassword SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/launch_secops_a2a.sh

launch-avatar:
  ./scripts/launch_avatar.sh

launch-avatar-example:
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="avatar-1" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/launch_avatar.sh

launch-avatar-example-op:
  SHADI_SECRET_BACKEND=onepassword SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="avatar-1" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/launch_avatar.sh

import-secops-secrets:
  ./scripts/import_secops_secrets.sh

import-secops-secrets-op:
  SHADI_SECRET_BACKEND=onepassword ./scripts/import_secops_secrets.sh

# ── Demo orchestration ────────────────────────────────────────────────────────
# Stop all demo processes (SLIM + SecOps A2A + Avatar).
demo-stop:
  -kill $(cat .tmp/slim.pid 2>/dev/null) 2>/dev/null; rm -f .tmp/slim.pid
  -kill $(cat .tmp/secops-a2a.pid 2>/dev/null) 2>/dev/null; rm -f .tmp/secops-a2a.pid
  -pkill -f "run_sandboxed_agent\.py|a2a_server\.py|run_shadi_memory\.py" 2>/dev/null || true
  -pkill -f slimctl 2>/dev/null || true
  @echo "Demo stopped."

# Start SLIM + SecOps A2A in the background and write PIDs to .tmp/.
# Use SHADI_HUMAN_GITHUB=<handle> to enable PR creation via gh CLI.
demo-start: demo-stop
  mkdir -p .tmp
  slimctl slim start --config ".tmp/shadi-slim-mtls/server-config.yaml" >.tmp/slim.log 2>&1 & echo $! >.tmp/slim.pid
  sleep 2
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" \
    ./scripts/launch_secops_a2a.sh >.tmp/secops-a2a.log 2>&1 & echo $! >.tmp/secops-a2a.pid
  @echo "Demo started. Tail logs: just demo-logs"
  @echo "Launch interactive avatar: just demo-avatar"

# Same as demo-start but uses 1Password as the secret backend.
demo-start-op: demo-stop
  @OP_ACCOUNT="${SHADI_OP_ACCOUNT:-my.1password.com}"; \
    op vault list --account "$OP_ACCOUNT" >/dev/null 2>&1 || \
    { echo "ERROR: 1Password not unlocked for $OP_ACCOUNT. Open the 1Password app and authenticate (Touch ID) first."; exit 1; }
  mkdir -p .tmp
  slimctl slim start --config ".tmp/shadi-slim-mtls/server-config.yaml" >.tmp/slim.log 2>&1 & echo $! >.tmp/slim.pid
  sleep 2
  SHADI_SECRET_BACKEND=onepassword SHADI_OP_ACCOUNT="${SHADI_OP_ACCOUNT:-my.1password.com}" \
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" \
  SHADI_OTEL_CONSOLE="${SHADI_OTEL_CONSOLE:-}" \
  OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-}" \
  OTEL_SERVICE_NAME="${OTEL_SERVICE_NAME:-}" \
    ./scripts/launch_secops_a2a.sh >.tmp/secops-a2a.log 2>&1 & echo $! >.tmp/secops-a2a.pid
  @echo "Demo started (1Password). Tail logs: just demo-logs"
  @echo "Launch interactive avatar: just demo-avatar-op"

# Launch the interactive Avatar agent (foreground REPL).
demo-avatar:
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="avatar-1" SHADI_OPERATOR_PRESENTATION="local-operator" \
    ./scripts/launch_avatar.sh

# Same as demo-avatar but uses 1Password as the secret backend.
demo-avatar-op:
  @OP_ACCOUNT="${SHADI_OP_ACCOUNT:-my.1password.com}"; \
    op vault list --account "$OP_ACCOUNT" >/dev/null 2>&1 || \
    { echo "ERROR: 1Password not unlocked for $OP_ACCOUNT. Open the 1Password app and authenticate (Touch ID) first."; exit 1; }
  SHADI_SECRET_BACKEND=onepassword SHADI_OP_ACCOUNT="${SHADI_OP_ACCOUNT:-my.1password.com}" \
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="avatar-1" SHADI_OPERATOR_PRESENTATION="local-operator" \
    ./scripts/launch_avatar.sh

# Tail background demo logs (SLIM + SecOps A2A).
demo-logs:
  tail -f .tmp/slim.log .tmp/secops-a2a.log

secure-profile-strict:
  cargo run -p shadictl -- --profile strict --print-policy

secure-profile-balanced:
  cargo run -p shadictl -- --profile balanced --print-policy

secure-profile-connected:
  cargo run -p shadictl -- --profile connected --print-policy
