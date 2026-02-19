set shell := ["zsh", "-uc"]

python_prefix := `brew --prefix python@3.12`
python312 := python_prefix + "/bin/python3.12"
PROVIDER := "google"
TIMEOUT := "60"
REMEDIATE := "false"

build:
  PYO3_PYTHON="{{python312}}" RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup" cargo build

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
  LLVM_COV="$(command -v llvm-cov || true)" \
  LLVM_PROFDATA="$(command -v llvm-profdata || true)" \
  LLVM_COV="${LLVM_COV:-$LLVM_BREW/bin/llvm-cov}" \
  LLVM_PROFDATA="${LLVM_PROFDATA:-$LLVM_BREW/bin/llvm-profdata}" \
  LLVM_COV="${LLVM_COV:-$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-cov}" \
  LLVM_PROFDATA="${LLVM_PROFDATA:-$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-profdata}" \
  SHADI_KEYCHAIN_TESTS=1 \
  PYO3_PYTHON="{{python312}}" RUSTFLAGS="-C link-arg=-L{{python_prefix}}/Frameworks/Python.framework/Versions/3.12/lib/python3.12/config-3.12-darwin -C link-arg=-lpython3.12 -C link-arg=-framework -C link-arg=CoreFoundation" \
  LLVM_COV="$LLVM_COV" LLVM_PROFDATA="$LLVM_PROFDATA" \
  cargo llvm-cov --workspace --features coverage --lcov --output-path coverage/lcov.info --ignore-filename-regex "/rustc-[^/]+/"

coverage-html:
  mkdir -p coverage
  LLVM_SYSROOT="$(rustc --print sysroot)" \
  LLVM_HOST="$(rustc -Vv | awk '/host/ {print $2}')" \
  LLVM_BREW="$(brew --prefix llvm 2>/dev/null || true)" \
  LLVM_COV="$(command -v llvm-cov || true)" \
  LLVM_PROFDATA="$(command -v llvm-profdata || true)" \
  LLVM_COV="${LLVM_COV:-$LLVM_BREW/bin/llvm-cov}" \
  LLVM_PROFDATA="${LLVM_PROFDATA:-$LLVM_BREW/bin/llvm-profdata}" \
  LLVM_COV="${LLVM_COV:-$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-cov}" \
  LLVM_PROFDATA="${LLVM_PROFDATA:-$LLVM_SYSROOT/lib/rustlib/$LLVM_HOST/bin/llvm-profdata}" \
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
  SHADI_TMP_DIR="./.tmp" SLIM_ENDPOINT="127.0.0.1:47357" ./scripts/launch_slim.sh

launch-secops-a2a:
  ./scripts/launch_secops_a2a.sh

launch-secops-a2a-example:
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/import_secops_secrets.sh
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="secops-a" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/launch_secops_a2a.sh

launch-avatar:
  ./scripts/launch_avatar.sh

launch-avatar-example:
  SHADI_TMP_DIR="./.tmp" SHADI_AGENT_ID="avatar-1" SHADI_OPERATOR_PRESENTATION="local-operator" ./scripts/launch_avatar.sh

import-secops-secrets:
  ./scripts/import_secops_secrets.sh
