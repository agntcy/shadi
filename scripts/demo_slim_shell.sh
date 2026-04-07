#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SHADI_TMP_DIR:="${ROOT_DIR}/.tmp"}"
: "${SLIM_ENDPOINT:="127.0.0.1:47357"}"
: "${SHADI_SLIM_CHANNEL:="agntcy/shadi/secops-room"}"
: "${SHADI_SLIM_MODERATOR_AGENT:="avatar"}"
: "${SHADI_SLIM_PARTICIPANT_AGENT:="secops-a"}"
: "${SHADI_SLIM_PARTICIPANT_NAME:="agntcy/shadi/${SHADI_SLIM_PARTICIPANT_AGENT}"}"

print_only=0
run_smoke_test=0
skip_build=0
tls_dir="${SHADI_TMP_DIR}/shadi-slim-mtls"

usage() {
    cat <<'EOF'
Usage: ./scripts/demo_slim_shell.sh [--print-only] [--smoke-test] [--skip-build]

Local helper for the native SHADI SLIM shell demo.

Modes:
  --print-only   Print the manual commands without opening Terminal windows.
  --smoke-test   Run the ignored live smoke test instead of opening shells.
  --skip-build   Skip the cargo build step before launching the demo shells.

Relevant environment:
  SHADI_TMP_DIR                    Base tmp dir that contains shadi-slim-mtls
  SLIM_ENDPOINT                    Host:port for the local SLIM node
  SHADI_SLIM_CHANNEL               Group channel name to use in the demo
  SHADI_SLIM_MODERATOR_AGENT       SHADI_AGENT_ID for the moderator shell
  SHADI_SLIM_PARTICIPANT_AGENT     SHADI_AGENT_ID for the participant shell
  SHADI_SLIM_PARTICIPANT_NAME      Canonical SLIM participant name to invite
  SHADI_SECRET_BACKEND             Optional secret backend override
  SHADI_OP_VAULT                   Optional 1Password vault override
  SHADI_OP_ACCOUNT                 Optional 1Password account override
  SHADI_OPERATOR_PRESENTATION      Optional operator presentation token
  SHADI_SLIM_SHARED_SECRET_KEY     Optional secret store key override
  SLIM_SHARED_SECRET               Optional direct shared secret override
  SLIM_TLS_CERT / SLIM_TLS_KEY     Optional direct client TLS overrides
  SLIM_TLS_CA                      Optional direct CA override
EOF
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required command not found: ${cmd}" >&2
        exit 1
    fi
}

require_file() {
    local path="$1"
    local label="$2"
    if [[ ! -f "$path" ]]; then
        echo "error: ${label} not found at ${path}" >&2
        exit 1
    fi
}

quote_shell() {
    printf '%q' "$1"
}

apple_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

build_common_exports() {
    local result=""
    local value=""

    result+="export SHADI_TMP_DIR=$(quote_shell "$SHADI_TMP_DIR"); "
    result+="export SLIM_ENDPOINT=$(quote_shell "$SLIM_ENDPOINT"); "

    for name in \
        SHADI_SECRET_BACKEND \
        SHADI_OP_VAULT \
        SHADI_OP_ACCOUNT \
        OP_SERVICE_ACCOUNT_TOKEN \
        SHADI_OPERATOR_PRESENTATION \
        SHADI_SLIM_SHARED_SECRET_KEY \
        SHADI_SLIM_LOCAL_NAME \
        SLIM_SHARED_SECRET \
        SLIM_TLS_CERT \
        SLIM_TLS_KEY \
        SLIM_TLS_CA; do
        value="${!name-}"
        if [[ -n "$value" ]]; then
            result+="export ${name}=$(quote_shell "$value"); "
        fi
    done

    printf '%s' "$result"
}

client_identity_available() {
    local agent_id="$1"
    if [[ -f "${tls_dir}/client-${agent_id}.crt" && -f "${tls_dir}/client-${agent_id}.key" ]]; then
        return 0
    fi
    if [[ -f "${tls_dir}/client.crt" && -f "${tls_dir}/client.key" ]]; then
        return 0
    fi
    return 1
}

check_demo_prereqs() {
    require_cmd cargo
    require_file "${tls_dir}/server.crt" "SLIM server certificate"
    require_file "${tls_dir}/server.key" "SLIM server key"
    require_file "${tls_dir}/ca.crt" "SLIM CA certificate"

    if ! client_identity_available "$SHADI_SLIM_MODERATOR_AGENT"; then
        echo "error: no client TLS material found for moderator agent ${SHADI_SLIM_MODERATOR_AGENT} under ${tls_dir}" >&2
        exit 1
    fi

    if ! client_identity_available "$SHADI_SLIM_PARTICIPANT_AGENT"; then
        echo "error: no client TLS material found for participant agent ${SHADI_SLIM_PARTICIPANT_AGENT} under ${tls_dir}" >&2
        exit 1
    fi
}

build_shell_command() {
    local role="$1"
    local agent_id="$2"
    local command=""

    command+="cd $(quote_shell "$ROOT_DIR") && "
    command+="$(build_common_exports)"
    command+="export SHADI_AGENT_ID=$(quote_shell "$agent_id"); "
    command+="printf '%s\\n' "
    command+="$(quote_shell "${role} shell") '' 'Run these commands:' "

    if [[ "$role" == "Moderator" ]]; then
        command+="$(quote_shell '  /slim start node') "
        command+="$(quote_shell "  /slim create ${SHADI_SLIM_CHANNEL}") "
        command+="$(quote_shell "  /slim invite ${SHADI_SLIM_PARTICIPANT_NAME}") "
    else
        command+="$(quote_shell "  /slim join ${SHADI_SLIM_CHANNEL} --timeout 60") "
    fi

    command+="'' 'Status check:' $(quote_shell '  /slim status') '' ; "
    command+="cargo run -p agntcy-shadi-cli -- shell"
    printf '%s' "$command"
}

print_manual_steps() {
    cat <<EOF
Native SLIM shell demo

Repository: ${ROOT_DIR}
Endpoint:   ${SLIM_ENDPOINT}
Channel:    ${SHADI_SLIM_CHANNEL}

Moderator shell:
  cd $(quote_shell "$ROOT_DIR")
    env SHADI_TMP_DIR=$(quote_shell "$SHADI_TMP_DIR") SLIM_ENDPOINT=$(quote_shell "$SLIM_ENDPOINT") SHADI_AGENT_ID=$(quote_shell "$SHADI_SLIM_MODERATOR_AGENT") cargo run -p agntcy-shadi-cli -- shell

Participant shell:
  cd $(quote_shell "$ROOT_DIR")
    env SHADI_TMP_DIR=$(quote_shell "$SHADI_TMP_DIR") SLIM_ENDPOINT=$(quote_shell "$SLIM_ENDPOINT") SHADI_AGENT_ID=$(quote_shell "$SHADI_SLIM_PARTICIPANT_AGENT") cargo run -p agntcy-shadi-cli -- shell

Run order:
  1. Moderator:   /slim start node
  2. Participant: /slim join ${SHADI_SLIM_CHANNEL} --timeout 60
  3. Moderator:   /slim create ${SHADI_SLIM_CHANNEL}
  4. Moderator:   /slim invite ${SHADI_SLIM_PARTICIPANT_NAME}
  5. Both:        /slim status

Smoke test alternative:
    cargo test -p agntcy-shadi-cli live_group_session_flow_works_with_local_assets -- --ignored --nocapture --test-threads=1
EOF
}

launch_terminal_window() {
    local command="$1"
    local escaped

    escaped="$(apple_escape "$command")"
    /usr/bin/osascript <<EOF
tell application "Terminal"
    activate
    do script "$escaped"
end tell
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --print-only)
            print_only=1
            ;;
        --smoke-test)
            run_smoke_test=1
            ;;
        --skip-build)
            skip_build=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

check_demo_prereqs

if [[ "$run_smoke_test" -eq 1 ]]; then
    cd "$ROOT_DIR"
    exec cargo test -p agntcy-shadi-cli live_group_session_flow_works_with_local_assets -- --ignored --nocapture --test-threads=1
fi

if [[ "$skip_build" -eq 0 ]]; then
    cd "$ROOT_DIR"
    cargo build -p agntcy-shadi-cli
fi

print_manual_steps

if [[ "$print_only" -eq 1 ]]; then
    exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo
    echo "Auto-launch is only implemented for macOS Terminal.app. Use the commands above." >&2
    exit 0
fi

require_cmd osascript

launch_terminal_window "$(build_shell_command Moderator "$SHADI_SLIM_MODERATOR_AGENT")"
sleep 1
launch_terminal_window "$(build_shell_command Participant "$SHADI_SLIM_PARTICIPANT_AGENT")"

echo
echo "Opened demo shells in Terminal.app. Follow the run order printed above."