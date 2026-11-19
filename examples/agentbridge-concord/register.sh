#!/usr/bin/env bash
# ./register.sh <agent id> <the other members, comma-separated>
#
# Starts one member of the group, under the sandbox. Extra arguments go to
# `agentbridge register` (for example --verbose).
set -euo pipefail
ID="${1:?usage: register.sh <agent id> <peer,peer,...>}"
PEERS="${2:?usage: register.sh <agent id> <peer,peer,...>}"
cd "$(dirname "$0")"
source ./env.sh

if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" && -z "${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  echo "Set ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN first." >&2
  exit 1
fi
mkdir -p .run
export AGENTBRIDGE_PROFILES_DIR="$CONCORD_EXAMPLE/profiles"
# Each agent keeps its Claude sessions in its own configuration directory.
export CLAUDE_CONFIG_DIR="$CONCORD_EXAMPLE/.run/claude-config/$ID"
mkdir -p "$CLAUDE_CONFIG_DIR"

export SHADI_AGENT_ID="$ID"
cd "agents/$ID"
exec "$SHADICTL" \
  --allow . --allow "$CONCORD_EXAMPLE/.run" \
  --read "$CONCORD_EXAMPLE/.tmp" --read "$AGENTBRIDGE_PROFILES_DIR" --read "$CONCORD_EXAMPLE/bin" \
  --allow /tmp --allow /private/tmp \
  --net-block --net-allow api.anthropic.com:443 --net-allow "$SLIM_ENDPOINT" -- \
  "$AGENTBRIDGE" register --protocol concord --tool "$ID" --command "$PWD" \
  --slim-endpoint "$SLIM_ENDPOINT" --peer-agent-ids "$PEERS" "${@:3}"
