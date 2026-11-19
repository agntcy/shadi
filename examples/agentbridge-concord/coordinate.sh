#!/usr/bin/env bash
# Opens the run and prints the report. Extra arguments go to
# `agentbridge coordinate`.
#
# The initiator is a Claude too: it reads the task and writes the anchors, the
# threshold and the shape of a candidate. An option given here
# (--reject, --ideal, --schema, --threshold) is used as it is and not written
# by the model.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" && -z "${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  echo "Set ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN first." >&2
  exit 1
fi
mkdir -p .run
GOAL="We are adding a new notification-delivery capability to the product (a notification service): users can opt in to email / push / SMS notifications for events raised across several existing subsystems. Your team must develop it, and the team needs one decision on how to build it that everyone can live with."

export AGENTBRIDGE_PROFILES_DIR="$CONCORD_EXAMPLE/profiles"
export CLAUDE_CONFIG_DIR="$CONCORD_EXAMPLE/.run/claude-config/coordinator"
mkdir -p "$CLAUDE_CONFIG_DIR"
export SHADI_AGENT_ID=coordinator
cd agents/coordinator
exec "$SHADICTL" \
  --allow . --allow "$CONCORD_EXAMPLE/.run" \
  --read "$CONCORD_EXAMPLE/.tmp" --read "$AGENTBRIDGE_PROFILES_DIR" --read "$CONCORD_EXAMPLE/bin" \
  --allow /tmp --allow /private/tmp \
  --net-block --net-allow api.anthropic.com:443 --net-allow "$SLIM_ENDPOINT" -- \
  "$AGENTBRIDGE" coordinate --protocol concord --slim-endpoint "$SLIM_ENDPOINT" \
  --tool coordinator --command "$PWD" \
  --participants microservices,monolith,pragmatist \
  --report "$CONCORD_EXAMPLE/.run/report.json" \
  --goal "$GOAL" "$@"
