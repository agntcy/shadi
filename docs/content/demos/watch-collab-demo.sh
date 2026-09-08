#!/usr/bin/env bash
# Tail live progress for a run-collab-demo.sh in progress.
#
# Usage:  bash docs/content/demos/watch-collab-demo.sh
set -uo pipefail

DIR="$(ls -dt /tmp/shadi-collab-demo.*/logs 2>/dev/null | head -1)"
if [ -z "$DIR" ]; then
  echo "No run-collab-demo.sh run found yet — start one with 'bash docs/content/demos/run-collab-demo.sh' first." >&2
  exit 1
fi

AGENTS=(claude-code copilot codex cursor-agent goose)
FILES=("$DIR/node.log" "$DIR/list-local.log" "$DIR/lru-turns.log" "$DIR/fifo-turns.log")
for a in "${AGENTS[@]}"; do FILES+=("$DIR/$a-agent.log"); done

echo "Watching: $DIR (Ctrl-C to stop watching; does not affect the running demo)"
echo
tail -n +1 -F "${FILES[@]}" 2>/dev/null
