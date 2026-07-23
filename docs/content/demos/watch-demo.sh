#!/usr/bin/env bash
# Tail live progress/logs for a run-demo.sh in progress.
#
# Run this in a second terminal while run-demo.sh is running (see
# did-agent-group.md). It finds the most recently started demo run dir and
# tails every per-agent log, labeled by filename — including files that
# haven't been created yet (later phases), which `tail -F` picks up as soon
# as run-demo.sh creates them.
#
# Usage:  bash docs/demos/watch-demo.sh
set -uo pipefail

DIR="$(ls -dt /tmp/shadi-did-demo.*/logs 2>/dev/null | head -1)"
if [ -z "$DIR" ]; then
  echo "No run-demo.sh run found yet — start one with 'bash docs/demos/run-demo.sh' first." >&2
  exit 1
fi

AGENTS=(avatar claude-code codex copilot cursor-agent)
FILES=("$DIR/node.log")
for a in "${AGENTS[@]}"; do FILES+=("$DIR/$a.log" "$DIR/$a-collaborate.log"); done
for a in claude-code codex copilot; do FILES+=("$DIR/$a-agent.log" "$DIR/$a-delegate.log"); done

echo "Watching: $DIR (Ctrl-C to stop watching; does not affect the running demo)"
echo
tail -n +1 -F "${FILES[@]}" 2>/dev/null
