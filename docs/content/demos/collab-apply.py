#!/usr/bin/env python3
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
"""Apply at most two lines of Rust from an agent turn onto src/lib.rs.

The orchestrator (run-collab-demo.sh) feeds the agent's raw reply on stdin and
the current file as argv[1]. stdout is the updated file. stderr reports how
the cap was applied. A third code line is never written.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DIRECTIVE = re.compile(r"^(INSERT|REPLACE|APPEND)(?:\s+(\d+))?\s*$", re.IGNORECASE)
META = re.compile(r"^(NEXT|DONE)(?:\s+(\S+))?\s*$", re.IGNORECASE)
FENCE = re.compile(r"^```")


def is_meta(line: str) -> bool:
    return META.match(line.strip()) is not None


def parse_next(lines: list[str]) -> str:
    """Last NEXT <id> or DONE in the reply. Empty if the agent did not choose."""
    chosen = ""
    for line in lines:
        match = META.match(line.strip())
        if match is None:
            continue
        if match.group(1).upper() == "DONE":
            return "DONE"
        if match.group(2):
            chosen = match.group(2)
    return chosen


def strip_reply(text: str) -> list[str]:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # Drop the agentbridge CLI wrapper if the caller passed a full log.
    start = 0
    for i, line in enumerate(lines):
        if line.startswith("Response from "):
            start = i + 1
    lines = lines[start:]
    fenced: list[str] = []
    in_fence = False
    for line in lines:
        if FENCE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            fenced.append(line)
    if fenced:
        return fenced
    return [line for line in lines if not line.startswith("Delegating task ")]


def code_lines(lines: list[str]) -> list[str]:
    """Keep at most two non-empty lines (the hard cap)."""
    out: list[str] = []
    for line in lines:
        if line.strip() == "":
            continue
        if is_meta(line):
            continue
        if line.startswith("agentbridge error:"):
            return []
        out.append(line.rstrip("\n"))
        if len(out) == 2:
            break
    return out


def apply_directive(current: list[str], lines: list[str]) -> tuple[list[str], str]:
    match = DIRECTIVE.match(lines[0].strip())
    assert match is not None
    op = match.group(1).upper()
    raw_n = match.group(2)
    code = code_lines(lines[1:])
    if not code:
        return current, "directive with no code lines; file unchanged"
    if op == "APPEND":
        return current + code, f"APPEND {len(code)} line(s) (capped at 2)"
    n = int(raw_n or "1")
    idx = min(max(n, 1) - 1, len(current))
    if op == "INSERT":
        return current[:idx] + code + current[idx:], f"INSERT {len(code)} line(s) at {idx + 1} (capped at 2)"
    # Replace the single target line with 1–2 lines. Do not eat the next
    # line (that deleted the closing `}` when an agent expanded a stub).
    replaced = current[:idx] + code + current[idx + 1 :]
    return replaced, f"REPLACE {len(code)} line(s) at {idx + 1} (capped at 2)"


def two_line_merge(current: list[str], proposed: list[str]) -> tuple[list[str], str]:
    """Copy current, accepting at most two INSERT/REPLACE edits from proposed."""
    result: list[str] = []
    i = 0
    j = 0
    edits = 0
    while i < len(current) or j < len(proposed):
        if i < len(current) and j < len(proposed) and current[i] == proposed[j]:
            result.append(current[i])
            i += 1
            j += 1
            continue
        if edits >= 2:
            result.extend(current[i:])
            return result, "full-file reply truncated to 2 line edits"
        if i < len(current) and j < len(proposed):
            result.append(proposed[j])
            i += 1
            j += 1
            edits += 1
            continue
        if j < len(proposed):
            result.append(proposed[j])
            j += 1
            edits += 1
            continue
        result.extend(current[i:])
        break
    return result, f"full-file reply applied {edits} line edit(s) (capped at 2)"


def apply_raw(current: list[str], lines: list[str]) -> tuple[list[str], str]:
    code = code_lines(lines)
    if not code:
        return current, "empty or error reply; file unchanged"
    for i, line in enumerate(current):
        if any(marker in line for marker in ("todo!", "TODO", "unimplemented!")):
            return current[:i] + code + current[i + 1 :], f"REPLACE stub at {i + 1} with {len(code)} line(s)"
    for i, line in enumerate(current):
        if line.strip() == "items":
            return current[:i] + code + current[i + 1 :], f"REPLACE identity body at {i + 1}"
    return current + code, f"APPEND {len(code)} line(s) (capped at 2)"


def apply_turn(current_text: str, reply: str) -> tuple[str, str]:
    current = current_text.splitlines()
    lines = strip_reply(reply)
    if not lines:
        return current_text if current_text.endswith("\n") or current_text == "" else current_text + "\n", "empty reply"
    code_only = [line for line in lines if line.strip() and not is_meta(line)]
    if DIRECTIVE.match(lines[0].strip() if lines else ""):
        updated, note = apply_directive(current, lines)
    elif len(code_only) > 2:
        updated, note = two_line_merge(current, [line.rstrip("\n") for line in code_only])
    else:
        updated, note = apply_raw(current, lines)
    body = "\n".join(updated)
    if body and not body.endswith("\n"):
        body += "\n"
    return body, note


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--next":
        sys.stdout.write(parse_next(strip_reply(sys.stdin.read())))
        return 0
    if len(sys.argv) != 2:
        print("usage: collab-apply.py <current-lib.rs> | --next", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    current = path.read_text()
    reply = sys.stdin.read()
    updated, note = apply_turn(current, reply)
    sys.stderr.write(note + "\n")
    sys.stdout.write(updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
