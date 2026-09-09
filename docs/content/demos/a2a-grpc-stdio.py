#!/usr/bin/env python3
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
"""Scripted agentbridge profile binary for the A2A gRPC demo.

Used as `bin` in AGENTBRIDGE_PROFILES_DIR copilot/codex JSON so the collab
loop can run without paid coding CLIs. One hop applies at most one stub
(the two-line cap still lives in collab-apply.py).

  python3 a2a-grpc-stdio.py --prompt "..."
  python3 a2a-grpc-stdio.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys

NUMBERED = re.compile(r"^\s*(\d+)\|\s?(.*)$")
YOU_ARE = re.compile(r"^You are (\S+) on hop", re.MULTILINE)
PEERS = re.compile(r"^Peers:\s*(.+)\.\s*$", re.MULTILINE)


def numbered_src(prompt: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    capturing = False
    for raw in prompt.splitlines():
        if raw.startswith("Current src/lib.rs:"):
            capturing = True
            continue
        if capturing:
            if raw.startswith("Last cargo test:") or raw.startswith("Last peer"):
                break
            match = NUMBERED.match(raw)
            if match:
                lines.append((int(match.group(1)), match.group(2)))
    return lines


def indent_of(text: str) -> str:
    return text[: len(text) - len(text.lstrip())]


def next_peer(prompt: str) -> str:
    self_id = "copilot"
    match = YOU_ARE.search(prompt)
    if match:
        self_id = match.group(1)
    peers = ["codex"] if self_id == "copilot" else ["copilot"]
    listed = PEERS.search(prompt)
    if listed:
        peers = [p.strip() for p in listed.group(1).split(",") if p.strip()]
    for peer in peers:
        if peer != self_id:
            return peer
    return "codex" if self_id == "copilot" else "copilot"


def fifo_turn(prompt: str) -> str | None:
    src = numbered_src(prompt)
    if not src:
        return None
    peer = next_peer(prompt)
    for n, text in src:
        if "pub fn push(&mut self, _item: T) {}" in text:
            pad = indent_of(text)
            return (
                f"REPLACE {n}\n"
                f"{pad}pub fn push(&mut self, item: T) {{ self.items.push(item); }}\n"
                f"NEXT {peer}"
            )
    for i, (n, text) in enumerate(src):
        if "pub fn pop(&mut self)" not in text:
            continue
        for n2, body in src[i + 1 :]:
            if body.strip() == "None":
                pad = indent_of(body)
                return (
                    f"REPLACE {n2}\n"
                    f"{pad}self.items.drain(0..self.items.len().min(1)).next()\n"
                    f"NEXT {peer}"
                )
            if body.strip() and not body.strip().startswith("}"):
                break
    for i, (n, text) in enumerate(src):
        if "pub fn len(&self)" not in text:
            continue
        for n2, body in src[i + 1 :]:
            if body.strip() == "0":
                pad = indent_of(body)
                return (
                    f"REPLACE {n2}\n"
                    f"{pad}self.items.len()\n"
                    f"NEXT {peer}"
                )
            if body.strip() and not body.strip().startswith("}"):
                break
    for i, (n, text) in enumerate(src):
        if "pub fn is_empty(&self)" not in text:
            continue
        for n2, body in src[i + 1 :]:
            if body.strip() == "false":
                pad = indent_of(body)
                return (
                    f"REPLACE {n2}\n"
                    f"{pad}self.items.is_empty()\n"
                    f"DONE"
                )
            if body.strip() and not body.strip().startswith("}"):
                break
    return "DONE"


def handle(prompt: str) -> str:
    if prompt.startswith("HANDOFF from") or "Do not write Rust." in prompt:
        return "stored handoff (scripted)"
    if "PING" in prompt and "Current src/lib.rs:" not in prompt:
        return "PONG"
    fifo = fifo_turn(prompt)
    if fifo is not None:
        return fifo
    return "PONG" if "PING" in prompt else "ok"


def self_test() -> None:
    ping = handle("please PING the listener")
    assert ping == "PONG", ping
    src = """You are copilot on hop 1
Peers: copilot, codex.
GOAL: fifo
Current src/lib.rs:
 11|     pub fn push(&mut self, _item: T) {}
 14|         None
Last cargo test:
failed
"""
    first = handle(src)
    assert "REPLACE 11" in first, first
    assert "self.items.push" in first, first
    assert "NEXT codex" in first, first
    pop_src = """You are codex on hop 2
Peers: copilot, codex.
Current src/lib.rs:
 13|     pub fn pop(&mut self) -> Option<T> {
 14|         None
 15|     }
Last cargo test:
failed
"""
    second = handle(pop_src)
    assert "REPLACE 14" in second, second
    assert "drain(0.." in second, second
    assert "NEXT copilot" in second, second
    empty_src = """You are copilot on hop 4
Peers: copilot, codex.
Current src/lib.rs:
 21|     pub fn is_empty(&self) -> bool {
 22|         false
 23|     }
Last cargo test:
failed
"""
    last = handle(empty_src)
    assert "is_empty()" in last, last
    assert last.strip().endswith("DONE"), last
    print("a2a-grpc-stdio.py self-test ok", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt", default="")
    parser.add_argument("--self-test", action="store_true")
    args, _unknown = parser.parse_known_args()
    if args.self_test:
        self_test()
        return 0
    sys.stdout.write(handle(args.prompt))
    if not args.prompt.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
