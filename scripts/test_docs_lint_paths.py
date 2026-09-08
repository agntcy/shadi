#!/usr/bin/env python3
"""Check that Docs lint path filters match GitHub Actions glob rules."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "docs-lint.yml"

# GitHub cheat-sheet cases: (pattern, path, should_match)
CHEAT_SHEET = [
    ("docs/**", "docs/README.md", True),
    ("docs/**", "docs/mona/octocat.txt", True),
    ("docs/**", "README.md", False),
    ("docs/**/*.md", "docs/README.md", True),
    ("docs/**/*.md", "docs/mona/hello-world.md", True),
    ("docs/**/*.md", "README.md", False),
    ("**/README.md", "README.md", True),
    ("**/README.md", "js/README.md", True),
    ("**/*-post.md", "my-post.md", True),
    ("**/*-post.md", "path/their-post.md", True),
    ("*.md", "README.md", True),
    ("*.md", "docs/README.md", False),
]

SHOULD_TRIGGER = [
    ["docs/content/cli.md"],
    ["docs/mkdocs/mkdocs.yml"],
    ["docs/content/stylesheets/custom.css"],
    ["README.md"],
    ["CONTRIBUTING.md"],
    ["crates/shadictl/README.md"],
    ["typos.toml"],
    [".markdownlint-cli2.jsonc"],
    ["lychee.toml"],
    ["just/core.just"],
    ["Justfile"],
    [".github/workflows/docs-lint.yml"],
    ["Cargo.toml", "docs/content/cli.md"],
]

SHOULD_SKIP = [
    ["crates/shadictl/src/main.rs"],
    ["Cargo.toml"],
    ["Cargo.lock"],
    ["apps/shadi_desktop/src/App.tsx"],
    [".github/workflows/ci.yml"],
    ["just/vars.just"],
    ["Formula/shadictl.rb"],
    ["scripts/test_install_shadictl.sh"],
]


def github_glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate GitHub Actions path-filter globs to a regex.

    ``*`` matches inside one path segment. ``**`` matches across segments.
    See the workflow syntax filter-pattern cheat sheet.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def matches(path: str, pattern: str) -> bool:
    return github_glob_to_regex(pattern).fullmatch(path) is not None


def would_run(changed: list[str], patterns: list[str]) -> bool:
    return any(matches(path, pattern) for path in changed for pattern in patterns)


def parse_event_paths(text: str, event: str) -> list[str]:
    lines = text.splitlines()
    in_event = False
    in_paths = False
    event_indent: int | None = None
    paths: list[str] = []
    for line in lines:
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if re.match(rf"{event}:\s*$", stripped):
            in_event = True
            event_indent = indent
            in_paths = False
            continue
        if in_event and event_indent is not None:
            if stripped and indent <= event_indent and not stripped.startswith("#"):
                break
            if stripped == "paths:":
                in_paths = True
                continue
            if in_paths:
                if stripped.startswith("- "):
                    value = stripped[2:].strip().strip('"').strip("'")
                    paths.append(value)
                    continue
                if stripped == "" or stripped.startswith("#"):
                    continue
                break
    if not paths:
        raise SystemExit(f"no paths: list found under {event}: in {WORKFLOW}")
    return paths


def main() -> int:
    text = WORKFLOW.read_text()
    push_paths = parse_event_paths(text, "push")
    pr_paths = parse_event_paths(text, "pull_request")
    if push_paths != pr_paths:
        print("push and pull_request path filters differ:", file=sys.stderr)
        print(f"  push: {push_paths}", file=sys.stderr)
        print(f"  pull_request: {pr_paths}", file=sys.stderr)
        return 1

    failures = 0
    for pattern, path, expected in CHEAT_SHEET:
        got = matches(path, pattern)
        if got != expected:
            print(
                f"cheat sheet: {path!r} vs {pattern!r}: expected {expected}, got {got}",
                file=sys.stderr,
            )
            failures += 1

    for changed in SHOULD_TRIGGER:
        if not would_run(changed, push_paths):
            print(f"should trigger, did not: {changed}", file=sys.stderr)
            failures += 1

    for changed in SHOULD_SKIP:
        if would_run(changed, push_paths):
            print(f"should skip, did not: {changed}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"{failures} path-filter check(s) failed", file=sys.stderr)
        return 1

    print(f"Docs lint path filter: {len(push_paths)} patterns")
    print(f"  trigger cases: {len(SHOULD_TRIGGER)} ok")
    print(f"  skip cases: {len(SHOULD_SKIP)} ok")
    print("  workflow_dispatch stays unfiltered (manual runs always start)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
