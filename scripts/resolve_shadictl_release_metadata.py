#!/usr/bin/env python3
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parent.parent

CLI_CONFIGS = {
    "shadictl": {
        "manifest": ROOT / "crates" / "shadictl" / "Cargo.toml",
        "tag_prefix": "agntcy-shadi-cli-v",
        "binary_name": "shadictl",
    },
    "agentbridge": {
        "manifest": ROOT / "crates" / "agentbridge_cli" / "Cargo.toml",
        "tag_prefix": "agntcy-agentbridge-cli-v",
        "binary_name": "agentbridge",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve CLI release metadata for the GitHub Actions workflow."
    )
    parser.add_argument(
        "--cli",
        choices=sorted(CLI_CONFIGS),
        default="shadictl",
        help="Which CLI to resolve release metadata for (default: shadictl).",
    )
    parser.add_argument(
        "--event-name",
        required=True,
        help="GitHub event name for the current workflow run.",
    )
    parser.add_argument(
        "--release-tag",
        default="",
        help="GitHub release tag when the workflow is running for a published release.",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Rust target triple used to build the CLI.",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        required=True,
        help="GitHub Actions output file path.",
    )
    return parser.parse_args()


def load_version(manifest: Path) -> str:
    with manifest.open("rb") as handle:
        manifest_data = tomllib.load(handle)
    return manifest_data["package"]["version"]


def resolve_release_tag(
    event_name: str, release_tag: str, version: str, manifest: Path, tag_prefix: str
) -> str:
    if event_name != "release":
        return ""

    if not release_tag.startswith(tag_prefix):
        raise SystemExit(f"expected {tag_prefix}<version>, got {release_tag}")

    tag_version = release_tag[len(tag_prefix):]
    if tag_version != version:
        raise SystemExit(
            f"release tag version {tag_version} does not match {manifest} version {version}"
        )

    return release_tag


def resolve_binary_path(target: str, binary_name: str) -> str:
    binary_path = f"target/{target}/release/{binary_name}"
    if target.endswith("windows-msvc"):
        return f"{binary_path}.exe"
    return binary_path


def main() -> None:
    args = parse_args()
    config = CLI_CONFIGS[args.cli]

    version = load_version(config["manifest"])
    release_tag = resolve_release_tag(
        args.event_name, args.release_tag, version, config["manifest"], config["tag_prefix"]
    )

    outputs = {
        "version": version,
        "release_tag": release_tag,
        "binary_path": resolve_binary_path(args.target, config["binary_name"]),
        "binary_name": config["binary_name"],
    }

    with args.github_output.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()