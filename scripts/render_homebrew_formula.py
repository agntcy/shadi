#!/usr/bin/env python3
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import textwrap
import tomllib
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
CLI_MANIFEST = ROOT / "crates" / "shadictl" / "Cargo.toml"
DEFAULT_OUTPUT = ROOT / "Formula" / "shadictl.rb"
TAG_PATTERN = re.compile(r"^agntcy-shadi-cli-v(?P<version>[0-9A-Za-z.+-]+)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render the Homebrew formula for the released shadictl CLI tag."
    )
    parser.add_argument(
        "--tag",
        required=True,
        help="Release tag in the form agntcy-shadi-cli-v<version>",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Formula output path (default: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def resolve_workspace_value(package: dict, workspace_package: dict, key: str) -> str:
    value = package.get(key)
    if isinstance(value, dict) and value.get("workspace"):
        return workspace_package[key]
    if value is None:
        return workspace_package[key]
    return value


def fetch_sha256(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "GitHub-Copilot"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=60) as response:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def ruby_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_formula(tag: str) -> str:
    match = TAG_PATTERN.match(tag)
    if not match:
        raise SystemExit(f"expected agntcy-shadi-cli-v<version> tag, got: {tag}")

    workspace = load_toml(WORKSPACE_MANIFEST)
    cli_manifest = load_toml(CLI_MANIFEST)
    workspace_package = workspace["workspace"]["package"]
    package = cli_manifest["package"]

    description = package["description"]
    homepage = resolve_workspace_value(package, workspace_package, "repository")
    license_id = resolve_workspace_value(package, workspace_package, "license")
    source_url = f"{homepage}/archive/refs/tags/{tag}.tar.gz"
    source_sha256 = fetch_sha256(source_url)
    git_url = homepage if homepage.endswith(".git") else f"{homepage}.git"

    return textwrap.dedent(
        f"""\
        class Shadictl < Formula
          desc \"{ruby_string(description)}\"
          homepage \"{ruby_string(homepage)}\"
          url \"{ruby_string(source_url)}\"
          sha256 \"{source_sha256}\"
          license \"{ruby_string(license_id)}\"
          head \"{ruby_string(git_url)}\", branch: \"main\"

          depends_on \"pkgconf\" => :build
          depends_on \"rust\" => :build
          depends_on \"nettle\"
          depends_on \"openssl@3\"
          depends_on \"python@3.12\"

          def install
            ENV[\"OPENSSL_DIR\"] = Formula[\"openssl@3\"].opt_prefix
            ENV[\"PYO3_PYTHON\"] = Formula[\"python@3.12\"].opt_bin/\"python3.12\"

            system \"cargo\", \"install\", \"--locked\", \"--path\", \"crates/shadictl\", *std_cargo_args
          end

          test do
            assert_match \"shadictl\", shell_output("#{{bin}}/shadictl --help")
          end
        end
        """
    )


def main() -> int:
    args = parse_args()
    formula = render_formula(args.tag)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(formula, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
