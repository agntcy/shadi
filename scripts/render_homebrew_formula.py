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

CLI_CONFIGS = {
    "shadictl": {
        "manifest": ROOT / "crates" / "shadictl" / "Cargo.toml",
        "tag_pattern": re.compile(r"^agntcy-shadi-cli-v(?P<version>[0-9A-Za-z.+-]+)$"),
        "default_output": ROOT / "Formula" / "shadictl.rb",
        "class_name": "Shadictl",
        "crate_path": "crates/shadictl",
        "binary_name": "shadictl",
        "linux_needs_openssl": True,
    },
    "agentbridge": {
        "manifest": ROOT / "crates" / "agentbridge_cli" / "Cargo.toml",
        "tag_pattern": re.compile(
            r"^agntcy-agentbridge-cli-v(?P<version>[0-9A-Za-z.+-]+)$"
        ),
        "default_output": ROOT / "Formula" / "agentbridge.rb",
        "class_name": "Agentbridge",
        "crate_path": "crates/agentbridge_cli",
        "binary_name": "agentbridge",
        "linux_needs_openssl": False,
    },
}

FORMULA_HEADER = textwrap.dedent(
    """\
    # Copyright AGNTCY Contributors (https://github.com/agntcy)
    # SPDX-License-Identifier: Apache-2.0

    """
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render the Homebrew formula for a released CLI tag."
    )
    parser.add_argument(
        "--cli",
        choices=sorted(CLI_CONFIGS),
        default="shadictl",
        help="Which CLI to render a formula for (default: shadictl).",
    )
    parser.add_argument(
        "--tag",
        required=True,
        help="Release tag, e.g. agntcy-shadi-cli-v<version> or agntcy-agentbridge-cli-v<version>",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Formula output path (default: Formula/<cli>.rb)",
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


def released_sha256(url: str) -> str:
    """The digest the release publishes, rather than re-hashing the archive."""
    request = urllib.request.Request(f"{url}.sha256", headers={"User-Agent": "GitHub-Copilot"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            first = response.read().decode("utf-8").split()
        if first:
            return first[0]
    except Exception:
        pass
    return fetch_sha256(url)


def ruby_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_formula(cli: str, tag: str) -> str:
    config = CLI_CONFIGS[cli]
    match = config["tag_pattern"].match(tag)
    if not match:
        raise SystemExit(f"expected {config['tag_pattern'].pattern} tag, got: {tag}")

    workspace = load_toml(WORKSPACE_MANIFEST)
    cli_manifest = load_toml(config["manifest"])
    workspace_package = workspace["workspace"]["package"]
    package = cli_manifest["package"]

    description = package["description"]
    homepage = resolve_workspace_value(package, workspace_package, "repository")
    license_id = resolve_workspace_value(package, workspace_package, "license")
    source_url = f"{homepage}/archive/refs/tags/{tag}.tar.gz"
    source_sha256 = fetch_sha256(source_url)
    git_url = homepage if homepage.endswith(".git") else f"{homepage}.git"
    class_name = config["class_name"]
    crate_path = config["crate_path"]
    binary_name = config["binary_name"]

    version = match.group("version")
    needs_openssl = config["linux_needs_openssl"]

    def arch_blocks(targets: dict[str, str], indent: str) -> str:
        blocks = []
        for cpu, target in targets.items():
            asset = f"{binary_name}-v{version}-{target}.tar.gz"
            url = f"{homepage}/releases/download/{tag}/{asset}"
            blocks.append(
                f"{indent}on_{cpu} do\n"
                f'{indent}  url "{ruby_string(url)}"\n'
                f'{indent}  sha256 "{released_sha256(url)}"\n'
                f"{indent}end"
            )
        return "\n\n".join(blocks)

    macos_block = arch_blocks(
        {"arm": "aarch64-apple-darwin", "intel": "x86_64-apple-darwin"}, "    "
    )
    linux_block = arch_blocks(
        {"arm": "aarch64-unknown-linux-gnu", "intel": "x86_64-unknown-linux-gnu"}, "    "
    )
    if needs_openssl:
        linux_block += (
            '\n\n    depends_on "patchelf" => :build'
            '\n    depends_on "openssl@3"'
        )
        # The released binary carries no DT_RUNPATH, so the loader would look for
        # libcrypto.so.3 on the system path and miss Homebrew's copy.
        rpath = (
            '\n\n    return unless OS.linux?\n\n'
            '    system "patchelf", "--set-rpath", Formula["openssl@3"].opt_lib,'
            f' bin/"{binary_name}"'
        )
    else:
        rpath = ""

    formula_body = textwrap.dedent(
        f"""\
        class {class_name} < Formula
          desc \"{ruby_string(description)}\"
          homepage \"{ruby_string(homepage)}\"
          version \"{version}\"
          license \"{ruby_string(license_id)}\"
          head \"{ruby_string(git_url)}\", branch: \"main\"

        MACOS_BLOCK

        LINUX_BLOCK

          def install
            bin.install \"{binary_name}\"RPATH
          end

          test do
            assert_match \"{binary_name}\", shell_output("#{{bin}}/{binary_name} --help")
          end
        end
        """
    )
    formula_body = (
        formula_body.replace("MACOS_BLOCK", f"  on_macos do\n{macos_block}\n  end")
        .replace("LINUX_BLOCK", f"  on_linux do\n{linux_block}\n  end")
        .replace("RPATH", rpath)
    )

    return f"{FORMULA_HEADER}{formula_body}"


def main() -> int:
    args = parse_args()
    output = args.output or CLI_CONFIGS[args.cli]["default_output"]
    formula = render_formula(args.cli, args.tag)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(formula, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
