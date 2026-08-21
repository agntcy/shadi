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
    macos_targets = {
        "arm": f"aarch64-apple-darwin",
        "intel": f"x86_64-apple-darwin",
    }
    macos_blocks = []
    for cpu, target in macos_targets.items():
        asset = f"{binary_name}-v{version}-{target}.tar.gz"
        url = f"{homepage}/releases/download/{tag}/{asset}"
        macos_blocks.append(
            f'    on_{cpu} do\n'
            f'      url "{ruby_string(url)}"\n'
            f'      sha256 "{released_sha256(url)}"\n'
            f'    end'
        )
    macos_block = "\n\n".join(macos_blocks)

    formula_body = textwrap.dedent(
        f"""\
        class {class_name} < Formula
          desc \"{ruby_string(description)}\"
          homepage \"{ruby_string(homepage)}\"
          version \"{version}\"
          license \"{ruby_string(license_id)}\"
          head \"{ruby_string(git_url)}\", branch: \"main\"

        MACOS_BLOCK

          on_linux do
            # The Linux build links libcrypto.so.3 with no rpath, so it resolves
            # against the system loader path rather than a Homebrew prefix. Built
            # from source here until the released binary carries its own rpath.
            url \"{ruby_string(source_url)}\"
            sha256 \"{source_sha256}\"

            depends_on \"pkgconf\" => :build
            depends_on \"rust\" => :build
            depends_on \"nettle\"
            depends_on \"openssl@3\"
            depends_on \"python@3.12\"
          end

          def install
            if OS.mac?
              bin.install \"{binary_name}\"
            else
              ENV[\"OPENSSL_DIR\"] = Formula[\"openssl@3\"].opt_prefix
              ENV[\"PYO3_PYTHON\"] = Formula[\"python@3.12\"].opt_bin/\"python3.12\"

              # std_cargo_args already passes --locked and --path.
              system \"cargo\", \"install\", *std_cargo_args(path: \"{crate_path}\")
            end
          end

          test do
            assert_match \"{binary_name}\", shell_output("#{{bin}}/{binary_name} --help")
          end
        end
        """
    ).replace("MACOS_BLOCK", f"  on_macos do\n{macos_block}\n  end")

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
