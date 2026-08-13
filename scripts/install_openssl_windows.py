#!/usr/bin/env python3
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Install the OpenSSL build that WinGet will install alongside the CLI.

SQLCipher links libcrypto dynamically, so the DLL major the released binary
imports has to match the one WinGet resolves for the manifest dependency.
PackageDependencies carries no version ceiling and WinGet installs the newest
version satisfying the minimum, so the only way to keep the two in step is to
build against the same publisher and major. This reads the installer URL and
digest straight out of the winget-pkgs manifest for that reason.

ShiningLight serves only the current build of each line, so pinning an exact
version here would start 404ing the moment they publish a patch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from urllib.error import HTTPError

DEV_PACKAGE_PATH = "manifests/s/ShiningLight/OpenSSL/Dev"
CONTENTS_API = f"https://api.github.com/repos/microsoft/winget-pkgs/contents/{DEV_PACKAGE_PATH}"
RAW_MANIFEST = (
    "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/"
    f"{DEV_PACKAGE_PATH}/{{version}}/ShiningLight.OpenSSL.Dev.installer.yaml"
)
INSTALL_CANDIDATES = (
    r"C:\Program Files\OpenSSL",
    r"C:\Program Files\OpenSSL-Win64",
    r"C:\OpenSSL-Win64",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--major",
        default="4",
        help="OpenSSL major to build against. Bump together with the WinGet "
        "dependency in render_winget_manifests.py (default: 4).",
    )
    parser.add_argument(
        "--github-env",
        type=Path,
        default=os.environ.get("GITHUB_ENV"),
        help="File to append OPENSSL_* variables to (default: $GITHUB_ENV).",
    )
    return parser.parse_args()


def fetch(url: str) -> bytes:
    headers = {"User-Agent": "agntcy-shadi", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()
    except HTTPError as error:
        raise SystemExit(f"failed to fetch {url}: HTTP {error.code}") from error


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def latest_version(major: str) -> str:
    entries = json.loads(fetch(CONTENTS_API))
    versions = [
        entry["name"]
        for entry in entries
        if entry.get("type") == "dir" and entry["name"].startswith(f"{major}.")
    ]
    if not versions:
        raise SystemExit(f"winget-pkgs publishes no OpenSSL {major}.x dev package")
    return max(versions, key=version_key)


def x64_installer(version: str) -> tuple[str, str]:
    """The x64 .msi URL and its expected SHA-256, from the winget manifest."""
    manifest = fetch(RAW_MANIFEST.format(version=version)).decode("utf-8")
    for block in manifest.split("\n- Architecture: ")[1:]:
        if not block.startswith("x64"):
            continue
        url = re.search(r"InstallerUrl:\s*(\S+)", block)
        digest = re.search(r"InstallerSha256:\s*(\S+)", block)
        if url and digest and url.group(1).lower().endswith(".msi"):
            return url.group(1), digest.group(1).lower()
    raise SystemExit(f"no x64 .msi installer in the OpenSSL {version} manifest")


def download_verified(url: str, expected_sha256: str, destination: Path) -> None:
    destination.write_bytes(fetch(url))
    actual = hashlib.sha256(destination.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise SystemExit(
            f"{url} digest mismatch: manifest says {expected_sha256}, got {actual}"
        )


def install(msi: Path) -> None:
    result = subprocess.run(
        ["msiexec", "/i", str(msi), "/quiet", "/norestart"], check=False
    )
    if result.returncode != 0:
        raise SystemExit(f"msiexec exited {result.returncode}")


def resolve_install_dir() -> Path:
    for candidate in INSTALL_CANDIDATES:
        if (Path(candidate) / "include" / "openssl" / "evp.h").is_file():
            return Path(candidate)
    raise SystemExit("no OpenSSL headers found after install")


def main() -> int:
    args = parse_args()
    if os.name != "nt":
        raise SystemExit("this script only applies to Windows builds")

    version = latest_version(args.major)
    url, expected = x64_installer(version)
    print(f"OpenSSL {version} from {url}")

    with tempfile.TemporaryDirectory() as work:
        msi = Path(work) / "openssl-dev.msi"
        download_verified(url, expected, msi)
        install(msi)

    openssl_dir = resolve_install_dir()
    lib_dir = openssl_dir / "lib" / "VC" / "x64" / "MD"
    if not lib_dir.is_dir():
        lib_dir = openssl_dir / "lib"

    variables = {
        "OPENSSL_DIR": str(openssl_dir),
        "OPENSSL_LIB_DIR": str(lib_dir),
        "OPENSSL_INCLUDE_DIR": str(openssl_dir / "include"),
    }
    for name, value in variables.items():
        print(f"{name}={value}")
    if args.github_env:
        with Path(args.github_env).open("a", encoding="utf-8") as handle:
            for name, value in variables.items():
                handle.write(f"{name}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
