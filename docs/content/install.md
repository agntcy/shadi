# Install the CLI

This page covers the supported released-install flows for `shadictl`.

## Linux

Install the latest released `shadictl` with a single command:

```bash
curl -fsSL https://agntcy.github.io/shadi/install.sh | bash
```

The installer currently supports these published Linux release archives:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

For each install, it downloads the matching release archive and its `.sha256`
sidecar from the published `agntcy-shadi-cli-v*` GitHub release, verifies the
archive checksum, and only then installs `shadictl`.

## Install Paths

By default, the installer chooses a writable binary directory:

- non-root: `${XDG_BIN_HOME:-$HOME/.local/bin}`
- root: `/usr/local/bin`

To install somewhere else, set `SHADI_INSTALL_DIR` on the `bash` side of the
pipeline:

```bash
curl -fsSL https://agntcy.github.io/shadi/install.sh | env SHADI_INSTALL_DIR="$HOME/bin" bash
```

If the target directory is not already on `PATH`, the installer prints the
export command needed to add it.

## Pinning and Upgrades

With no version override, rerunning the installer upgrades `shadictl` to the
latest published CLI release.

To install or downgrade to a specific release, set `SHADI_VERSION`:

```bash
curl -fsSL https://agntcy.github.io/shadi/install.sh | env SHADI_VERSION=0.1.1 bash
```

`SHADI_VERSION` accepts `0.1.1`, `v0.1.1`, or the full release tag
`agntcy-shadi-cli-v0.1.1`.

The installer replaces the existing `shadictl` binary in place. If the archive
download or checksum validation fails, the existing binary is left untouched.

## Environment Overrides

These environment variables are supported by the installer:

- `SHADI_VERSION`: install a specific published CLI release instead of the latest one.
- `SHADI_INSTALL_DIR`: install `shadictl` into a specific directory.
- `SHADI_RELEASE_API_URL`: advanced override for the latest-release metadata endpoint.
- `SHADI_RELEASE_DOWNLOAD_BASE_URL`: advanced override for the release asset base URL.

The two advanced overrides are primarily useful for mirrors, staging, and local
validation of the installer script.

## macOS and Windows

On macOS, install the released CLI with Homebrew:

```bash
brew tap agntcy/shadi https://github.com/agntcy/shadi
brew install agntcy/shadi/shadictl
```

On Windows, once the matching manifest has landed in the default WinGet source,
install or upgrade with:

```powershell
winget install --id AGNTCY.shadictl -e
winget upgrade --id AGNTCY.shadictl -e
```