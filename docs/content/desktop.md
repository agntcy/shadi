# SHADI Desktop

SHADI Desktop is a native app over what `shadictl` and `agentbridge` do:
identity and secrets, sandboxed sessions and their policy, SLIM rooms, the
Agent Directory, agent coordination, traces and memory. It links the SHADI
crates directly rather than running the CLIs, so it applies the same checks
they do. For anything the tabs don't cover yet, its Terminal button opens the
real `shadictl shell`.

## Tabs

| Tab | What it does | CLI equivalent |
| --- | --- | --- |
| Identity | Onboarding from an SSH key or 1Password: your human DID, derived agent DIDs, mTLS material | `shadictl derive-agent-identity --source ssh` |
| Keys | DIDs from a GPG or GitHub key, deriving and verifying agent identities, the secret store by key name | `did-from-gpg`, `did-from-github`, `verify-agent-identity`, `--list-keychain` |
| Sandbox | List, launch, attach to and kill sandboxed sessions | `shadictl <flags> -- <cmd>`, shell `/sessions` |
| Policy | Query, patch, explain and diff a session's live policy | shell `/policy` |
| Rooms | A local SLIM node, rooms you create or join, rosters | shell `/slim` |
| Directory | Search the Agent Directory, publish an AgentCard, invite what you find | `shadictl dir`, `agentbridge register --dir-publish` |
| Owner | Approve who joins the rooms you own, with standing rules and an audit trail | `agentbridge request-invite` is the agent's side |
| agentbridge | List adapters, hand off, delegate, coordinate | `agentbridge list`, `handoff`, `delegate`, `coordinate` |
| Traces | Recent trace lines and a per-span summary, and a read-only view of memory | `shadictl trace`, `shadictl memory` |

The secrets surfaces never show a secret's value: the store is listed by key
name, and a key can be checked for presence. Memory opens only with the key
`shadictl memory` reads from the secret store.

## Install

Download the installer for your platform from the latest
[`shadi-desktop-v*` release](https://github.com/agntcy/shadi/releases?q=shadi-desktop&expanded=true).
The builds are not yet code-signed, so the first launch needs one extra step.

- **macOS** (`.dmg`, Apple silicon or Intel): open the image and drag
  *SHADI Desktop* to Applications. On first launch, right-click the app and
  choose **Open**, or clear the quarantine flag:

  ```bash
  xattr -dr com.apple.quarantine "/Applications/SHADI Desktop.app"
  ```

- **Windows** (`.msi` or `-setup.exe`): run the installer. If SmartScreen
  stops it, choose **More info**, then **Run anyway**.
- **Linux** (`.deb`, `.rpm` or AppImage): install the package with your
  package manager, for example `sudo apt install ./SHADI.Desktop_*_amd64.deb`,
  or make the AppImage executable and run it.

Two tabs use tools the app doesn't bundle: the Terminal runs `shadictl`
([Install the CLI](install.md)), found on `PATH`, in `~/.cargo/bin` or the
Homebrew prefixes, or at `SHADI_SHADICTL`; the Directory tab runs `dirctl`.

### Verify a download

Each installer has a `.sha256` checksum, a cosign `.sigstore.json` bundle and a
build-provenance attestation, made by the release workflow:

```bash
shasum -a 256 -c "SHADI Desktop_0.1.0_aarch64.dmg.sha256"
cosign verify-blob \
  --bundle "SHADI Desktop_0.1.0_aarch64.dmg.sigstore.json" \
  --certificate-identity-regexp 'https://github.com/agntcy/shadi/\.github/workflows/desktop-release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "SHADI Desktop_0.1.0_aarch64.dmg"
gh attestation verify "SHADI Desktop_0.1.0_aarch64.dmg" --repo agntcy/shadi
```

## Build from source

```bash
cd apps/shadi_desktop
pnpm install
pnpm tauri dev      # or: pnpm tauri build
```

See [`apps/shadi_desktop/README.md`](https://github.com/agntcy/shadi/blob/main/apps/shadi_desktop/README.md)
for the tests and how a release is cut, and
[A Desktop walkthrough](demos/desktop-walkthrough.md) for an end-to-end tour.
