# SHADI Desktop

A native control-plane app for `shadictl`, `agentbridge`, and the SHADI shell — see
[agntcy/shadi#112](https://github.com/agntcy/shadi/issues/112) for the epic and panel
breakdown.

Tauri (Rust backend in `src-tauri/`, linking the core SHADI crates directly) plus
a React/Vite/TypeScript frontend, following
[block/buzz](https://github.com/block/buzz)'s desktop app layout.

## What is implemented

Nine tabs are wired today:

- **Identity** — SSH / 1Password onboarding, GitHub handle cross-check, derived agent DIDs ([#123](https://github.com/agntcy/shadi/issues/123)).
- **Keys** — DIDs from a GPG or GitHub key, derived agent identities and their verification, and the secret store by key name; no secret value reaches the UI ([#117](https://github.com/agntcy/shadi/issues/117)).
- **Sandbox** — list, launch, attach, and kill sessions via `shadi_sandbox` ([#115](https://github.com/agntcy/shadi/issues/115)).
- **Policy** — live query/patch plus explain/diff against `shadi_sandbox` ([#116](https://github.com/agntcy/shadi/issues/116)).
- **Rooms** — SLIM node, groups, roster, and persistence ([#118](https://github.com/agntcy/shadi/issues/118), [#138](https://github.com/agntcy/shadi/issues/138)).
- **Directory** — search the Agent Directory by skill or DID, pull a record, publish an AgentCard, and invite what you find into a room, through `dirctl` ([#119](https://github.com/agntcy/shadi/issues/119)).
- **Owner** — the rooms you moderate are yours. Agents ask over A2A to let someone in. Standing rules decide most requests, and the rest wait in an inbox until you allow or deny them or they time out. Every decision goes to an audit trail ([#421](https://github.com/agntcy/shadi/issues/421)).
- **agentbridge** — list, handoff, delegate, and coordinate with live round events ([#120](https://github.com/agntcy/shadi/issues/120)).
- **Traces** — recent trace lines and a per-span summary, and a read-only view of SQLCipher memory that opens with the key in the secret store, as `shadictl memory` does ([#121](https://github.com/agntcy/shadi/issues/121)).

The **Terminal** button opens `shadictl shell` in a real terminal at the bottom of the window, for anything the tabs don't cover yet ([#122](https://github.com/agntcy/shadi/issues/122)). It looks for `shadictl` on `PATH`, `~/.cargo/bin`, `/opt/homebrew/bin` and `/usr/local/bin`, or at `SHADI_SHADICTL`.

Releases are unsigned installers on GitHub Releases ([#124](https://github.com/agntcy/shadi/issues/124)); see Release below.

## Develop

```bash
pnpm install
pnpm tauri dev
```

## Build

```bash
pnpm tauri build
```

## Release

The Desktop is versioned on its own, outside the workspace's release-plz
cycle. Set the new version in `src-tauri/tauri.conf.json`,
`src-tauri/Cargo.toml` and `package.json`, merge, then push a matching tag:

```bash
git tag -s shadi-desktop-v0.1.0 -m "SHADI Desktop 0.1.0"
git push origin shadi-desktop-v0.1.0
```

`.github/workflows/desktop-release.yml` checks the tag against
`tauri.conf.json`, creates a prerelease (never marked Latest, which stays the
CLI's), and attaches the macOS `.dmg`s, the Linux `.deb`, `.rpm` and AppImage,
and the Windows `.msi` and setup `.exe`. Each has a `.sha256`, a cosign
`.sigstore.json` bundle and a build-provenance attestation. There is no Apple
or Windows code-signing certificate yet, so the OS warns on first launch.

## Test

```bash
cargo test --manifest-path src-tauri/Cargo.toml
pnpm test:e2e
```

`cargo test` covers the Tauri commands against the linked SHADI crates.
`pnpm test:e2e` drives the real frontend in Playwright with the backend
replaced by canned answers (`e2e/tauri.ts`), so it needs no SLIM node or
keychain. Run `pnpm exec playwright install chromium` once, or set
`PW_CHANNEL=chrome` (or `msedge`) to use an installed browser. The live tier
runs a real SLIM node: `docs/content/demos/desktop-room-e2e.sh` and
`desktop-owner-e2e.sh` from the repository root.

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
