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

There is no desktop release yet ([#124](https://github.com/agntcy/shadi/issues/124)).

## Develop

```bash
pnpm install
pnpm tauri dev
```

## Build

```bash
pnpm tauri build
```

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
