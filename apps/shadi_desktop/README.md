# SHADI Desktop

A native control-plane app for `shadictl`, `agentbridge`, and the SHADI shell — see
[agntcy/shadi#112](https://github.com/agntcy/shadi/issues/112) for the epic and panel
breakdown.

Tauri (Rust backend in `src-tauri/`, linking the core SHADI crates directly) plus
a React/Vite/TypeScript frontend, following
[block/buzz](https://github.com/block/buzz)'s desktop app layout.

## What is implemented

Five tabs are wired today:

- **Identity** — SSH / 1Password onboarding, GitHub handle cross-check, derived agent DIDs ([#123](https://github.com/agntcy/shadi/issues/123)). The remaining identity/secrets IPC from [#117](https://github.com/agntcy/shadi/issues/117) is still stubbed.
- **Sandbox** — list, launch, attach, and kill sessions via `shadi_sandbox` ([#115](https://github.com/agntcy/shadi/issues/115)).
- **Policy** — live query/patch plus explain/diff against `shadi_sandbox` ([#116](https://github.com/agntcy/shadi/issues/116)).
- **Rooms** — SLIM node, groups, roster, and persistence ([#118](https://github.com/agntcy/shadi/issues/118), [#138](https://github.com/agntcy/shadi/issues/138)).
- **agentbridge** — list, handoff, delegate, and coordinate with live round events ([#120](https://github.com/agntcy/shadi/issues/120)).

Agent Directory and trace/memory backends still return `not_implemented`
([#119](https://github.com/agntcy/shadi/issues/119),
[#121](https://github.com/agntcy/shadi/issues/121)). There is no signed
desktop release yet ([#124](https://github.com/agntcy/shadi/issues/124)).

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
