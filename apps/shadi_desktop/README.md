# SHADI Desktop

A native control-plane app for `shadictl`, `agentbridge`, and the SHADI shell — see
[agntcy/shadi#112](https://github.com/agntcy/shadi/issues/112) for the epic and panel
breakdown.

This is scaffolding only ([agntcy/shadi#113](https://github.com/agntcy/shadi/issues/113)):
an empty window, no feature panels yet. Tauri (Rust backend in `src-tauri/`, linking the
core SHADI crates directly) + React/Vite/TypeScript frontend, following
[block/buzz](https://github.com/block/buzz)'s desktop app layout.

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
