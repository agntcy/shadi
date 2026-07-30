// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SHADI Desktop — a native control-plane app for shadictl, agentbridge, and
//! the SHADI shell. See agntcy/shadi#112 for the epic and panel breakdown.
//!
//! This is scaffolding only (agntcy/shadi#113): an empty window with no
//! feature panels yet. The Tauri IPC command contract (agntcy/shadi#114)
//! lands before any panel starts calling into the core SHADI crates.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
