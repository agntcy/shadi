// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SHADI Desktop — a native control-plane app for shadictl, agentbridge, and
//! the SHADI shell. See agntcy/shadi#112 for the epic and panel breakdown.
//!
//! The Tauri IPC command contract (agntcy/shadi#114) is defined in
//! `commands/` — see `../docs/ipc-contract.md`. Every command there is
//! currently a stub; no feature panels exist yet.

mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::sandbox::sandbox_launch,
            commands::sandbox::sandbox_list_sessions,
            commands::sandbox::sandbox_attach,
            commands::sandbox::sandbox_detach,
            commands::sandbox::sandbox_kill,
            commands::sandbox::sandbox_status,
            commands::policy::policy_query,
            commands::policy::policy_patch,
            commands::policy::policy_explain,
            commands::policy::policy_diff,
            commands::policy::policy_profiles,
            commands::identity::identity_did_from_gpg,
            commands::identity::identity_did_from_github,
            commands::identity::identity_derive_agent,
            commands::identity::identity_verify_agent,
            commands::identity::secret_get,
            commands::identity::secret_put_key,
            commands::identity::secret_list_keychain,
            commands::identity::secret_backend_status,
            commands::slim::slim_node_start,
            commands::slim::slim_node_status,
            commands::slim::slim_group_create,
            commands::slim::slim_group_invite,
            commands::slim::slim_group_join,
            commands::slim::slim_controller_list_connections,
            commands::slim::slim_controller_list_routes,
            commands::dir::dir_search,
            commands::dir::dir_pull,
            commands::dir::dir_info,
            commands::dir::dir_register,
            commands::agentbridge::agentbridge_list_adapters,
            commands::agentbridge::agentbridge_handoff,
            commands::agentbridge::agentbridge_delegate,
            commands::agentbridge::agentbridge_coordinate,
            commands::trace_memory::trace_list,
            commands::trace_memory::trace_summary,
            commands::trace_memory::memory_get,
            commands::trace_memory::memory_search,
            commands::trace_memory::memory_list,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
