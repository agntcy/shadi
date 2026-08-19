// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SHADI Desktop — a native control-plane app for shadictl, agentbridge, and
//! the SHADI shell. See agntcy/shadi#112 for the epic and panel breakdown.
//!
//! The Tauri IPC command contract (agntcy/shadi#114) is defined in
//! `commands/` — see `../docs/ipc-contract.md`.

use tauri::Manager;

mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Native file picker, so a key outside ~/.ssh can be chosen.
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::slim::SlimState::default())
        .setup(|app| {
            // Known rooms are persisted (agntcy/shadi#138); the app data dir is
            // only resolvable once the app exists. A failure here is reported
            // and tolerated — a bad room store must not block startup.
            match app.path().app_data_dir() {
                Ok(dir) => {
                    let state = app.state::<commands::slim::SlimState>();
                    if let Err(err) = state.init_store(dir.join("rooms.json")) {
                        eprintln!("warning: could not load saved rooms: {err}");
                    }
                    // Adopt the onboarding identity (agntcy/shadi#123) so DID
                    // auth works without the environment contract.
                    match state.load_identity(&commands::bootstrap::config_path(&dir)) {
                        Ok(true) => {}
                        Ok(false) => eprintln!("info: no identity yet — run onboarding"),
                        Err(err) => eprintln!("warning: could not load identity: {err}"),
                    }
                    // The transport reads mTLS material from SHADI_TMP_DIR; point
                    // it at the app's own directory unless the operator set one.
                    if std::env::var_os("SHADI_TMP_DIR").is_none() {
                        std::env::set_var("SHADI_TMP_DIR", &dir);
                    }
                }
                Err(err) => eprintln!("warning: no app data dir, rooms will not persist: {err}"),
            }
            Ok(())
        })
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
            commands::identity::identity_discover_ssh_keys,
            commands::identity::identity_generate_ssh_key,
            commands::identity::identity_github_human_did,
            commands::identity::identity_list_1password_accounts,
            commands::identity::identity_list_1password_ssh_keys,
            commands::identity::identity_bootstrap,
            commands::identity::identity_status,
            commands::identity::identity_trust_github_handle,
            commands::identity::identity_untrust_github_handle,
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
            commands::slim::slim_group_list,
            commands::slim::slim_group_roster,
            commands::slim::slim_group_remove_member,
            commands::slim::slim_group_forget,
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
