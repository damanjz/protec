#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config;
mod dto;
mod ipc;
mod match_domain;
mod state;

use config::AppConfig;
use state::AppState;
use std::path::PathBuf;

/// Resolve the default vault path: %APPDATA%/Protec/vault.dat (falls back to CWD).
fn default_vault_path() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("Protec").join("vault.dat")
}

fn main() {
    let config = AppConfig::load(&commands::settings::config_path());
    let vault_path = config
        .vault_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(default_vault_path);
    let app_state = AppState::new(vault_path, config);

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::settings::get_config,
            commands::settings::set_config,
            commands::auth::vault_status,
            commands::auth::create_vault,
            commands::auth::unlock,
            commands::auth::lock,
            commands::auth::backup_available,
            commands::auth::restore_backup,
            commands::entries::list_entries,
            commands::entries::get_entry,
            commands::entries::add_entry,
            commands::entries::update_entry,
            commands::entries::delete_entry,
            commands::entries::save_vault,
            commands::generator::generate,
            commands::clipboard::copy_secret
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
