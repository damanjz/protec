#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config;
mod dto;
mod state;

use config::AppConfig;
use state::AppState;
use std::path::PathBuf;

/// Resolve the default vault path: %APPDATA%/Protec/vault.dat (falls back to CWD).
fn default_vault_path() -> PathBuf {
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    base.join("Protec").join("vault.dat")
}

fn main() {
    let config = AppConfig::default(); // real load happens in a later task
    let vault_path = config
        .vault_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(default_vault_path);
    let app_state = AppState::new(vault_path, config);

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
