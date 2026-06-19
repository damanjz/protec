use crate::config::AppConfig;
use crate::state::AppState;
use tauri::State;

#[tauri::command]
pub fn get_config(state: State<AppState>) -> AppConfig {
    state.lock().config.clone()
}

#[tauri::command]
pub fn set_config(new_config: AppConfig, state: State<AppState>) -> Result<(), String> {
    let sanitized = new_config.sanitized();
    let path = config_path();
    sanitized.save(&path)?;
    state.lock().config = sanitized;
    Ok(())
}

/// %APPDATA%/Protec/config.toml (falls back to ./config.toml).
pub fn config_path() -> std::path::PathBuf {
    let base = std::env::var("APPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    base.join("Protec").join("config.toml")
}
