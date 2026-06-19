use crate::dto::VaultStatus;
use crate::state::{AppState, VaultSlot};
use protec_core::{Vault, VaultError};
use std::path::PathBuf;
use tauri::State;

fn map_err(e: VaultError) -> String {
    match e {
        VaultError::WrongPassword => "Incorrect master password".into(),
        VaultError::Tampered => "Vault failed authentication — it may be damaged".into(),
        VaultError::Corrupted => "Vault file is corrupted".into(),
        VaultError::VersionUnsupported(v) => format!("Unsupported vault version: {v}"),
        VaultError::NotFound => "Entry not found".into(),
        VaultError::Io(e) => format!("File error: {e}"),
    }
}

#[tauri::command]
pub fn vault_status(state: State<AppState>) -> VaultStatus {
    let inner = state.lock();
    VaultStatus {
        exists: inner.vault_path.exists(),
        unlocked: matches!(inner.slot, VaultSlot::Unlocked(_)),
    }
}

#[tauri::command]
pub fn create_vault(master_password: String, state: State<AppState>) -> Result<(), String> {
    if master_password.is_empty() {
        return Err("Master password cannot be empty".into());
    }
    let inner = state.lock();
    if inner.vault_path.exists() {
        return Err("A vault already exists at this location".into());
    }
    // First run: the parent directory (e.g. %APPDATA%\Protec) may not exist yet.
    if let Some(parent) = inner.vault_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Could not create vault folder: {e}"))?;
    }
    Vault::create(&inner.vault_path, &master_password).map_err(map_err)
}

#[tauri::command]
pub fn unlock(master_password: String, state: State<AppState>) -> Result<(), String> {
    let mut inner = state.lock();
    let locked = Vault::open(&inner.vault_path).map_err(map_err)?;
    let unlocked = locked.unlock(&master_password).map_err(map_err)?;
    inner.slot = VaultSlot::Unlocked(unlocked);
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<AppState>) -> Result<(), String> {
    let mut inner = state.lock();
    // Replacing the slot drops the UnlockedVault, zeroizing keys.
    inner.slot = VaultSlot::Locked;
    Ok(())
}

fn bak_path_of(path: &std::path::Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    let mut name = name;
    name.push(".bak");
    p.set_file_name(name);
    p
}

/// True if a `.bak` exists next to the configured vault file.
#[tauri::command]
pub fn backup_available(state: State<AppState>) -> bool {
    let inner = state.lock();
    bak_path_of(&inner.vault_path).exists()
}

/// Restore the vault from its `.bak`: copy `vault.dat.bak` over `vault.dat`.
/// Verifies the backup is openable before overwriting; returns an error otherwise.
#[tauri::command]
pub fn restore_backup(state: State<AppState>) -> Result<(), String> {
    let inner = state.lock();
    let bak = bak_path_of(&inner.vault_path);
    if !bak.exists() {
        return Err("No backup file found".into());
    }
    // Validate the backup is structurally well-formed (magic/version/parse) before
    // clobbering the live vault. Note: this does NOT verify it decrypts with the
    // current master password — a restored backup may require a different password.
    Vault::open(&bak).map_err(map_err)?;
    std::fs::copy(&bak, &inner.vault_path).map_err(|e| format!("Restore failed: {e}"))?;
    Ok(())
}
