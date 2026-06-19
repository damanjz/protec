use crate::dto::VaultStatus;
use crate::state::{AppState, VaultSlot};
use protec_core::{Vault, VaultError};
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
    let inner = state.inner.lock().unwrap();
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
    let inner = state.inner.lock().unwrap();
    if inner.vault_path.exists() {
        return Err("A vault already exists at this location".into());
    }
    Vault::create(&inner.vault_path, &master_password).map_err(map_err)
}

#[tauri::command]
pub fn unlock(master_password: String, state: State<AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().unwrap();
    let locked = Vault::open(&inner.vault_path).map_err(map_err)?;
    let unlocked = locked.unlock(&master_password).map_err(map_err)?;
    inner.slot = VaultSlot::Unlocked(unlocked);
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().unwrap();
    // Replacing the slot drops the UnlockedVault, zeroizing keys.
    inner.slot = VaultSlot::Locked;
    Ok(())
}
