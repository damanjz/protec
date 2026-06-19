use crate::state::{AppState, VaultSlot};
use protec_core::{KeyWrap, WrapKind};
use tauri::State;

/// Whether this device supports Windows Hello AND the open vault has a Hello wrap.
#[derive(serde::Serialize)]
pub struct HelloStatus {
    pub available: bool,
    pub enabled: bool,
}

#[tauri::command]
pub fn hello_status(state: State<AppState>) -> HelloStatus {
    let available = protec_hello::is_available();
    let enabled = {
        let inner = state.lock();
        match &inner.slot {
            VaultSlot::Unlocked(v) => v.has_wrap(&WrapKind::WindowsHello),
            VaultSlot::Locked => {
                // Vault is locked: read the on-disk header to know if Hello is enabled.
                protec_core::Vault::open(&inner.vault_path)
                    .map(|locked| locked.has_wrap(&WrapKind::WindowsHello))
                    .unwrap_or(false)
            }
        }
    };
    HelloStatus { available, enabled }
}

/// Enable Hello: requires the vault unlocked. Prompts Hello, wraps the vault key,
/// adds the WindowsHello wrap. Never removes the master-password wrap.
#[tauri::command]
pub fn hello_enable(state: State<AppState>) -> Result<(), String> {
    if !protec_hello::is_available() {
        return Err("Windows Hello is not available on this device".into());
    }
    // Snapshot the vault key under the lock, then drop the lock before the Hello prompt.
    let vault_key = {
        let inner = state.lock();
        match &inner.slot {
            VaultSlot::Unlocked(v) => v.vault_key(),
            VaultSlot::Locked => return Err("Unlock the vault first".into()),
        }
    };
    let wrapping_key = hello_wrapping_key_enable().map_err(|e| e.to_string())?;
    let wrap = KeyWrap::seal(WrapKind::WindowsHello, &wrapping_key, &vault_key)
        .map_err(|_| "Failed to wrap the vault key".to_string())?;
    let mut inner = state.lock();
    match &mut inner.slot {
        VaultSlot::Unlocked(v) => v.add_wrap(wrap).map_err(|_| "Failed to save".to_string()),
        VaultSlot::Locked => Err("Vault locked".into()),
    }
}

/// Disable Hello: remove the WindowsHello wrap + delete the TPM key. Master
/// password unaffected.
#[tauri::command]
pub fn hello_disable(state: State<AppState>) -> Result<(), String> {
    {
        let mut inner = state.lock();
        if let VaultSlot::Unlocked(v) = &mut inner.slot {
            // Remove the wrap first (the vault is the source of truth). If this
            // fails, do NOT delete the TPM key — that would orphan the wrap.
            v.remove_wrap(WrapKind::WindowsHello)
                .map_err(|_| "Failed to disable Windows Hello".to_string())?;
        } else {
            return Err("Unlock the vault first".into());
        }
    }
    // Best-effort TPM key delete; the wrap is already gone so a delete failure is
    // non-fatal (the orphaned TPM key is harmless and Hello-gated).
    let _ = hello_delete_key();
    Ok(())
}

/// Unlock the vault using Windows Hello (lock screen path). Prompts Hello,
/// recovers the vault key from the WindowsHello wrap. On any failure the caller
/// falls back to the master-password field.
#[tauri::command]
pub fn hello_unlock(state: State<AppState>) -> Result<(), String> {
    if !protec_hello::is_available() {
        return Err("Windows Hello is not available".into());
    }
    let wrapping_key = hello_wrapping_key_unlock().map_err(|e| e.to_string())?;
    let mut inner = state.lock();
    let path = inner.vault_path.clone();
    let locked = protec_core::Vault::open(&path).map_err(|_| "Could not open vault".to_string())?;
    let unlocked = locked
        .unlock_with_wrap(WrapKind::WindowsHello, &wrapping_key)
        .map_err(|_| "Windows Hello unlock failed — use your master password".to_string())?;
    inner.slot = VaultSlot::Unlocked(unlocked);
    Ok(())
}

// ---- platform shims so non-Windows builds compile ----
#[cfg(windows)]
fn hello_wrapping_key_enable() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    protec_hello::enable_wrapping_key()
}
#[cfg(not(windows))]
fn hello_wrapping_key_enable() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    Err(protec_hello::HelloError::Unavailable)
}
#[cfg(windows)]
fn hello_wrapping_key_unlock() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    protec_hello::unlock_wrapping_key()
}
#[cfg(not(windows))]
fn hello_wrapping_key_unlock() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    Err(protec_hello::HelloError::Unavailable)
}
#[cfg(windows)]
fn hello_delete_key() -> Result<(), protec_hello::HelloError> {
    protec_hello::disable()
}
#[cfg(not(windows))]
fn hello_delete_key() -> Result<(), protec_hello::HelloError> {
    Ok(())
}
