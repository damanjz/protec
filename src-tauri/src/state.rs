use crate::config::AppConfig;
use protec_core::UnlockedVault;
use std::path::PathBuf;
use std::sync::Mutex;

/// Whether a vault is currently open in memory.
pub enum VaultSlot {
    Locked,
    Unlocked(UnlockedVault),
}

/// The single source of truth for the app, guarded by a Mutex.
pub struct AppState {
    pub inner: Mutex<Inner>,
}

pub struct Inner {
    pub slot: VaultSlot,
    pub vault_path: PathBuf,
    pub config: AppConfig,
}

impl AppState {
    pub fn new(vault_path: PathBuf, config: AppConfig) -> Self {
        Self {
            inner: Mutex::new(Inner { slot: VaultSlot::Locked, vault_path, config }),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.inner.lock().unwrap().slot, VaultSlot::Unlocked(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_locked() {
        let st = AppState::new(PathBuf::from("x.dat"), AppConfig::default());
        assert!(!st.is_unlocked());
    }
}
