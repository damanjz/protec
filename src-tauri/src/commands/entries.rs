use crate::dto::{EntryDetail, EntrySummary};
use crate::state::{AppState, VaultSlot};
use protec_core::{Entry, VaultError};
use tauri::State;
use uuid::Uuid;

/// Rate limiter for plaintext password reveals/copies. Blocks bulk exfiltration
/// (e.g. a script dumping every password) while never impeding a human revealing
/// a handful of entries. Keyed by a constant since the threat is total volume.
pub struct RevealLimiter(pub std::sync::Mutex<crate::ipc::ratelimit::RateLimiter>);

impl Default for RevealLimiter {
    fn default() -> Self {
        // Allow up to 30 reveals per 10 seconds — far above any human pace,
        // far below a scripted dump of a full vault.
        Self(std::sync::Mutex::new(
            crate::ipc::ratelimit::RateLimiter::new(10_000, 30),
        ))
    }
}

fn reveal_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn map_err(e: VaultError) -> String {
    match e {
        VaultError::NotFound => "Entry not found".into(),
        VaultError::Io(e) => format!("File error: {e}"),
        other => format!("{other}"),
    }
}

/// Run a closure with the unlocked vault, or return a "locked" error.
fn with_unlocked<T>(
    state: &State<AppState>,
    f: impl FnOnce(&mut protec_core::UnlockedVault) -> Result<T, String>,
) -> Result<T, String> {
    let mut inner = state.lock();
    match &mut inner.slot {
        VaultSlot::Unlocked(v) => f(v),
        VaultSlot::Locked => Err("Vault is locked".into()),
    }
}

#[tauri::command]
pub fn list_entries(state: State<AppState>) -> Result<Vec<EntrySummary>, String> {
    with_unlocked(&state, |v| {
        Ok(v.list_entries().iter().map(EntrySummary::from).collect())
    })
}

#[tauri::command]
pub fn get_entry(
    id: Uuid,
    reveal: bool,
    state: State<AppState>,
    reveal_limiter: State<RevealLimiter>,
) -> Result<EntryDetail, String> {
    if reveal {
        let allowed = reveal_limiter
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .check("reveal", reveal_now_ms());
        if !allowed {
            return Err("Too many password reveals — slow down.".into());
        }
    }
    with_unlocked(&state, |v| {
        let e = v.get(id).ok_or_else(|| "Entry not found".to_string())?;
        Ok(if reveal {
            EntryDetail::revealed(e)
        } else {
            EntryDetail::masked(e)
        })
    })
}

/// Payload for creating/updating an entry from the frontend.
#[derive(serde::Deserialize)]
pub struct EntryInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
}

#[tauri::command]
pub fn add_entry(input: EntryInput, state: State<AppState>) -> Result<Uuid, String> {
    with_unlocked(&state, |v| {
        let mut e = Entry::new(input.title, now_secs());
        e.username = input.username;
        e.password = input.password;
        e.url = input.url;
        e.notes = input.notes;
        e.tags = input.tags;
        let id = e.id;
        v.add(e);
        Ok(id)
    })
}

#[tauri::command]
pub fn update_entry(id: Uuid, input: EntryInput, state: State<AppState>) -> Result<(), String> {
    with_unlocked(&state, |v| {
        let existing = v.get(id).ok_or_else(|| "Entry not found".to_string())?;
        let mut e = existing.clone();
        e.title = input.title;
        e.username = input.username;
        e.password = input.password;
        e.url = input.url;
        e.notes = input.notes;
        e.tags = input.tags;
        e.updated_at = now_secs();
        v.update(id, e).map_err(map_err)
    })
}

#[tauri::command]
pub fn delete_entry(id: Uuid, state: State<AppState>) -> Result<(), String> {
    with_unlocked(&state, |v| v.delete(id).map_err(map_err))
}

#[tauri::command]
pub fn save_vault(state: State<AppState>) -> Result<(), String> {
    with_unlocked(&state, |v| v.save().map_err(map_err))
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod reveal_tests {
    use crate::ipc::ratelimit::RateLimiter;

    #[test]
    fn reveal_limiter_blocks_bulk_but_allows_human_pace() {
        let mut rl = RateLimiter::new(10_000, 30);
        // 30 reveals in the window are allowed (generous human pace).
        for i in 0..30 {
            assert!(rl.check("reveal", i), "reveal {i} should be allowed");
        }
        // The 31st within the window is blocked (a scripted dump).
        assert!(!rl.check("reveal", 31), "31st reveal should be blocked");
        // After the window slides, reveals are allowed again.
        assert!(
            rl.check("reveal", 10_001),
            "reveal after window should be allowed"
        );
    }
}
