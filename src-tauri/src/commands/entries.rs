use crate::dto::{EntryDetail, EntrySummary};
use crate::state::{AppState, VaultSlot};
use protec_core::{Entry, VaultError};
use tauri::State;
use uuid::Uuid;

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
    let mut inner = state.inner.lock().unwrap();
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
pub fn get_entry(id: Uuid, reveal: bool, state: State<AppState>) -> Result<EntryDetail, String> {
    with_unlocked(&state, |v| {
        let e = v.get(id).ok_or_else(|| "Entry not found".to_string())?;
        Ok(if reveal { EntryDetail::revealed(e) } else { EntryDetail::masked(e) })
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
pub fn add_entry(input: EntryInput, now: u64, state: State<AppState>) -> Result<Uuid, String> {
    with_unlocked(&state, |v| {
        let mut e = Entry::new(input.title, now);
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
pub fn update_entry(id: Uuid, input: EntryInput, now: u64, state: State<AppState>) -> Result<(), String> {
    with_unlocked(&state, |v| {
        let existing = v.get(id).ok_or_else(|| "Entry not found".to_string())?;
        let mut e = existing.clone();
        e.title = input.title;
        e.username = input.username;
        e.password = input.password;
        e.url = input.url;
        e.notes = input.notes;
        e.tags = input.tags;
        e.updated_at = now;
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
