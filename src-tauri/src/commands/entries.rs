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

/// Apply an `EntryInput` onto an existing entry, returning the updated entry.
///
/// Blank-guard: a stored secret is never overwritten with an empty input. This is
/// defense-in-depth — even if the UI regresses or the command is invoked directly, an
/// empty `password`/`notes` field cannot silently destroy a saved value; it is treated
/// as "leave unchanged". To remove an entry, delete it. `title`, `username`, `url`, and
/// `tags` are legitimately clearable, so they always overwrite. `totp` and
/// `custom_fields` are preserved (carried over from `existing`).
fn apply_update(existing: &Entry, input: EntryInput, now: u64) -> Entry {
    let mut e = existing.clone();
    e.title = input.title;
    e.username = input.username;
    if !input.password.is_empty() {
        e.password = input.password;
    }
    e.url = input.url;
    if !input.notes.is_empty() {
        e.notes = input.notes;
    }
    e.tags = input.tags;
    e.updated_at = now;
    e
}

#[tauri::command]
pub fn update_entry(id: Uuid, input: EntryInput, state: State<AppState>) -> Result<(), String> {
    with_unlocked(&state, |v| {
        let existing = v.get(id).ok_or_else(|| "Entry not found".to_string())?;
        let e = apply_update(existing, input, now_secs());
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
mod update_tests {
    use super::*;

    fn base_input() -> EntryInput {
        EntryInput {
            title: "New Title".into(),
            username: "newuser".into(),
            password: "newpass".into(),
            url: "https://new.example".into(),
            notes: "new notes".into(),
            tags: vec!["a".into(), "b".into()],
        }
    }

    fn existing_entry() -> Entry {
        let mut e = Entry::new("Old Title".to_string(), 100);
        e.username = "olduser".into();
        e.password = "oldpass".into();
        e.url = "https://old.example".into();
        e.notes = "old notes".into();
        e.tags = vec!["x".into()];
        e
    }

    #[test]
    fn non_empty_password_replaces() {
        let e = apply_update(&existing_entry(), base_input(), 200);
        assert_eq!(e.password, "newpass");
        assert_eq!(e.title, "New Title");
        assert_eq!(e.username, "newuser");
        assert_eq!(e.notes, "new notes");
        assert_eq!(e.tags, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(e.updated_at, 200);
    }

    #[test]
    fn empty_password_preserves_existing() {
        let mut input = base_input();
        input.password = String::new();
        let e = apply_update(&existing_entry(), input, 200);
        // Blank-guard: the old password survives an empty input.
        assert_eq!(e.password, "oldpass");
        // Other fields still update normally.
        assert_eq!(e.title, "New Title");
    }

    #[test]
    fn empty_notes_preserves_existing() {
        let mut input = base_input();
        input.notes = String::new();
        let e = apply_update(&existing_entry(), input, 200);
        assert_eq!(e.notes, "old notes");
    }

    #[test]
    fn clearable_fields_can_be_emptied() {
        let mut input = base_input();
        input.url = String::new();
        input.username = String::new();
        input.tags = vec![];
        let e = apply_update(&existing_entry(), input, 200);
        // url/username/tags are legitimately clearable.
        assert_eq!(e.url, "");
        assert_eq!(e.username, "");
        assert!(e.tags.is_empty());
        // password updated normally (non-empty input); not the focus of this test.
        assert_eq!(e.password, "newpass");
    }

    #[test]
    fn both_empty_password_stays_empty() {
        // A legitimately password-less entry, edited with an empty password field,
        // stays empty (the blank-guard returns the existing value, which is "").
        let mut existing = existing_entry();
        existing.password = String::new();
        let mut input = base_input();
        input.password = String::new();
        let e = apply_update(&existing, input, 200);
        assert_eq!(e.password, "");
    }

    #[test]
    fn totp_and_custom_fields_are_preserved() {
        let mut existing = existing_entry();
        existing.totp = Some(protec_core::Totp {
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
        });
        existing.custom_fields = vec![protec_core::CustomField {
            name: "PIN".into(),
            value: "1234".into(),
        }];
        let e = apply_update(&existing, base_input(), 200);
        assert!(e.totp.is_some());
        // `Entry`/`Totp` impl Drop (zeroize), so borrow rather than move out.
        assert_eq!(e.totp.as_ref().unwrap().secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(e.custom_fields.len(), 1);
        assert_eq!(e.custom_fields[0].name, "PIN");
    }

    #[test]
    fn id_and_created_at_are_unchanged() {
        let existing = existing_entry();
        let id = existing.id;
        let created = existing.created_at;
        let e = apply_update(&existing, base_input(), 200);
        assert_eq!(e.id, id);
        assert_eq!(e.created_at, created);
    }
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
