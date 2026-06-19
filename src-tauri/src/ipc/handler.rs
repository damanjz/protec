use crate::ipc::protocol::{Request, Response};
use crate::match_domain::origin_matches;
use crate::state::{AppState, VaultSlot};
use protec_core::Entry;

/// A credential candidate found for an origin.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub id: uuid::Uuid,
    pub username: String,
    pub password: String,
}

/// All entries whose URL matches the page origin (registrable-domain match).
pub fn find_matches(entries: &[Entry], origin: &str) -> Vec<Match> {
    entries
        .iter()
        .filter(|e| !e.url.is_empty() && origin_matches(&e.url, origin))
        .map(|e| Match {
            id: e.id,
            username: e.username.clone(),
            password: e.password.clone(),
        })
        .collect()
}

/// What a submitted login means relative to the current vault.
#[derive(Debug, Clone, PartialEq)]
pub enum SubmitOutcome {
    /// No entry for this origin+username — offer to save a new one.
    Save,
    /// An entry exists with a different password — offer to update it.
    Update { id: uuid::Uuid },
    /// An entry already has this exact username+password — do nothing.
    NoOp,
}

/// Decide save vs update vs noop. The extension never knew the stored password;
/// this comparison happens here, in Rust, where the secret lives.
pub fn classify_submit(
    entries: &[Entry],
    origin: &str,
    username: &str,
    password: &str,
) -> SubmitOutcome {
    let existing = entries
        .iter()
        .find(|e| !e.url.is_empty() && origin_matches(&e.url, origin) && e.username == username);
    match existing {
        None => SubmitOutcome::Save,
        Some(e) if e.password == password => SubmitOutcome::NoOp,
        Some(e) => SubmitOutcome::Update { id: e.id },
    }
}

/// Process one request against app state. `confirm` is an async gate the caller
/// supplies (it raises the desktop prompt and resolves to true=Allow/false=Deny).
/// Returns the Response to send back over the pipe.
pub async fn process<F, Fut>(state: &AppState, req: Request, confirm: F) -> Response
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    match req {
        Request::Status => {
            let unlocked = matches!(state.lock().slot, VaultSlot::Unlocked(_));
            Response::Status { unlocked }
        }
        Request::Find { origin } => {
            if crate::match_domain::registrable_domain(&origin).is_none() {
                return Response::NoMatch;
            }
            let matches = {
                let inner = state.lock();
                match &inner.slot {
                    VaultSlot::Locked => return Response::Locked,
                    VaultSlot::Unlocked(v) => find_matches(v.list_entries(), &origin),
                }
            };
            if matches.is_empty() {
                return Response::NoMatch;
            }
            if !confirm(format!("Fill login for {origin}?")).await {
                return Response::Denied;
            }
            let m = &matches[0];
            Response::Credential {
                username: m.username.clone(),
                password: m.password.clone(),
            }
        }
        Request::Submit {
            origin,
            username,
            password,
        } => {
            if crate::match_domain::registrable_domain(&origin).is_none() {
                return Response::Acknowledged;
            }
            let outcome = {
                let inner = state.lock();
                match &inner.slot {
                    VaultSlot::Locked => return Response::Locked,
                    VaultSlot::Unlocked(v) => {
                        classify_submit(v.list_entries(), &origin, &username, &password)
                    }
                }
            };
            // Submit always returns Acknowledged (except when Locked) so a page
            // cannot use the response to learn whether a password matched, an
            // entry exists, or the user approved a save/update.
            match outcome {
                SubmitOutcome::NoOp => Response::Acknowledged,
                SubmitOutcome::Save => {
                    if !confirm(format!("Save new login for {origin}?")).await {
                        return Response::Acknowledged;
                    }
                    let mut inner = state.lock();
                    if let VaultSlot::Unlocked(v) = &mut inner.slot {
                        let title = crate::match_domain::registrable_domain(&origin)
                            .unwrap_or_else(|| origin.clone());
                        let mut e = Entry::new(title, now_secs());
                        e.url = origin;
                        e.username = username;
                        e.password = password;
                        v.add(e);
                        if v.save().is_err() {
                            return Response::Error {
                                message: "Failed to save".into(),
                            };
                        }
                        Response::Acknowledged
                    } else {
                        Response::Locked
                    }
                }
                SubmitOutcome::Update { id } => {
                    if !confirm(format!("Update password for {origin}?")).await {
                        return Response::Acknowledged;
                    }
                    let mut inner = state.lock();
                    if let VaultSlot::Unlocked(v) = &mut inner.slot {
                        if let Some(existing) = v.get(id) {
                            let mut updated = existing.clone();
                            updated.password = password;
                            updated.updated_at = now_secs();
                            let _ = v.update(id, updated);
                            if v.save().is_err() {
                                return Response::Error {
                                    message: "Failed to save".into(),
                                };
                            }
                        }
                        Response::Acknowledged
                    } else {
                        Response::Locked
                    }
                }
            }
        }
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, url: &str, user: &str, pw: &str) -> Entry {
        let mut e = Entry::new(title, 0);
        e.url = url.into();
        e.username = user.into();
        e.password = pw.into();
        e
    }

    #[test]
    fn find_matches_by_registrable_domain() {
        let entries = vec![
            entry("GitHub", "https://github.com", "octocat", "pw1"),
            entry("Paypal", "https://paypal.com", "me", "pw2"),
        ];
        let got = find_matches(&entries, "https://www.github.com/login");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].username, "octocat");
    }

    #[test]
    fn find_ignores_lookalike() {
        let entries = vec![entry("GitHub", "https://github.com", "octocat", "pw1")];
        assert!(find_matches(&entries, "https://github.com.evil.com").is_empty());
    }

    #[test]
    fn classify_new_username_is_save() {
        let entries = vec![entry("GitHub", "https://github.com", "octocat", "pw1")];
        assert_eq!(
            classify_submit(&entries, "https://github.com", "newuser", "pw"),
            SubmitOutcome::Save
        );
    }

    #[test]
    fn classify_changed_password_is_update() {
        let entries = vec![entry("GitHub", "https://github.com", "octocat", "old")];
        let id = entries[0].id;
        assert_eq!(
            classify_submit(&entries, "https://www.github.com", "octocat", "new"),
            SubmitOutcome::Update { id }
        );
    }

    #[test]
    fn classify_identical_is_noop() {
        let entries = vec![entry("GitHub", "https://github.com", "octocat", "same")];
        assert_eq!(
            classify_submit(&entries, "https://github.com", "octocat", "same"),
            SubmitOutcome::NoOp
        );
    }
}
