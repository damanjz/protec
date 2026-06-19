use crate::match_domain::origin_matches;
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
        .map(|e| Match { id: e.id, username: e.username.clone(), password: e.password.clone() })
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
pub fn classify_submit(entries: &[Entry], origin: &str, username: &str, password: &str)
    -> SubmitOutcome
{
    let existing = entries.iter().find(|e| {
        !e.url.is_empty() && origin_matches(&e.url, origin) && e.username == username
    });
    match existing {
        None => SubmitOutcome::Save,
        Some(e) if e.password == password => SubmitOutcome::NoOp,
        Some(e) => SubmitOutcome::Update { id: e.id },
    }
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
