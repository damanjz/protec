use protec_core::Entry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Sent to the frontend for the list view. Deliberately carries NO password/TOTP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntrySummary {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
}

impl From<&Entry> for EntrySummary {
    fn from(e: &Entry) -> Self {
        Self {
            id: e.id,
            title: e.title.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            tags: e.tags.clone(),
        }
    }
}

/// Full detail, returned only on explicit get_entry. Password masked unless revealed
/// by the caller via the `reveal` flag in the command (see commands/entries.rs).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryDetail {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub has_totp: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

impl std::fmt::Debug for EntryDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryDetail")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("has_totp", &self.has_totp)
            .finish_non_exhaustive()
    }
}

impl EntryDetail {
    /// Build a detail with the password field masked (never sends plaintext).
    pub fn masked(e: &Entry) -> Self {
        Self {
            id: e.id,
            title: e.title.clone(),
            username: e.username.clone(),
            password: "••••••••".to_string(),
            url: e.url.clone(),
            notes: e.notes.clone(),
            tags: e.tags.clone(),
            has_totp: e.totp.is_some(),
            created_at: e.created_at,
            updated_at: e.updated_at,
        }
    }

    /// Build a detail with the real password (only for an explicit reveal action).
    pub fn revealed(e: &Entry) -> Self {
        let mut d = Self::masked(e);
        d.password = e.password.clone();
        d
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use protec_core::Entry;

    fn sample() -> Entry {
        let mut e = Entry::new("GitHub", 100);
        e.username = "octocat".into();
        e.password = "s3cr3t-pw".into();
        e
    }

    #[test]
    fn summary_never_contains_password() {
        let e = sample();
        let s = EntrySummary::from(&e);
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("s3cr3t-pw"),
            "summary leaked the password: {json}"
        );
        assert_eq!(s.title, "GitHub");
    }

    #[test]
    fn masked_detail_hides_password() {
        let e = sample();
        let d = EntryDetail::masked(&e);
        assert_ne!(d.password, "s3cr3t-pw");
        assert!(d.password.contains('•'));
    }

    #[test]
    fn revealed_detail_shows_password() {
        let e = sample();
        let d = EntryDetail::revealed(&e);
        assert_eq!(d.password, "s3cr3t-pw");
    }
}
