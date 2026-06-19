use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totp {
    pub secret: String, // base32
    pub digits: u8,     // typically 6
    pub period: u16,    // seconds, typically 30
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl Drop for Totp {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
}

impl Drop for CustomField {
    fn drop(&mut self) {
        // `value` may hold a secret (API key, PIN, etc.); `name` is a label.
        self.value.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub totp: Option<Totp>,
    pub custom_fields: Vec<CustomField>,
    pub created_at: u64, // unix seconds
    pub updated_at: u64,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &self.notes)
            .field("tags", &self.tags)
            .field("totp", &self.totp)
            .field("custom_fields", &self.custom_fields)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        // Wipe secret-bearing fields. `totp` and `custom_fields` wipe themselves
        // via their own Drop impls when this struct's fields are dropped.
        self.password.zeroize();
        self.notes.zeroize();
    }
}

impl Entry {
    /// Create a new entry with a fresh UUID and the given timestamp.
    pub fn new(title: impl Into<String>, now: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            totp: None,
            custom_fields: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_entry_has_unique_ids_and_set_timestamps() {
        let a = Entry::new("GitHub", 100);
        let b = Entry::new("GitHub", 100);
        assert_ne!(a.id, b.id);
        assert_eq!(a.created_at, 100);
        assert_eq!(a.updated_at, 100);
    }

    #[test]
    fn entry_serde_round_trips() {
        let mut e = Entry::new("Email", 1);
        e.username = "me@example.com".into();
        e.totp = Some(Totp {
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
        });
        let bytes = bincode::serialize(&e).unwrap();
        let back: Entry = bincode::deserialize(&bytes).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn entry_still_clones_and_serde_round_trips_with_drop() {
        let mut e = Entry::new("Email", 1);
        e.password = "s3cr3t".into();
        e.notes = "note".into();
        e.totp = Some(Totp {
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
        });
        e.custom_fields = vec![CustomField {
            name: "pin".into(),
            value: "1234".into(),
        }];
        let cloned = e.clone();
        assert_eq!(e, cloned);
        let bytes = bincode::serialize(&e).unwrap();
        let back: Entry = bincode::deserialize(&bytes).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn totp_and_custom_field_implement_zeroize_on_drop() {
        // Compile-level proof the Drop impls exist and run without panic.
        {
            let _t = Totp {
                secret: "abc".into(),
                digits: 6,
                period: 30,
            };
            let _c = CustomField {
                name: "n".into(),
                value: "v".into(),
            };
        } // drop runs here, zeroizing secret/value — no panic, no double-free
    }
}
