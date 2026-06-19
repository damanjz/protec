use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totp {
    pub secret: String, // base32
    pub digits: u8,     // typically 6
    pub period: u16,    // seconds, typically 30
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
}
