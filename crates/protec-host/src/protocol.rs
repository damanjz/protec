use serde::{Deserialize, Serialize};

/// Messages the extension sends to the host (and the host relays to the app).
// The host relays raw JSON without deserializing; Request exists for the shared protocol contract and tests.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// "What logins do you have for this page?" origin is browser-supplied.
    Find { origin: String },
    /// "I just submitted this login." The app decides save vs update vs noop.
    Submit {
        origin: String,
        username: String,
        password: String,
    },
    /// "Are you there and unlocked?"
    Status,
}

/// Messages the app returns (relayed back through the host to the extension).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// A single credential the user approved for filling.
    Credential { username: String, password: String },
    /// No saved login matched this origin.
    NoMatch,
    /// The app is locked — the extension should prompt the user to unlock.
    Locked,
    /// The user denied the request, or it was rate-limited.
    Denied,
    /// A save/update completed (or was a no-op).
    Acknowledged,
    /// Status reply.
    Status { unlocked: bool },
    /// Something went wrong; message is user-safe.
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = Request::Find {
            origin: "https://github.com".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), r);
    }

    #[test]
    fn submit_round_trips() {
        let r = Request::Submit {
            origin: "https://github.com".into(),
            username: "octocat".into(),
            password: "pw".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), r);
    }

    #[test]
    fn response_variants_round_trip() {
        for r in [
            Response::Credential {
                username: "u".into(),
                password: "p".into(),
            },
            Response::NoMatch,
            Response::Locked,
            Response::Denied,
            Response::Acknowledged,
            Response::Status { unlocked: true },
            Response::Error {
                message: "x".into(),
            },
        ] {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), r);
        }
    }
}
