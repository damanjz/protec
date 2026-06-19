use serde::{Deserialize, Serialize};

/// The named pipe both the app (server) and host (client) use. Versioned so a
/// future breaking change can bump it.
pub const PIPE_NAME: &str = r"\\.\pipe\protec-ipc-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Find {
        origin: String,
    },
    Submit {
        origin: String,
        username: String,
        password: String,
    },
    Status,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Credential { username: String, password: String },
    NoMatch,
    Locked,
    Denied,
    Acknowledged,
    Status { unlocked: bool },
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_versioned() {
        assert!(PIPE_NAME.contains("protec-ipc-v1"));
    }

    #[test]
    fn request_round_trips() {
        let r = Request::Find {
            origin: "https://github.com".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&j).unwrap(), r);
    }
}
