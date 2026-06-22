use serde::{Deserialize, Serialize};

/// The named pipe both the app (server) and host (client) use. Versioned so a
/// future breaking change can bump it.
pub const PIPE_NAME: &str = r"\\.\pipe\protec-ipc-v1";

/// The endpoint the app listens on and the host connects to.
/// Windows: a named pipe. Unix/macOS: a Unix-domain-socket path under the app
/// data dir. Kept here so app and host agree on one definition.
#[cfg(windows)]
pub fn endpoint() -> String {
    PIPE_NAME.to_string()
}

/// Unix socket path on macOS: `<data_dir>/Protec/protec-ipc-v1.sock`. Falls back
/// to a temp dir if HOME cannot be resolved.
///
/// IMPORTANT: the host crate (`crates/protec-host/src/pipe.rs`) derives this SAME
/// path independently (it cannot depend on the gui crate). Keep the two in sync:
/// HOME -> "Library/Application Support" -> "Protec" -> "protec-ipc-v1.sock".
#[cfg(target_os = "macos")]
pub fn endpoint() -> String {
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join("Library/Application Support"))
        .unwrap_or_else(std::env::temp_dir);
    base.join("Protec")
        .join("protec-ipc-v1.sock")
        .to_string_lossy()
        .into_owned()
}

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
    fn endpoint_is_nonempty_and_versioned() {
        let ep = endpoint();
        assert!(!ep.is_empty());
        assert!(ep.contains("protec-ipc-v1"));
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
