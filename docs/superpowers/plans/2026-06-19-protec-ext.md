# protec-ext Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `protec-ext` — a Chromium + Firefox browser extension with autofill (fill/save/update) for Protec, connected to the desktop app via native messaging over a Windows named pipe, with the desktop app as the gatekeeper that holds the only unlocked vault.

**Architecture:** Three pieces. (1) `protec-host`: a thin Rust native-messaging broker the browser launches; it relays framed JSON requests to the running desktop app over a named pipe. (2) `protec-gui` gains a named-pipe server, a strict registrable-domain matcher (in Rust), and a confirmation prompt — it is the gatekeeper that matches, confirms, and reads/writes the vault. (3) `protec-extension`: a content script that detects forms + reports the browser-supplied origin, and a background script that speaks native messaging. The vault key never leaves the app; the extension only ever receives single, confirmed, origin-matched credentials.

**Tech Stack:** Rust (`protec-host` binary + `protec-gui` additions), `tokio` named pipes (already in the tree via Tauri), `serde`/`serde_json`, `psl` crate (public-suffix list) for domain matching. Extension: TypeScript + Vite, Vitest for `forms.ts`. Manifest V3 (Chromium) and a Firefox manifest.

**Environment (verified):** Rust 1.96 (cargo at `~/.cargo/bin`; PowerShell `$env:Path += ";$env:USERPROFILE\.cargo\bin"`). Node + npm present. Tauri CLI 2.11 installed. Use `--manifest-path "<repo>\Cargo.toml"` for cargo if `-p` won't resolve. Git identity: `-c user.name="dev" -c user.email="daman.apuri2000@gmail.com"`. This runs in a dedicated worktree created before execution.

**Existing API this builds on (`protec-core`):** `UnlockedVault::{ list_entries() -> &[Entry], get(Uuid) -> Option<&Entry>, add(Entry), update(Uuid, Entry) -> Result<(),VaultError> }`. `Entry` has public fields `id, title, username, password, url, notes, tags, totp, custom_fields, created_at, updated_at`, and `Entry::new(title, now)`. The GUI's `AppState` holds `VaultSlot { Locked, Unlocked(UnlockedVault) }` behind a mutex with a poison-recovering `AppState::lock()` helper.

---

## File Structure

```
Protec/
├── Cargo.toml                              # workspace — add "crates/protec-host"
├── crates/
│   ├── protec-core/                        # (unchanged)
│   └── protec-host/                        # NEW binary crate
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                      # native-messaging loop
│           ├── nativemsg.rs                 # 4-byte LE length framing over stdin/stdout
│           ├── protocol.rs                  # request/response message types (serde)
│           └── pipe.rs                       # connect to GUI named pipe, relay
├── src-tauri/src/
│   ├── match_domain.rs                      # NEW: registrable-domain matcher (psl)
│   ├── ipc/
│   │   ├── mod.rs                           # NEW
│   │   ├── protocol.rs                      # NEW: shared request/response (mirrors host)
│   │   ├── server.rs                        # NEW: named-pipe server loop
│   │   └── handler.rs                       # NEW: match + confirm + read/write vault
│   └── (main.rs gains: mod match_domain; mod ipc; spawn server)
├── src/lib/components/
│   └── ConfirmPrompt.svelte                 # NEW: Allow/Deny confirmation UI
└── extension/                               # NEW browser extension
    ├── package.json
    ├── vite.config.ts
    ├── tsconfig.json
    ├── src/
    │   ├── forms.ts                          # form detection (heavily tested)
    │   ├── forms.test.ts
    │   ├── protocol.ts                       # TS mirror of the message schema
    │   ├── content.ts                        # detect forms, report origin, fill, capture
    │   ├── background.ts                     # native-messaging port routing
    │   ├── popup.html
    │   └── popup.ts
    ├── manifest.chromium.json
    ├── manifest.firefox.json
    └── scripts/
        └── register-host.ps1                 # writes native-messaging host manifests
```

---

## Phase A — Domain matcher (in protec-gui, pure & testable, no IPC yet)

### Task 1: Add the `psl` dependency and registrable-domain extraction

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Create: `src-tauri/src/match_domain.rs`
- Modify: `src-tauri/src/main.rs` (add `mod match_domain;`)

- [ ] **Step 1: Add the dependency**

In `src-tauri/Cargo.toml` `[dependencies]`, add:
```toml
psl = "2"
url = "2"
```

- [ ] **Step 2: Write the failing test (registrable domain extraction)**

Create `src-tauri/src/match_domain.rs`:
```rust
//! Strict registrable-domain matching for anti-phishing autofill.
//! The page origin is supplied by the browser, never by page content.

/// Extract the registrable domain (eTLD+1) from a URL or origin string.
/// e.g. "https://www.github.com/login" -> "github.com",
///      "https://a.b.example.co.uk" -> "example.co.uk".
/// Returns None if there is no host or no registrable domain.
pub fn registrable_domain(url_or_origin: &str) -> Option<String> {
    // Accept bare hosts too (e.g. "github.com") by trying to parse, then
    // falling back to treating the input as a host.
    let host = match url::Url::parse(url_or_origin) {
        Ok(u) => u.host_str().map(|h| h.to_string()),
        Err(_) => Some(url_or_origin.trim().to_string()),
    }?;
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    let domain = psl::domain_str(&host)?;
    Some(domain.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_domain() {
        assert_eq!(registrable_domain("https://github.com/login").as_deref(), Some("github.com"));
    }

    #[test]
    fn extracts_from_subdomain() {
        assert_eq!(registrable_domain("https://www.github.com").as_deref(), Some("github.com"));
        assert_eq!(registrable_domain("https://accounts.github.com").as_deref(), Some("github.com"));
    }

    #[test]
    fn handles_multi_part_suffix() {
        assert_eq!(registrable_domain("https://a.b.example.co.uk").as_deref(), Some("example.co.uk"));
    }

    #[test]
    fn accepts_bare_host() {
        assert_eq!(registrable_domain("github.com").as_deref(), Some("github.com"));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(registrable_domain(""), None);
    }
}
```

- [ ] **Step 3: Add `mod match_domain;` to `src-tauri/src/main.rs`** (next to the other `mod` lines).

- [ ] **Step 4: Run the tests**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-gui match_domain::`
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/src/match_domain.rs src-tauri/src/main.rs
git commit -m "feat(gui): registrable-domain extraction (psl) for anti-phishing"
```

### Task 2: The matching predicate (anti-phishing core)

**Files:**
- Modify: `src-tauri/src/match_domain.rs`

- [ ] **Step 1: Write the failing tests (the security-critical ones)**

Append to `match_domain.rs` (above the `#[cfg(test)]` block):
```rust
/// True if a saved entry URL should be offered for the given page origin.
/// Both are reduced to their registrable domain and compared exactly — so
/// `github.com` matches `www.github.com` but NOT `github.com.evil.com`.
pub fn origin_matches(saved_url: &str, page_origin: &str) -> bool {
    match (registrable_domain(saved_url), registrable_domain(page_origin)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}
```

Add to the `tests` module:
```rust
    #[test]
    fn matches_same_registrable_domain() {
        assert!(origin_matches("https://github.com", "https://www.github.com/login"));
        assert!(origin_matches("https://accounts.github.com", "https://github.com"));
    }

    #[test]
    fn rejects_lookalike_suffix_attack() {
        // The classic phishing vector — must NOT match.
        assert!(!origin_matches("https://github.com", "https://github.com.evil.com"));
    }

    #[test]
    fn rejects_typosquat() {
        assert!(!origin_matches("https://github.com", "https://g1thub.com"));
    }

    #[test]
    fn rejects_unrelated_domain() {
        assert!(!origin_matches("https://github.com", "https://paypal.com"));
    }

    #[test]
    fn rejects_when_either_side_unparseable() {
        assert!(!origin_matches("", "https://github.com"));
        assert!(!origin_matches("https://github.com", ""));
    }
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-gui match_domain::`
Expected: 10 tests PASS — especially `rejects_lookalike_suffix_attack`.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/match_domain.rs
git commit -m "feat(gui): strict origin matching with phishing-rejection tests"
```

---

## Phase B — Shared protocol + native-messaging framing (host crate)

### Task 3: Scaffold the `protec-host` crate + the message protocol

**Files:**
- Create: `crates/protec-host/Cargo.toml`, `crates/protec-host/src/main.rs`, `crates/protec-host/src/protocol.rs`
- Modify: root `Cargo.toml` (add member)

- [ ] **Step 1: Add the crate to the workspace**

In root `Cargo.toml`, change members to:
`members = ["crates/protec-core", "crates/protec-host", "src-tauri"]`

- [ ] **Step 2: Create `crates/protec-host/Cargo.toml`**

```toml
[package]
name = "protec-host"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 3: Write the protocol with a round-trip test**

Create `crates/protec-host/src/protocol.rs`:
```rust
use serde::{Deserialize, Serialize};

/// Messages the extension sends to the host (and the host relays to the app).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// "What logins do you have for this page?" origin is browser-supplied.
    Find { origin: String },
    /// "I just submitted this login." The app decides save vs update vs noop.
    Submit { origin: String, username: String, password: String },
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
        let r = Request::Find { origin: "https://github.com".into() };
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
            Response::Credential { username: "u".into(), password: "p".into() },
            Response::NoMatch,
            Response::Locked,
            Response::Denied,
            Response::Acknowledged,
            Response::Status { unlocked: true },
            Response::Error { message: "x".into() },
        ] {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), r);
        }
    }
}
```

- [ ] **Step 4: Create a minimal `main.rs` so the crate builds**

Create `crates/protec-host/src/main.rs`:
```rust
mod nativemsg;
mod pipe;
mod protocol;

fn main() {
    // Real loop wired in Task 5.
    eprintln!("protec-host: started");
}
```
> Note: `nativemsg` and `pipe` are created in Tasks 4 and 6. To keep this task self-contained and compiling, create empty stub files now: `crates/protec-host/src/nativemsg.rs` containing `// implemented in Task 4` and `crates/protec-host/src/pipe.rs` containing `// implemented in Task 6`.

- [ ] **Step 5: Run the protocol test + build**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-host protocol::`
Expected: 3 tests PASS.
Run: `cargo build --manifest-path "<repo>\Cargo.toml" -p protec-host`
Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/protec-host/
git commit -m "feat(host): scaffold protec-host crate + native-messaging protocol"
```

### Task 4: Native-messaging framing (4-byte length prefix)

**Files:**
- Modify: `crates/protec-host/src/nativemsg.rs`

- [ ] **Step 1: Write the framing with a round-trip test**

Replace `crates/protec-host/src/nativemsg.rs` with:
```rust
use std::io::{Read, Write};

/// Browser native messaging frames each message as a 4-byte little-endian
/// length prefix followed by that many bytes of UTF-8 JSON.
/// Chrome caps messages at 1 MB inbound; we enforce a sane limit.
const MAX_MESSAGE: u32 = 64 * 1024 * 1024;

/// Read one framed message from `r`. Returns None on clean EOF (browser closed).
pub fn read_message(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one framed message to `w`.
pub fn write_message(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    let len = body.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_then_read_round_trips() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"{\"hello\":1}").unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(got, b"{\"hello\":1}");
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn oversize_length_is_rejected() {
        let mut bytes = (u32::MAX).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"x");
        let mut cur = Cursor::new(bytes);
        assert!(read_message(&mut cur).is_err());
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-host nativemsg::`
Expected: 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-host/src/nativemsg.rs
git commit -m "feat(host): native-messaging length-prefixed framing"
```

---

## Phase C — Named-pipe server + gatekeeper handler (in protec-gui)

> The pipe name is a constant shared by host and app. Use
> `\\.\pipe\protec-ipc-v1`. Define it once in `ipc/protocol.rs` and have the
> host hardcode the same literal (the host can't depend on the gui crate).

### Task 5: IPC protocol + module in protec-gui (mirror of host protocol)

**Files:**
- Create: `src-tauri/src/ipc/mod.rs`, `src-tauri/src/ipc/protocol.rs`
- Modify: `src-tauri/src/main.rs`, `src-tauri/Cargo.toml`

- [ ] **Step 1: Ensure tokio with named-pipe + io features**

In `src-tauri/Cargo.toml` `[dependencies]`, ensure tokio is present with features (Tauri brings tokio, but make the features explicit for our use):
```toml
tokio = { version = "1", features = ["net", "io-util", "rt", "macros", "sync"] }
```

- [ ] **Step 2: Create the IPC protocol (mirror of host's protocol.rs)**

Create `src-tauri/src/ipc/protocol.rs`:
```rust
use serde::{Deserialize, Serialize};

/// The named pipe both the app (server) and host (client) use. Versioned so a
/// future breaking change can bump it.
pub const PIPE_NAME: &str = r"\\.\pipe\protec-ipc-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Find { origin: String },
    Submit { origin: String, username: String, password: String },
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
        let r = Request::Find { origin: "https://github.com".into() };
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&j).unwrap(), r);
    }
}
```

- [ ] **Step 3: Create the ipc module file**

Create `src-tauri/src/ipc/mod.rs`:
```rust
pub mod handler;
pub mod protocol;
pub mod server;
```
> Note: `handler` and `server` are created in Tasks 6–7. Create stubs now so this compiles: `src-tauri/src/ipc/handler.rs` with `// implemented in Task 6` and `src-tauri/src/ipc/server.rs` with `// implemented in Task 7`. (Empty modules are valid.)

- [ ] **Step 4: Add `mod ipc;` to main.rs**

Add `mod ipc;` to `src-tauri/src/main.rs` with the other module declarations.

- [ ] **Step 5: Test + build**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-gui ipc::protocol::`
Expected: 2 tests PASS.
Run: `cargo build --manifest-path "<repo>\Cargo.toml" -p protec-gui`
Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/src/ipc/ src-tauri/src/main.rs
git commit -m "feat(gui): IPC protocol + named-pipe constant"
```

### Task 6: The gatekeeper handler (match + classify save/update; pure logic)

**Files:**
- Modify: `src-tauri/src/ipc/handler.rs`

> The handler's vault-touching decisions are testable as pure functions over a
> slice of entries, separate from the async pipe and the confirmation UI. The
> confirmation step is injected as a closure so tests don't need a window.

- [ ] **Step 1: Write the failing tests (find + classify)**

Replace `src-tauri/src/ipc/handler.rs` with:
```rust
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
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-gui ipc::handler::`
Expected: 5 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/ipc/handler.rs
git commit -m "feat(gui): gatekeeper find + save/update classification (tested)"
```

### Task 6b: Per-origin rate limiter (abuse protection)

**Files:**
- Create: `src-tauri/src/ipc/ratelimit.rs`
- Modify: `src-tauri/src/ipc/mod.rs`

A malicious page could spam fill/submit requests to fatigue the user into
clicking Allow. Cap requests per origin within a sliding window. Pure and
testable; time is injected so tests are deterministic.

- [ ] **Step 1: Write the failing tests**

Create `src-tauri/src/ipc/ratelimit.rs`:
```rust
use std::collections::HashMap;

/// Sliding-window rate limiter keyed by origin. Not time-aware on its own —
/// the caller passes a monotonic "now" in milliseconds so it stays testable.
pub struct RateLimiter {
    window_ms: u64,
    max_in_window: usize,
    hits: HashMap<String, Vec<u64>>,
}

impl RateLimiter {
    pub fn new(window_ms: u64, max_in_window: usize) -> Self {
        Self { window_ms, max_in_window, hits: HashMap::new() }
    }

    /// Record a request for `origin` at time `now_ms`. Returns true if allowed,
    /// false if the origin has exceeded `max_in_window` within the window.
    pub fn check(&mut self, origin: &str, now_ms: u64) -> bool {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let v = self.hits.entry(origin.to_string()).or_default();
        v.retain(|&t| t >= cutoff);
        if v.len() >= self.max_in_window {
            return false;
        }
        v.push(now_ms);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit() {
        let mut rl = RateLimiter::new(1000, 3);
        assert!(rl.check("a", 0));
        assert!(rl.check("a", 10));
        assert!(rl.check("a", 20));
        assert!(!rl.check("a", 30)); // 4th within window → blocked
    }

    #[test]
    fn window_slides() {
        let mut rl = RateLimiter::new(1000, 2);
        assert!(rl.check("a", 0));
        assert!(rl.check("a", 500));
        assert!(!rl.check("a", 600));     // blocked
        assert!(rl.check("a", 1600));     // first hit aged out → allowed again
    }

    #[test]
    fn origins_are_independent() {
        let mut rl = RateLimiter::new(1000, 1);
        assert!(rl.check("a", 0));
        assert!(!rl.check("a", 1));
        assert!(rl.check("b", 1)); // different origin unaffected
    }
}
```

- [ ] **Step 2: Register the module**

In `src-tauri/src/ipc/mod.rs`, add `pub mod ratelimit;` to the module list.

- [ ] **Step 3: Run the tests**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-gui ipc::ratelimit::`
Expected: 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/ipc/ratelimit.rs src-tauri/src/ipc/mod.rs
git commit -m "feat(gui): per-origin rate limiter for autofill abuse protection"
```

> The limiter is wired into the server in Task 7 Step 4a: a single
> `Mutex<RateLimiter>` in managed state, checked at the top of `handle_conn`
> before processing; on `false`, return `Response::Denied` without prompting.

### Task 7: Named-pipe server wired to state + confirmation, spawned at startup

**Files:**
- Modify: `src-tauri/src/ipc/server.rs`, `src-tauri/src/ipc/handler.rs`, `src-tauri/src/main.rs`
- Create: `src/lib/components/ConfirmPrompt.svelte`
- Modify: `src/App.svelte` (mount the confirm prompt + a Tauri event listener)

- [ ] **Step 1: Add an async request-processing function to handler.rs**

Append to `src-tauri/src/ipc/handler.rs`:
```rust
use crate::ipc::protocol::{Request, Response};
use crate::state::{AppState, VaultSlot};

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
            // Snapshot matches under the lock, then drop it before awaiting.
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
            Response::Credential { username: m.username.clone(), password: m.password.clone() }
        }
        Request::Submit { origin, username, password } => {
            let outcome = {
                let inner = state.lock();
                match &inner.slot {
                    VaultSlot::Locked => return Response::Locked,
                    VaultSlot::Unlocked(v) => {
                        classify_submit(v.list_entries(), &origin, &username, &password)
                    }
                }
            };
            match outcome {
                SubmitOutcome::NoOp => Response::Acknowledged,
                SubmitOutcome::Save => {
                    if !confirm(format!("Save new login for {origin}?")).await {
                        return Response::Denied;
                    }
                    let mut inner = state.lock();
                    if let VaultSlot::Unlocked(v) = &mut inner.slot {
                        let mut e = Entry::new(origin.clone(), now_secs());
                        e.url = origin;
                        e.username = username;
                        e.password = password;
                        v.add(e);
                        let _ = v.save();
                        Response::Acknowledged
                    } else {
                        Response::Locked
                    }
                }
                SubmitOutcome::Update { id } => {
                    if !confirm(format!("Update password for {origin}?")).await {
                        return Response::Denied;
                    }
                    let mut inner = state.lock();
                    if let VaultSlot::Unlocked(v) = &mut inner.slot {
                        if let Some(existing) = v.get(id) {
                            let mut updated = existing.clone();
                            updated.password = password;
                            updated.updated_at = now_secs();
                            let _ = v.update(id, updated);
                            let _ = v.save();
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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
```
> Note: this references `state` so add `use` lines at the top as shown. The `find_matches`/`classify_submit`/`Match`/`SubmitOutcome` already exist in this file from Task 6.

- [ ] **Step 2: Create the named-pipe server**

Replace `src-tauri/src/ipc/server.rs` with:
```rust
use crate::ipc::handler::process;
use crate::ipc::protocol::{Request, Response, PIPE_NAME};
use crate::state::AppState;
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::oneshot;

/// Spawn the named-pipe server. Each client connection is handled, one request
/// per connection (the extension opens a fresh connection per request).
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let server = match ServerOptions::new().create(PIPE_NAME) {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            };
            if server.connect().await.is_err() {
                continue;
            }
            let app2 = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = handle_conn(app2, server).await;
            });
        }
    });
}

async fn handle_conn(app: AppHandle, mut server: NamedPipeServer) -> std::io::Result<()> {
    // Read a single length-prefixed JSON request (same framing as native msg).
    let mut len = [0u8; 4];
    server.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > 16 * 1024 * 1024 {
        return Ok(());
    }
    let mut body = vec![0u8; n];
    server.read_exact(&mut body).await?;

    let req: Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            write_response(&mut server, &Response::Error { message: e.to_string() }).await?;
            return Ok(());
        }
    };

    // Abuse protection: rate-limit per origin before doing anything else.
    // Status requests carry no origin and are not rate-limited.
    let origin = match &req {
        Request::Find { origin } | Request::Submit { origin, .. } => Some(origin.clone()),
        Request::Status => None,
    };
    if let Some(origin) = origin {
        let now_ms = now_ms();
        let limiter = app.state::<RateLimitState>();
        let allowed = limiter.0.lock().unwrap().check(&origin, now_ms);
        if !allowed {
            write_response(&mut server, &Response::Denied).await?;
            return Ok(());
        }
    }

    let state = app.state::<AppState>();
    let app_for_confirm = app.clone();
    let resp = process(state.inner(), req, move |prompt: String| {
        let app = app_for_confirm.clone();
        async move { request_confirmation(app, prompt).await }
    })
    .await;

    write_response(&mut server, &resp).await
}

async fn write_response(server: &mut NamedPipeServer, resp: &Response) -> std::io::Result<()> {
    let body = serde_json::to_vec(resp).unwrap_or_default();
    server.write_all(&(body.len() as u32).to_le_bytes()).await?;
    server.write_all(&body).await?;
    server.flush().await
}

/// Raise the desktop confirmation prompt and await Allow/Deny. Emits an event
/// the frontend listens for; the frontend replies by resolving a channel.
async fn request_confirmation(app: AppHandle, prompt: String) -> bool {
    let (tx, rx) = oneshot::channel::<bool>();
    let pending = app.state::<PendingConfirm>();
    {
        let mut guard = pending.0.lock().unwrap();
        *guard = Some(tx);
    }
    // Bring the window forward and ask.
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.set_focus();
    }
    let _ = app.emit("protec://confirm", prompt);
    rx.await.unwrap_or(false)
}

/// Holds the in-flight confirmation responder. Registered as managed state.
pub struct PendingConfirm(pub std::sync::Mutex<Option<oneshot::Sender<bool>>>);

impl Default for PendingConfirm {
    fn default() -> Self {
        Self(std::sync::Mutex::new(None))
    }
}

/// The per-origin rate limiter, registered as managed state.
pub struct RateLimitState(pub std::sync::Mutex<crate::ipc::ratelimit::RateLimiter>);

impl Default for RateLimitState {
    fn default() -> Self {
        // Allow up to 5 autofill requests per origin per 10 seconds.
        Self(std::sync::Mutex::new(crate::ipc::ratelimit::RateLimiter::new(10_000, 5)))
    }
}

/// Monotonic-ish wall-clock millis for the limiter.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
```
> Note: remove any `use` line the compiler reports as unused. Keep the file to
> exactly the items shown — no module-level statements.

- [ ] **Step 3: Add a Tauri command for the frontend to answer the prompt**

Append to `src-tauri/src/ipc/server.rs`:
```rust
/// Called by the frontend to answer the current confirmation prompt.
#[tauri::command]
pub fn answer_confirm(allow: bool, pending: tauri::State<PendingConfirm>) {
    if let Some(tx) = pending.0.lock().unwrap().take() {
        let _ = tx.send(allow);
    }
}
```

- [ ] **Step 4: Register state, command, and spawn the server in main.rs**

In `src-tauri/src/main.rs`:
- Add `use ipc::server::{PendingConfirm, RateLimitState};`
- In the Tauri builder, `.manage(PendingConfirm::default())` and
  `.manage(RateLimitState::default())`.
- Add `ipc::server::answer_confirm` to the `generate_handler!` list.
- After `.manage(...)` and before `.run(...)`, add a `.setup(|app| { ipc::server::spawn(app.handle().clone()); Ok(()) })` step.

(Exact builder edit — adapt to current structure: the builder already has `.manage(app_state)`, `.invoke_handler(generate_handler![...])`. Add `.manage(PendingConfirm::default())`, append the command, and add `.setup(...)`.)

- [ ] **Step 5: Create the ConfirmPrompt.svelte component**

Create `src/lib/components/ConfirmPrompt.svelte`:
```svelte
<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { invoke } from "@tauri-apps/api/core";

  let prompt: string | null = null;
  let unlisten: UnlistenFn | null = null;

  async function answer(allow: boolean) {
    prompt = null;
    await invoke("answer_confirm", { allow });
  }

  onMount(async () => {
    unlisten = await listen<string>("protec://confirm", (e) => {
      prompt = e.payload;
    });
    window.addEventListener("keydown", onKey);
  });
  onDestroy(() => {
    if (unlisten) unlisten();
    window.removeEventListener("keydown", onKey);
  });

  function onKey(e: KeyboardEvent) {
    if (prompt === null) return;
    if (e.key === "Enter") { e.preventDefault(); answer(true); }
    else if (e.key === "Escape") { e.preventDefault(); answer(false); }
  }
</script>

{#if prompt !== null}
  <div class="overlay" role="dialog" aria-label="Confirm request">
    <div class="box">
      <p class="msg">{prompt}</p>
      <p class="hint">A browser extension is requesting access to your vault.</p>
      <div class="row">
        <button class="allow" on:click={() => answer(true)}>Allow ↵</button>
        <button on:click={() => answer(false)}>Deny Esc</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); display: flex;
    justify-content: center; align-items: center; z-index: 100; }
  .box { width: 360px; background: var(--bg-elev); border: 1px solid var(--accent);
    border-radius: 10px; padding: 18px; }
  .msg { color: var(--text); font-size: 14px; margin: 0 0 6px; }
  .hint { color: var(--text-dim); font-size: 11px; margin: 0 0 14px; }
  .row { display: flex; gap: 8px; }
  .row button { flex: 1; padding: 8px; background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; cursor: pointer; }
  .allow { background: var(--accent); color: #fff; border: 0; }
</style>
```

- [ ] **Step 6: Mount ConfirmPrompt globally in App.svelte**

In `src/App.svelte`, import and render `<ConfirmPrompt />` once at the top level (outside the loading/lock/main branches), so it can appear over any screen:
```svelte
  import ConfirmPrompt from "./lib/components/ConfirmPrompt.svelte";
```
and in the markup, after the `{#if}...{/if}` block, add:
```svelte
<ConfirmPrompt />
```

- [ ] **Step 7: Build (compile-check both sides)**

Run: `cargo build --manifest-path "<repo>\Cargo.toml" -p protec-gui`
Expected: compiles. (Fix the stray-line correction from Step 2 if the compiler complains about module-level statements.)
Run: `npm run build`
Expected: `dist/` builds.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/ipc/server.rs src-tauri/src/ipc/handler.rs src-tauri/src/main.rs src/lib/components/ConfirmPrompt.svelte src/App.svelte
git commit -m "feat(gui): named-pipe server + desktop confirmation prompt"
```

---

## Phase D — Host broker wiring

### Task 8: Host connects to the pipe and relays a request

**Files:**
- Modify: `crates/protec-host/src/pipe.rs`, `crates/protec-host/src/main.rs`, `crates/protec-host/Cargo.toml`

- [ ] **Step 1: Confirm no new deps are needed**

No new dependencies are required for the host's pipe client: on Windows a named
pipe client is opened like a file via `std::fs::OpenOptions`, so `pipe.rs` uses
only `std`. `crates/protec-host/Cargo.toml` stays as created in Task 3 (`serde`
+ `serde_json`). Skip straight to Step 2.

- [ ] **Step 2: Implement the pipe client**

Replace `crates/protec-host/src/pipe.rs` with:
```rust
use std::io::{Read, Write};

/// Same pipe name the app's server listens on (kept in sync manually; the host
/// cannot depend on the gui crate).
const PIPE_NAME: &str = r"\\.\pipe\protec-ipc-v1";

/// Send a JSON request to the app over the named pipe and read the JSON reply.
/// Framing on the pipe is the same 4-byte LE length prefix as native messaging.
/// Returns Err if the app isn't running (pipe open fails) or on IO error.
pub fn round_trip(request_json: &[u8]) -> std::io::Result<Vec<u8>> {
    // A Windows named pipe client is opened like a file.
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)?;

    pipe.write_all(&(request_json.len() as u32).to_le_bytes())?;
    pipe.write_all(request_json)?;
    pipe.flush()?;

    let mut len = [0u8; 4];
    pipe.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    let mut body = vec![0u8; n];
    pipe.read_exact(&mut body)?;
    Ok(body)
}
```

- [ ] **Step 3: Wire the main loop**

Replace `crates/protec-host/src/main.rs` with:
```rust
mod nativemsg;
mod pipe;
mod protocol;

use std::io::{stdin, stdout};

fn main() {
    let mut input = stdin().lock();
    let mut output = stdout().lock();

    loop {
        let msg = match nativemsg::read_message(&mut input) {
            Ok(Some(m)) => m,
            Ok(None) => break, // browser closed the port
            Err(_) => break,
        };

        // Relay the raw JSON to the app; if the app isn't running, synthesize
        // an Error response so the extension shows a friendly state.
        let reply = match pipe::round_trip(&msg) {
            Ok(body) => body,
            Err(_) => {
                serde_json::to_vec(&protocol::Response::Error {
                    message: "Protec desktop app is not running".into(),
                })
                .unwrap_or_default()
            }
        };

        if nativemsg::write_message(&mut output, &reply).is_err() {
            break;
        }
    }
}
```

- [ ] **Step 4: Build the whole workspace**

Run: `cargo build --manifest-path "<repo>\Cargo.toml" --workspace`
Expected: compiles (protec-core, protec-host, protec-gui).

- [ ] **Step 5: Commit**

```bash
git add crates/protec-host/
git commit -m "feat(host): relay native messages to the app over the named pipe"
```

---

## Phase E — Browser extension

### Task 9: Extension scaffold + form detection (the fiddly, tested part)

**Files:**
- Create: `extension/package.json`, `extension/tsconfig.json`, `extension/vite.config.ts`, `extension/src/forms.ts`, `extension/src/forms.test.ts`, `extension/src/protocol.ts`

- [ ] **Step 1: Create the extension package**

Create `extension/package.json`:
```json
{
  "name": "protec-extension",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "build": "vite build",
    "test": "vitest run"
  },
  "devDependencies": {
    "typescript": "^5",
    "vite": "^5",
    "vitest": "^2",
    "jsdom": "^25"
  }
}
```

Create `extension/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "skipLibCheck": true,
    "lib": ["ES2020", "DOM"],
    "types": ["chrome", "vite/client"]
  },
  "include": ["src/**/*.ts"]
}
```

Create `extension/vite.config.ts`:
```ts
import { defineConfig } from "vite";
export default defineConfig({
  test: { environment: "jsdom" },
  build: {
    rollupOptions: {
      input: {
        background: "src/background.ts",
        content: "src/content.ts",
        popup: "src/popup.ts",
      },
      output: { entryFileNames: "[name].js", format: "es" },
    },
    outDir: "dist",
  },
});
```

- [ ] **Step 2: Create the TS protocol mirror**

Create `extension/src/protocol.ts`:
```ts
export type Request =
  | { type: "find"; origin: string }
  | { type: "submit"; origin: string; username: string; password: string }
  | { type: "status" };

export type Response =
  | { type: "credential"; username: string; password: string }
  | { type: "no_match" }
  | { type: "locked" }
  | { type: "denied" }
  | { type: "acknowledged" }
  | { type: "status"; unlocked: boolean }
  | { type: "error"; message: string };
```

- [ ] **Step 3: Write the form detection with tests**

Create `extension/src/forms.ts`:
```ts
/// Result of scanning a document for a login form.
export interface DetectedForm {
  usernameField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
}

/// Find the most likely username + password fields in a root element.
/// Heuristic: the password field is the first visible input[type=password];
/// the username field is the nearest preceding text/email input.
export function detectLoginForm(root: ParentNode): DetectedForm {
  const passwords = Array.from(
    root.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).filter(isVisible);
  const passwordField = passwords[0] ?? null;
  let usernameField: HTMLInputElement | null = null;

  if (passwordField) {
    const candidates = Array.from(
      root.querySelectorAll<HTMLInputElement>(
        'input[type="text"], input[type="email"], input:not([type])',
      ),
    ).filter(isVisible);
    // Prefer the last text/email input that appears before the password field.
    const pwIndex = allInputs(root).indexOf(passwordField);
    usernameField =
      candidates
        .filter((c) => allInputs(root).indexOf(c) < pwIndex)
        .pop() ?? candidates[0] ?? null;
  }
  return { usernameField, passwordField };
}

function allInputs(root: ParentNode): HTMLInputElement[] {
  return Array.from(root.querySelectorAll<HTMLInputElement>("input"));
}

function isVisible(el: HTMLElement): boolean {
  // jsdom has no layout; treat elements without explicit hiding as visible.
  if (el.hidden) return false;
  const style = (el as HTMLElement).getAttribute("style") ?? "";
  if (/display:\s*none/.test(style) || /visibility:\s*hidden/.test(style)) return false;
  return el.type !== "hidden";
}

/// Read the current username+password values from a detected form.
export function readCredentials(form: DetectedForm): { username: string; password: string } | null {
  if (!form.passwordField || !form.passwordField.value) return null;
  return {
    username: form.usernameField?.value ?? "",
    password: form.passwordField.value,
  };
}
```

Create `extension/src/forms.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { detectLoginForm, readCredentials } from "./forms";

function dom(html: string): ParentNode {
  document.body.innerHTML = html;
  return document.body;
}

describe("forms", () => {
  it("detects a standard username+password form", () => {
    const root = dom(`
      <form>
        <input type="text" name="user" value="octocat" />
        <input type="password" name="pass" value="s3cret" />
        <button>Login</button>
      </form>`);
    const f = detectLoginForm(root);
    expect(f.passwordField?.value).toBe("s3cret");
    expect(f.usernameField?.value).toBe("octocat");
  });

  it("detects email-style username", () => {
    const root = dom(`
      <input type="email" value="me@example.com" />
      <input type="password" value="pw" />`);
    const f = detectLoginForm(root);
    expect(f.usernameField?.value).toBe("me@example.com");
  });

  it("returns null password field when none present", () => {
    const root = dom(`<input type="text" value="x" />`);
    const f = detectLoginForm(root);
    expect(f.passwordField).toBeNull();
  });

  it("ignores hidden password fields", () => {
    const root = dom(`
      <input type="password" style="display: none" value="hidden" />
      <input type="text" value="u" />
      <input type="password" value="real" />`);
    const f = detectLoginForm(root);
    expect(f.passwordField?.value).toBe("real");
  });

  it("readCredentials returns null when password empty", () => {
    const root = dom(`<input type="text" value="u" /><input type="password" value="" />`);
    expect(readCredentials(detectLoginForm(root))).toBeNull();
  });

  it("readCredentials captures both fields", () => {
    const root = dom(`<input type="text" value="u" /><input type="password" value="p" />`);
    expect(readCredentials(detectLoginForm(root))).toEqual({ username: "u", password: "p" });
  });
});
```

- [ ] **Step 4: Install + test**

Run (from `extension/`): `npm install`
Run: `npm run test`
Expected: 6 form tests PASS.

- [ ] **Step 5: Commit**

```bash
git add extension/package.json extension/tsconfig.json extension/vite.config.ts extension/src/forms.ts extension/src/forms.test.ts extension/src/protocol.ts extension/package-lock.json
git commit -m "feat(ext): scaffold + tested login-form detection"
```

### Task 10: Background (native messaging) + content (fill/capture) + popup

**Files:**
- Create: `extension/src/background.ts`, `extension/src/content.ts`, `extension/src/popup.ts`, `extension/src/popup.html`

- [ ] **Step 1: Create the background script (native messaging bridge)**

Create `extension/src/background.ts`:
```ts
import type { Request, Response } from "./protocol";

const HOST = "dev.protec.host";

/// Send one request to the native host and resolve its response.
function sendNative(req: Request): Promise<Response> {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST, req, (resp) => {
      if (chrome.runtime.lastError || !resp) {
        resolve({ type: "error", message: "Protec host unavailable" });
      } else {
        resolve(resp as Response);
      }
    });
  });
}

// Content scripts ask the background to talk to the host (content scripts can't
// use native messaging directly).
chrome.runtime.onMessage.addListener((msg: Request, _sender, sendResponse) => {
  sendNative(msg).then(sendResponse);
  return true; // keep the channel open for the async response
});
```

- [ ] **Step 2: Create the content script (origin, fill, capture)**

Create `extension/src/content.ts`:
```ts
import type { Request, Response } from "./protocol";
import { detectLoginForm, readCredentials } from "./forms";

/// The page origin as the browser sees it — NOT page-controlled content.
const ORIGIN = window.location.origin;

function ask(req: Request): Promise<Response> {
  return new Promise((resolve) => chrome.runtime.sendMessage(req, resolve));
}

/// Fill the detected form with a credential.
function fill(username: string, password: string) {
  const form = detectLoginForm(document);
  if (form.usernameField) {
    form.usernameField.value = username;
    form.usernameField.dispatchEvent(new Event("input", { bubbles: true }));
  }
  if (form.passwordField) {
    form.passwordField.value = password;
    form.passwordField.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

/// On load, if there's a login form, ask the app for a credential.
async function tryFill() {
  if (!detectLoginForm(document).passwordField) return;
  const resp = await ask({ type: "find", origin: ORIGIN });
  if (resp.type === "credential") {
    fill(resp.username, resp.password);
  }
  // locked / no_match / denied → do nothing (fail closed).
}

/// On submit, report the credential so the app can save/update.
function watchSubmit() {
  document.addEventListener(
    "submit",
    () => {
      const creds = readCredentials(detectLoginForm(document));
      if (creds) {
        void ask({ type: "submit", origin: ORIGIN, username: creds.username, password: creds.password });
      }
    },
    true,
  );
}

// Listen for a manual fill request from the popup.
chrome.runtime.onMessage.addListener((msg: { type?: string }) => {
  if (msg?.type === "manual_fill") void tryFill();
});

void tryFill();
watchSubmit();
```

- [ ] **Step 3: Create the popup**

Create `extension/src/popup.html`:
```html
<!DOCTYPE html>
<html>
  <head><meta charset="utf-8" /><style>
    body { width: 220px; font-family: system-ui, sans-serif; padding: 12px; background:#0d1117; color:#e6edf3; }
    button { width: 100%; padding: 8px; margin-top: 8px; background:#2f81f7; color:#fff; border:0; border-radius:6px; cursor:pointer; }
    .status { font-size: 12px; color:#7d8590; }
  </style></head>
  <body>
    <div class="status" id="status">Checking…</div>
    <button id="fill">Fill this page</button>
    <script type="module" src="popup.js"></script>
  </body>
</html>
```

Create `extension/src/popup.ts`:
```ts
import type { Request, Response } from "./protocol";

const statusEl = document.getElementById("status")!;
const fillBtn = document.getElementById("fill") as HTMLButtonElement;

function sendNative(req: Request): Promise<Response> {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage("dev.protec.host", req, (resp) => {
      if (chrome.runtime.lastError || !resp) resolve({ type: "error", message: "unavailable" });
      else resolve(resp as Response);
    });
  });
}

(async () => {
  const resp = await sendNative({ type: "status" });
  if (resp.type === "status") statusEl.textContent = resp.unlocked ? "● Protec unlocked" : "● Protec locked";
  else if (resp.type === "error") statusEl.textContent = "Protec app not running";
})();

fillBtn.addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) chrome.tabs.sendMessage(tab.id, { type: "manual_fill" });
});
```

- [ ] **Step 4: Build the extension**

Run (from `extension/`): `npm run build`
Expected: `dist/background.js`, `dist/content.js`, `dist/popup.js` produced. (popup.html is copied in Task 11's manifest packaging; for now confirm the JS bundles build.)

- [ ] **Step 5: Commit**

```bash
git add extension/src/background.ts extension/src/content.ts extension/src/popup.ts extension/src/popup.html
git commit -m "feat(ext): background native-messaging bridge, content fill/capture, popup"
```

### Task 11: Manifests (Chromium + Firefox) + host registration

**Files:**
- Create: `extension/manifest.chromium.json`, `extension/manifest.firefox.json`, `extension/scripts/register-host.ps1`

- [ ] **Step 1: Create the Chromium manifest (MV3)**

Create `extension/manifest.chromium.json`:
```json
{
  "manifest_version": 3,
  "name": "Protec",
  "version": "0.1.0",
  "description": "Autofill from your local Protec vault.",
  "permissions": ["nativeMessaging", "activeTab", "tabs", "scripting"],
  "background": { "service_worker": "background.js", "type": "module" },
  "action": { "default_popup": "popup.html" },
  "content_scripts": [
    { "matches": ["http://*/*", "https://*/*"], "js": ["content.js"], "run_at": "document_idle" }
  ]
}
```

- [ ] **Step 2: Create the Firefox manifest (MV2-style background, MV3 capable)**

Create `extension/manifest.firefox.json`:
```json
{
  "manifest_version": 3,
  "name": "Protec",
  "version": "0.1.0",
  "description": "Autofill from your local Protec vault.",
  "permissions": ["nativeMessaging", "activeTab", "tabs", "scripting"],
  "background": { "scripts": ["background.js"] },
  "action": { "default_popup": "popup.html" },
  "content_scripts": [
    { "matches": ["http://*/*", "https://*/*"], "js": ["content.js"], "run_at": "document_idle" }
  ],
  "browser_specific_settings": { "gecko": { "id": "protec@local" } }
}
```

- [ ] **Step 3: Create the host-registration script**

Create `extension/scripts/register-host.ps1`:
```powershell
# Registers the protec-host native-messaging host for Chromium + Firefox.
# Usage: powershell -ExecutionPolicy Bypass -File register-host.ps1 -HostExe "C:\path\to\protec-host.exe" -ChromiumExtId "<id>" -FirefoxExtId "protec@local"
param(
  [Parameter(Mandatory=$true)][string]$HostExe,
  [string]$ChromiumExtId = "REPLACE_WITH_CHROMIUM_EXTENSION_ID",
  [string]$FirefoxExtId = "protec@local"
)

$ErrorActionPreference = "Stop"
$hostName = "dev.protec.host"
$dir = Join-Path $env:LOCALAPPDATA "Protec\nmh"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# Chromium manifest
$chromium = @{
  name = $hostName
  description = "Protec native messaging host"
  path = $HostExe
  type = "stdio"
  allowed_origins = @("chrome-extension://$ChromiumExtId/")
} | ConvertTo-Json -Depth 5
$chromiumPath = Join-Path $dir "$hostName.chromium.json"
Set-Content -Path $chromiumPath -Value $chromium -Encoding UTF8

# Firefox manifest
$firefox = @{
  name = $hostName
  description = "Protec native messaging host"
  path = $HostExe
  type = "stdio"
  allowed_extensions = @($FirefoxExtId)
} | ConvertTo-Json -Depth 5
$firefoxPath = Join-Path $dir "$hostName.firefox.json"
Set-Content -Path $firefoxPath -Value $firefox -Encoding UTF8

# Register via the per-user registry keys.
$chromeKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
New-Item -Path $chromeKey -Force | Out-Null
Set-ItemProperty -Path $chromeKey -Name "(default)" -Value $chromiumPath

$edgeKey = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName"
New-Item -Path $edgeKey -Force | Out-Null
Set-ItemProperty -Path $edgeKey -Name "(default)" -Value $chromiumPath

$ffKey = "HKCU:\Software\Mozilla\NativeMessagingHosts\$hostName"
New-Item -Path $ffKey -Force | Out-Null
Set-ItemProperty -Path $ffKey -Name "(default)" -Value $firefoxPath

Write-Host "Registered protec-host for Chrome, Edge, and Firefox."
Write-Host "Chromium manifest: $chromiumPath"
Write-Host "Firefox manifest:  $firefoxPath"
```

- [ ] **Step 4: Verify the script parses (dry syntax check)**

Run: `powershell -NoProfile -Command "Get-Command -Syntax { . '.\extension\scripts\register-host.ps1' }" 2>$null; echo "ok"`
(If that form is awkward, just confirm the file exists and is valid PowerShell by running `powershell -NoProfile -File extension\scripts\register-host.ps1 -HostExe "C:\tmp\protec-host.exe"` in a scratch context — it will write manifests to LOCALAPPDATA; that's acceptable as a smoke check. Report what you did.)

- [ ] **Step 5: Commit**

```bash
git add extension/manifest.chromium.json extension/manifest.firefox.json extension/scripts/register-host.ps1
git commit -m "feat(ext): Chromium + Firefox manifests and host-registration script"
```

---

## Phase F — Integration, CI, docs

### Task 12: Workspace tests, clippy/fmt, CI, README

**Files:**
- Modify: `.github/workflows/ci.yml`, `README.md`

- [ ] **Step 1: Full Rust suite + lint/fmt**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" --workspace`
Expected: all pass (protec-core, protec-host protocol+nativemsg, protec-gui incl. match_domain + ipc).
Run: `cargo clippy --manifest-path "<repo>\Cargo.toml" --workspace --all-targets -- -D warnings`
Fix any warnings minimally (idiomatic fix; justified `#[allow]` only if needed). Re-run until clean.
Run: `cargo fmt --manifest-path "<repo>\Cargo.toml" --all` then `--all -- --check` (clean).

- [ ] **Step 2: Extension tests**

Run (from `extension/`): `npm run test`
Expected: form tests PASS.

- [ ] **Step 3: Extend CI**

Add a `host` job and an `ext` job to `.github/workflows/ci.yml`. Insert these jobs under the existing `jobs:` map (keep the existing `core`, `audit`, `gui` jobs unchanged):
```yaml
  host:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - run: cargo clippy -p protec-host --all-targets -- -D warnings
      - run: cargo test -p protec-host
      - run: cargo build -p protec-host --release
  ext:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: extension
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm run test
      - run: npm run build
```
Also update the existing `gui` job's clippy line to cover the new modules (it already runs `cargo clippy -p protec-gui --all-targets` — no change needed; the new ipc/match_domain modules are part of `protec-gui`).

- [ ] **Step 4: Update README**

Append a "Browser extension" section to `README.md`:
```markdown
## Browser extension (autofill)

Protec autofills logins in Chrome, Edge, and Firefox via **native messaging** —
no network, no localhost server. The browser talks to a small local host
(`protec-host`) that relays requests to the running desktop app over a Windows
named pipe. The app is the gatekeeper: it stays unlocked, matches the page's
registrable domain (strict — `github.com` never fills on `github.com.evil.com`),
and every fill/save/update requires an explicit Allow in the app.

### Install (development)

```bash
cargo build -p protec-host --release          # build the host
cd extension && npm install && npm run build  # build the extension
```

Load `extension/dist` (with the right manifest) as an unpacked extension, then
register the host (run from an elevated-not-required PowerShell):

```powershell
extension\scripts\register-host.ps1 -HostExe "<repo>\target\release\protec-host.exe" -ChromiumExtId "<your-unpacked-extension-id>"
```

The desktop app must be running and unlocked for autofill to work.
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci+docs: build/test host and extension; document the browser extension"
```

---

## Definition of Done

- `cargo test --workspace` passes (core + host protocol/framing + gui match_domain/ipc).
- `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --all -- --check` clean.
- Extension `npm run test` passes (form detection).
- The matcher rejects `github.com.evil.com`, `g1thub.com`, `paypal.com` for a `github.com` entry (tested).
- The host relays to the app; when the app is closed, the extension gets a friendly "not running" error (fail-closed).
- Fill, save, and update each raise a desktop Allow/Deny prompt; Deny releases no secret; save/update happen in Rust on the unlocked vault.
- The vault key never crosses the pipe — only single credentials, post-confirmation, post-match.
- CI builds the host (Windows) and tests the extension (Linux).
- README documents the native-messaging install for Chromium + Firefox.

## Manual verification (post-implementation, needs a real browser — done by the operator)

These cannot be fully automated; verify by hand after the plan completes:
1. Build host + extension; load unpacked in Chrome; run `register-host.ps1` with the real extension ID.
2. With the app unlocked, visit a saved site's login page → app prompts "Fill login for …?" → Allow → fields fill.
3. Submit a new login → app prompts "Save new login?" → Allow → entry appears in the app.
4. Change a saved password and submit → app prompts "Update password?" → Allow → entry updates.
5. Lock the app → autofill request shows "Protec is locked" in the extension, no prompt.
6. Visit `https://github.com.evil.com` (a local hosts-file alias) with a `github.com` entry → NO match offered.
```
