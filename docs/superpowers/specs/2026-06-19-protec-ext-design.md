# protec-ext — Design Spec

**Date:** 2026-06-19
**Status:** Approved (design phase)
**Sub-project:** 3 of 4 (Windows Hello becomes sub-project 4)

---

## 0. Context

`protec-core` (the vault engine) and `protec-gui` (the Tauri 2 + Svelte desktop app) are
complete and merged on `main`. The desktop app already owns the only unlocked vault in
memory and enforces the "secrets stay in Rust" boundary.

`protec-ext` adds a **browser extension with autofill** for **Chromium (Chrome/Edge/Brave)
and Firefox**, connected to the desktop app via **native messaging** — no network, no
localhost server, no open ports. This preserves the "totally local" requirement: the only
link between the browser and Protec is an OS-level pipe to a local host process.

**Remaining roadmap after this:** (4) Windows Hello unlock.

---

## 1. Locked-In Decisions

- **Native messaging**, not a local HTTP server — keeps everything local, no ports.
- **Chromium + Firefox**, one extension codebase with two manifests.
- **App-unlocked + per-action confirmation:** the desktop app must be running and unlocked;
  every fill/save/update requires an explicit Allow in a desktop confirmation prompt. The
  extension never holds the vault key and never writes the vault directly.
- **Strict registrable-domain matching, done in Rust** using a public-suffix list. The page
  origin is supplied by the browser API, never trusted from page content. Anti-phishing:
  a credential is never offered on a lookalike domain.
- **Fill + Save + Update.** The extension reports what was submitted; **the app decides**
  (in Rust, where the stored secret lives) whether it is new (→ save), changed (→ update),
  or already-matching (→ no-op).

---

## 2. Architecture & Trust Model

Three components with a hard boundary between them:

1. **`protec-host`** (new Rust binary, joins the workspace) — the **native-messaging host**.
   The browser launches it and talks over stdin/stdout using length-prefixed JSON (4-byte LE
   length + JSON body, per the native-messaging spec). It is a **thin broker**: it does NOT
   hold its own unlocked vault. It connects to the already-running desktop app over a local
   named pipe and relays requests/responses. Untrusted-by-default.

2. **`protec-gui` as gatekeeper** — owns the unlocked vault (as today) and gains a **local
   IPC endpoint**: a **Windows named pipe** (not a socket, not a port). On each request the
   app performs the domain match, shows the confirmation prompt, and only then returns a
   single credential or performs the vault write. The app must be running and unlocked.

3. **`protec-extension`** (browser extension) — content script detects forms and reports the
   page origin; background script speaks native messaging to `protec-host`. The extension
   **never sees the vault** — only single credentials the app released, only for the current
   origin, only after confirmation.

**Fill data path:** page origin → extension → host → app (match + confirm) → host →
extension → fill. The vault key never leaves the app; the host is a pipe-to-pipe relay; the
extension receives exactly one credential after the user's Allow.

---

## 3. Components & Files

### `crates/protec-host/` (new Rust binary)
- `main.rs` — native-messaging loop: read framed JSON from stdin, dispatch, write framed
  response to stdout.
- `protocol.rs` — message types exchanged with the extension (`FindRequest`, `FillResponse`,
  `SaveRequest`, `UpdateRequest`, `StatusResponse`, error shapes). Serde structs, shared
  schema with the extension's TS types.
- `pipe.rs` — connects to the desktop app's named pipe; forwards requests; handles
  "app not running / locked / pipe error" cleanly (fail closed).
- `nativemsg.rs` — framing helpers (4-byte LE length prefix + JSON) per the browser spec.

### `protec-gui` additions (gatekeeper side)
- `src-tauri/src/ipc/server.rs` — named-pipe server: accepts host connections (user-restricted
  ACL), deserializes requests, verifies the connecting process is our host.
- `src-tauri/src/ipc/handler.rs` — per request: domain-match, raise the confirmation UI, and on
  approval return the credential or perform the save/update on the unlocked vault.
- `src-tauri/src/match_domain.rs` — registrable-domain matching via a public-suffix list. Pure,
  exhaustively tested. (File named `match_domain.rs` because `match` is a Rust keyword.)
- Confirmation UI — a focused Svelte prompt: "Fill / Save / Update [site]? Allow / Deny."

### `extension/` (shared codebase)
- `manifest.chromium.json` + `manifest.firefox.json` — two manifests, one source.
- `background.ts` — connects to the native host, routes messages.
- `content.ts` — detects login/signup forms, reports the page origin, fills fields, captures
  submits for save/update.
- `forms.ts` — form-detection heuristics (find username/password fields, detect submit, report
  submitted values). Isolated and unit-tested.
- `popup.html` / `popup.ts` — tiny status popup ("app connected / app locked / not running")
  and a manual "fill here" button.

### Host registration
A small install step writes the native-messaging manifest to each browser's expected location
and pins the absolute host binary path:
- **Chromium:** a JSON manifest in the per-user NativeMessagingHosts directory (and/or the
  documented registry key on Windows) naming the host and the allowed extension ID.
- **Firefox:** a JSON manifest in Firefox's `native-messaging-hosts` location with the allowed
  extension ID.

---

## 4. Data Flow (the three operations)

All three go through the app as gatekeeper; the vault key never leaves Rust.

### FILL
1. Content script detects a login form and reports the page's **real origin** (from the
   browser, not page JS) → background → host → app's named pipe.
2. App runs `match_domain.rs` against the origin (strict registrable-domain). If the app is
   **locked**, it returns "locked" → extension shows "unlock Protec" (no secrets, no prompt).
3. If matches exist, the app shows the **confirmation prompt** ("Fill `github.com` login?
   Allow/Deny"). On Allow → app returns the single credential → host → extension → fields
   filled. On Deny → nothing leaves the app.

### SAVE
1. On submit, content script captures username + password and sends a `SaveRequest` with the
   origin → host → app.
2. App confirms ("Save new login for `github.com`? Allow/Deny"). On Allow → app **writes a new
   `Entry`** to the unlocked vault and persists. The extension only sent a request.

### UPDATE
1. On submit, the extension sends username + submitted password for the origin. The extension
   does **not** know the stored password (it never sees it).
2. The **app** compares the submission against what it holds for that origin+username:
   - not present → treat as SAVE candidate ("Save new login?")
   - present but password differs → "Update password for `github.com`? Allow/Deny"
   - present and identical → no-op (no prompt)
   On Allow → app updates the entry. Detection lives in Rust, where the stored secret is.

### Abuse protection
The app rate-limits requests per origin and can offer "Protec is being asked repeatedly —
block this site?" to stop a malicious page from spamming confirmations.

---

## 5. Security Properties

- **Vault key never leaves the app.** Host and extension only ever see single credentials,
  post-confirmation, for the matched origin.
- **Origin is browser-supplied**, never trusted from page content.
- **Pipe authentication:** named pipe restricted to the current user (Windows ACL); the app
  verifies the connecting process. The host binary path is pinned in the native-messaging
  manifest, so the browser only launches our host; the manifest names the allowed extension ID.
- **No silent operations:** fill/save/update each require an explicit Allow; Deny leaves zero
  trace in the browser.
- **Fail closed:** app locked / not running / pipe error / no match → a safe "unavailable" or
  "no match", never a partial secret.
- **Rate-limiting + per-site block** against confirmation spam.

---

## 6. Error Handling

Every boundary returns typed results mapped to friendly states: "Protec is locked," "Protec
isn't running," "no saved login for this site," "request denied," "rate-limited." The extension
popup surfaces connection status so failures are legible, never silent hangs.

---

## 7. Testing

- `match_domain.rs` — exhaustive table tests: `github.com` matches `github.com` /
  `www.github.com`; rejects `github.com.evil.com`, `g1thub.com`, `paypal.com`; public-suffix
  edge cases (`example.co.uk`).
- Protocol round-trip (serde) tests for every message type, shared schema with the extension.
- `forms.ts` — unit tests over saved HTML samples: find username/password fields, detect
  submit, handle multi-step / no-form cases gracefully.
- App-side save-vs-update decision tests (new → save, changed → update, same → no-op).
- Scripted end-to-end on a **local test page** (no real sites) exercising fill/save/update
  against a running app.

---

## 8. Packaging (open source)

- `protec-host` builds with the Cargo workspace (added to `members`).
- An install step registers the native-messaging manifests for Chromium + Firefox and pins the
  host path.
- Extension packaged as a `.zip` (Chromium) / `.xpi` (Firefox).
- README documents install for both browsers. Apache-2.0 throughout.
- CI builds the host and lints/tests the extension TypeScript.

---

## 9. Recap of Locked-In Decisions

- Native messaging over a Windows named pipe (no network/ports).
- Host = thin broker; desktop app = gatekeeper holding the only unlocked vault.
- Strict registrable-domain matching in Rust (public-suffix list); origin from the browser API.
- Fill + Save + Update, with the app deciding save-vs-update by comparing in Rust.
- Per-action confirmation; fail-closed everywhere; rate-limiting + per-site block.
- Chromium + Firefox, one extension codebase, two manifests.
