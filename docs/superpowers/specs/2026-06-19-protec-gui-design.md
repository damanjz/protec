# protec-gui — Design Spec

**Date:** 2026-06-19
**Status:** Approved (design phase)
**Sub-project:** 2 of 5 (the CLI sub-project was dropped; the GUI is now sub-project 2)

---

## 0. Context

`protec-core` (sub-project 1) is complete and merged on `main`: a Rust library crate
providing a secure local vault (Argon2id + XChaCha20-Poly1305, envelope encryption with a
multi-wrap header, type-state `Locked`/`Unlocked` API, zeroized key material, atomic
versioned storage). Public API: `Vault::create/open`, `LockedVault::unlock`, `UnlockedVault`
(`list_entries`, `get`, `add`, `update`, `delete`, `save`, `lock`, `is_expired`), the `Entry`
model (title, username, password, url, notes, tags, totp, custom_fields, timestamps), and
`VaultError`.

`protec-gui` is a desktop client built directly on that crate. The original CLI sub-project
was intentionally dropped — the core's 25-test suite already proves the engine end-to-end, so
effort goes entirely into a best-in-class GUI.

**Remaining roadmap after this:** (3) Windows Hello unlock, (4) browser extension.

---

## 1. Product Direction

A **minimal, keyboard-driven, command-palette-first** desktop password manager with a
**very techy** aesthetic and strong functionality. Reference feel: Raycast / Linear / a
refined developer tool. Fast, dark, dense-but-clean. Keyboard is the primary input; mouse is
fully supported.

### Locked-in decisions
- **Layout A — persistent two-pane + command palette:** an always-visible entry list + detail
  pane, with a `Ctrl+K` command palette overlaid for instant search and actions. Keyboard-first
  but nothing is hidden ("very functional").
- **Theme: Slate Dev-Tool (default)** — cool slate greys, one blue accent, green for live data;
  techy via mono-font + density rather than loud color. **Terminal Green** ships as a switchable
  alternate theme (hacker/matrix mood). Themes are CSS variables flipped by a `data-theme`
  attribute, so adding more later is trivial.
- **Stack: Tauri 2 + Svelte** (TypeScript + Vite). Svelte chosen for a small, fast runtime that
  suits a snappy keyboard-driven UI.

---

## 2. Architecture

Tauri 2 app: a Rust backend that links `protec-core` directly (no separate process, no
re-implementation) and a Svelte web frontend that is purely a **view**.

### The security boundary (central design stance)
**Secrets stay in the Rust process. The frontend is a view that only receives what it
explicitly requests.**
- The Rust backend owns the `UnlockedVault`.
- The entry **list** is sent to the frontend as summaries with **no passwords**.
- A password/TOTP crosses the boundary only on an explicit, user-initiated action
  ("reveal" or "copy"), and "copy" routes the secret to the OS clipboard from Rust without
  necessarily rendering it in the UI.
- This is the GUI analog of the core's type-state safety: the frontend cannot leak a secret it
  was never given.

### Vault state
A single source of truth in the backend: `VaultState { Locked, Unlocked(UnlockedVault) }`
behind a `Mutex`, plus the configured vault path. The `Mutex` serializes commands so they
cannot race; a secret-accessing command on a `Locked` vault returns a clean error, never a
panic.

---

## 3. Component Structure

"Many small files, one responsibility each."

### Rust backend (`src-tauri/src/`)
- `main.rs` — Tauri setup, command registration, window config.
- `state.rs` — `VaultState` enum behind a `Mutex`; owns vault path; single source of truth.
- `config.rs` — load/save/validate `config.toml`; sane fallbacks for missing/malformed config
  (never crash on bad config; out-of-range values fall back to defaults).
- `dto.rs` — boundary data shapes: `EntrySummary { id, title, username, tags }` (**no
  password**); `EntryDetail` (includes secrets only when explicitly requested);
  `VaultStatus`; `GeneratorOptions`; `AppConfig`.
- `commands/auth.rs` — `create_vault`, `unlock`, `lock`, `vault_status`.
- `commands/entries.rs` — `list_entries`, `get_entry`, `add_entry`, `update_entry`,
  `delete_entry`, `save_vault`.
- `commands/generator.rs` — `generate_password`.
- `commands/clipboard.rs` — `copy_secret` (copy + scheduled auto-clear).
- `commands/settings.rs` — `get_config`, `set_config`.

### Password generator location
`generate_password(options) -> String` is **pure, testable Rust** added to `protec-core` (it
is vault-independent logic and the natural home is the core crate). Options: length, character
sets (upper/lower/digits/symbols), exclude-ambiguous, and a passphrase mode (word-based,
configurable word count and separator).

### Frontend (`src/`)
- `App.svelte` — root; routes between first-run, lock screen, and main view by status.
- `lib/components/`: `FirstRun.svelte`, `LockScreen.svelte`, `EntryList.svelte`,
  `EntryDetail.svelte`, `CommandPalette.svelte`, `GeneratorPanel.svelte`, `EntryForm.svelte`,
  `Settings.svelte`, `Toast.svelte`.
- `lib/stores/` — Svelte stores: vault status, entries, selection, palette open-state, config.
- `lib/api.ts` — typed wrappers over Tauri `invoke()`; the **only** place the frontend talks to
  Rust.
- `lib/keybindings.ts` — global keyboard handling (`Ctrl+K`, `↑/↓`, `Enter`, `Ctrl+C`,
  `Ctrl+L`, `Esc`).
- `lib/theme.css` — CSS variables for Slate (default) + Terminal Green; switched via
  `data-theme`.

The clean seams: `api.ts` is the single frontend→backend channel; `dto.rs` is the single
definition of what crosses it; `state.rs` is the single owner of vault state.

---

## 4. Behaviors & Data Flow

### Startup → unlock
1. App launches → backend checks for a vault file at the configured path
   (default `%APPDATA%/Protec/vault.dat`).
2. **No vault** → `FirstRun`: set master password (confirm field + strength meter) →
   `create_vault`.
3. **Vault exists** → `LockScreen`: master password → `unlock` → backend holds `UnlockedVault`
   → main view. Wrong password → inline error, nothing leaked.

### Main view (unlocked)
- Backend sends `EntrySummary[]` (no passwords) → `EntryList`.
- Selecting an entry → `get_entry(id)` → `EntryDetail` with the password **masked**; a "reveal"
  toggle shows it (governed by the *reveal-on-select* setting), "copy" never needs to reveal.
- **`Ctrl+K` palette:** fuzzy-search entries + run commands ("New entry", "Generate password",
  "Lock vault", "Switch theme", "Settings", "Copy password of…"). `Enter` runs the action.
- **Edits** mutate the in-memory `UnlockedVault`, then (if auto-save on) call `save_vault` →
  atomic write. Auto-save defaults **on**; when off, an "unsaved" indicator + explicit save
  command appear.

### Auto-lock & Hello-ready seam
- Frontend tracks activity; on inactivity timeout it calls `lock`. Backend also self-checks
  `is_expired` on each command as a backstop. On lock → backend drops `UnlockedVault` (keys
  zeroized) → `LockScreen`.
- **Windows Hello seam:** the lock screen reserves a slot for an "Unlock with Windows Hello"
  button, hidden/disabled now, wired in sub-project 3. The multi-wrap header in `protec-core`
  already supports the second wrap.

### Clipboard safety
- `copy_secret` copies to the OS clipboard and **schedules an auto-clear** (default 20 s,
  configurable incl. Off). A subtle countdown shows in the UI.

---

## 5. Settings (fully configurable)

A `Settings` panel (Ctrl+K → "Settings" or a gear icon), backed by `%APPDATA%/Protec/config.toml`
(plaintext — **no secrets**, preferences only). Validated at load (out-of-range/unknown →
default).

| Setting | Default | Options |
|---|---|---|
| Auto-lock timeout | 10 min | Off, 1, 5, 10, 15, 30 min, custom |
| Lock on minimize / window-blur | Off | On/Off |
| Clipboard auto-clear | 20 s | Off, 10, 20, 30, 60 s, custom |
| Auto-save after edits | On | On/Off |
| Theme | Slate Dev-Tool | Slate / Terminal Green |
| Reveal-on-select | Off (masked) | On/Off |
| Generator defaults | len 20, all sets, exclude-ambiguous | full config |
| Vault file location | `%APPDATA%/Protec/vault.dat` | custom path |
| Windows Hello unlock | Off (seam) | disabled until sub-project 3 |

---

## 6. Error Handling & Edge Cases

- Every Tauri command returns `Result<T, String>`; errors surface as user-friendly toasts/inline
  text, never a raw panic. `VaultError` maps to clean messages (`WrongPassword` → "Incorrect
  master password"; `Tampered`/`Corrupted` → "Vault file may be damaged — restore backup?").
- **Corrupted/tampered vault:** offer to restore from the `.bak` the core maintains. No silent
  data loss.
- **Malformed config:** fall back to defaults, show a non-blocking notice; app always starts.
- **Locked-vault command:** clean "vault is locked" error, no crash (enforced by the `Mutex` +
  state check).
- **Clipboard failures:** caught, surfaced as a toast, never break the flow.
- **Window close while unlocked:** vault dropped (keys zeroized) on exit; if auto-save is off and
  edits are pending, prompt before closing.

---

## 7. Testing & Packaging

### Testing
- **Rust backend:** unit-test command logic, `config.rs` (load/validate/fallback), and DTO
  mapping — including a **security regression guard** asserting `EntrySummary` never carries a
  password. Thorough `generate_password` tests (length, charset inclusion/exclusion, ambiguity
  filter, passphrase mode).
- **Frontend:** Vitest for stores, keybinding dispatch, and palette fuzzy-search, with `api.ts`
  mocked.
- **E2E smoke flows:** create vault → add entry → lock → unlock → entry persists; generate+fill.

### Packaging (open source, continues sub-project 1)
- `protec-gui` joins the existing Cargo workspace `members`.
- Tauri builds a Windows installer (`.msi` / NSIS).
- CI extends the current workflow with a Tauri build job.
- README updated with screenshots + install instructions. Apache-2.0 throughout.

---

## 8. Recap of Locked-In Decisions

- Tauri 2 + Svelte; secrets-stay-in-Rust boundary.
- Layout A (two-pane + Ctrl+K palette); Slate Dev-Tool theme default, Terminal Green alternate.
- Full password generator (in `protec-core`), incl. passphrase mode.
- Fully-configurable Settings panel backed by `config.toml`.
- Auto-save on by default; clipboard auto-clear 20 s by default; both configurable.
- Master-password unlock now, Windows Hello seam reserved.
- Corrupted-vault `.bak` recovery; never crash on bad config.
- Windows `.msi` packaging; workspace + CI extended.
