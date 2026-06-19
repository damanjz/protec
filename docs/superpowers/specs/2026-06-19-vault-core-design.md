# vault-core — Design Spec

**Date:** 2026-06-19
**Status:** Approved (design phase)
**Sub-project:** 1 of 5

---

## 0. Project Overview & Roadmap

This is the first sub-project of a fully-local, open-source password manager written in
Rust. The full system is decomposed into independent sub-projects, each with its own
spec → plan → implementation cycle, built in dependency order:

1. **`vault-core`** *(this spec)* — the secure engine: master-password unlock, crypto,
   storage format, in-memory locked/unlocked state, auto-lock mechanism, secret CRUD.
   No UI, no CLI, no network.
2. **`vault-cli`** — thin terminal client. Exists primarily to prove the core works
   before building richer clients on top of it.
3. **`vault-gui`** — good-looking desktop app (Tauri: Rust backend reusing `vault-core` +
   polished web frontend).
4. **Windows Hello** — feature of the GUI: a second wrapping of the vault key held by the
   Windows TPM, enabling biometric/PIN re-unlock after the first master-password unlock.
5. **Browser extension** — autofill via a Rust native-messaging host linking `vault-core`.

**Security target:** best-practice personal vault — 1Password/Bitwarden-grade crypto done
correctly. Resists a stolen laptop and a stolen vault file. Fully local: no account, no
server, no telemetry. The vault file is the user's to back up.

**Critical design principle:** `vault-core`'s API is designed *up front* to support the GUI
and Windows Hello, even though they are built later. Specifically, the storage format
supports **multiple independent wraps of the vault key** from day one, so Hello adds a wrap
without any data re-encryption or format migration.

---

## 1. Purpose & Scope

`vault-core` is a standalone Rust library crate that securely stores and retrieves secrets,
encrypted at rest, unlocked by a master password. It is the engine every other sub-project
depends on.

### In scope
- Key derivation (master password → keys)
- Envelope encryption / decryption
- On-disk vault format (single portable file)
- In-memory unlocked state and key material lifecycle
- Auto-lock *mechanism* (timing exposed; clients drive it)
- Secret CRUD: add / get / update / delete / list entries
- Memory hygiene (guaranteed wiping of key material)

### Out of scope (YAGNI / later sub-projects)
- Sync, cloud, backup automation
- Biometrics / Windows Hello (sub-project 4 — but the *hook* is designed in here)
- UI of any kind (CLI/GUI/extension are sub-projects 2–5)
- Autofill / browser integration
- Password generation UI (a generator *utility* may live here; the UI does not)

---

## 2. Architecture & Crypto

The core is a state machine with two states: **Locked** and **Unlocked**.

### Key derivation
- Master password + random 16-byte salt → **Argon2id** → 32-byte master key.
- Argon2id parameters tuned to ~250–500 ms on a normal machine; params stored in the
  vault header so they travel with the file and can be increased over time.

### Envelope encryption (the central design choice)
- A random 32-byte **vault key** encrypts the actual secrets.
- The **master key wraps (encrypts) the vault key** — it never touches secret data directly.
- **Why this matters:** Windows Hello later becomes simply a *second wrap* of the same vault
  key by a TPM-held key. No re-encryption, no schema change. The format supports a list of
  wraps from day one.

### Symmetric encryption
- **XChaCha20-Poly1305** (AEAD — authenticated; tampering is detected).
- 24-byte random nonce per encryption operation.

### Memory hygiene
- Master key, vault key, and decrypted secrets are held in `zeroize`-wrapping types that
  wipe RAM on drop.
- `lock()` drops and wipes all key material.

---

## 3. On-Disk Vault Format

A single self-contained, portable file (`vault.dat`). Safe to copy anywhere because it is
encrypted.

```
┌─────────────────────────────────────────────┐
│ HEADER (plaintext, authenticated)            │
│  • magic bytes + format version              │
│  • Argon2id params (salt, mem, iters, lanes) │
│  • list of "key wraps":                      │
│      - wrap[0]: master-password wrap         │
│      - wrap[1]: (later) Windows Hello wrap   │
├─────────────────────────────────────────────┤
│ ENCRYPTED BODY (XChaCha20-Poly1305)          │
│  • nonce                                     │
│  • ciphertext = encrypted entry list         │
│  • auth tag                                  │
└─────────────────────────────────────────────┘
```

- **Header is plaintext but authenticated** — KDF params must be readable to derive the key;
  the AEAD tag covers the header so it cannot be tampered with undetected.
- **Key-wraps list** is what makes Hello drop in cleanly — adding Hello appends `wrap[1]`;
  the body is untouched.
- **Format version byte** — enables safe migration of old vaults; essential for a tool people
  trust with real data over time.
- **Atomic writes** — write to temp file then rename; a crash mid-write never corrupts the
  vault. A `.bak` of the previous version is retained.

### Entry model (inside the encrypted body)
Each secret entry contains:
- `id` (UUID)
- `title`
- `username`
- `password`
- `url`
- `notes`
- `tags` (list)
- `totp` (optional — TOTP/2FA secret + parameters)
- `custom_fields` (optional key/value list)
- `created_at`, `updated_at`

TOTP and custom fields are included now because retrofitting them later would require a
format migration.

---

## 4. Public API & Auto-Lock

A small, hard-to-misuse API. The type system enforces security: secret-accessing methods
exist **only** on `UnlockedVault`, so reading a secret from a locked vault does not compile.

```rust
Vault::create(path, master_password)      // create a new vault on disk
Vault::open(path) -> LockedVault          // load from disk (remains locked)

LockedVault::unlock(master_password) -> UnlockedVault
UnlockedVault::lock()                     // wipe keys, return to locked state

// Available ONLY on UnlockedVault:
.list_entries()
.get(id)
.add(entry)
.update(id, entry)
.delete(id)
.save()                                   // re-encrypt + atomic write
```

### Auto-lock
- The core tracks last-activity time and exposes `is_expired(timeout)`.
- **Clients drive the clock** and call `lock()` when idle — the core stays UI-agnostic but
  provides the mechanism.
- Default timeout configurable; ships at **10 minutes idle**.

---

## 5. Error Handling

A typed `VaultError` enum:
- `WrongPassword`
- `Corrupted`
- `Tampered`
- `Io`
- `VersionUnsupported`

Wrong-password and tampering failures are indistinguishable in message/timing where it
matters — no padding/decryption oracle leaks. Decryption never returns partial or garbage
plaintext on auth failure.

---

## 6. Testing

- Unit tests per module.
- Round-trip tests: create → add → save → open → unlock → read.
- **Tamper tests:** flip a byte in header or body → must fail authentication, never return
  garbage.
- Wrong-password tests.
- Known-answer crypto vectors (Argon2id, XChaCha20-Poly1305).
- Multi-wrap test: vault key wrapped by two keys, each independently unwraps.
- Coverage target: 80%+.

---

## 7. Packaging (Open Source)

- Cargo **workspace** repo (room for `vault-core`, `vault-cli`, `vault-gui`, host crate).
- `LICENSE` — Apache-2.0 or MIT (decided before first public push).
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- GitHub Actions CI: build + test + `cargo audit` + `cargo deny` + `cargo clippy` + `cargo fmt --check`.
- No secrets, no telemetry, no network calls anywhere in the codebase.

---

## 8. Recap of Locked-In Decisions

- **Language:** Rust (memory safety + `zeroize` + single-binary distribution).
- **Crypto:** Argon2id (KDF) + XChaCha20-Poly1305 (AEAD).
- **Architecture:** envelope encryption with multi-wrap (Windows Hello-ready).
- **Storage:** single portable authenticated file, versioned, atomic writes, `.bak`.
- **API:** type-state Locked/Unlocked — security enforced at compile time.
- **Auto-lock:** 10-minute idle default, configurable, client-driven.
- **Entry model:** includes TOTP and custom fields.
- **Distribution:** fully local, open source, CI-gated, no network/telemetry.
