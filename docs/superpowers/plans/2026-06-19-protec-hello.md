# protec-hello Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional, opt-in **Windows Hello** (biometric/PIN) unlock to Protec as a TPM-bound second wrap of the vault key, with the master password always remaining a valid unlock method.

**Architecture:** `protec-core` already stores a list of key-wraps in its header; Hello adds a second `WindowsHello` wrap. A new `protec-hello` crate isolates the Windows-specific code: the wrap/unwrap *envelope* logic sits behind a `KeyProvider` trait (testable with a fake provider, no hardware), and the real TPM provider (`tpm.rs`) calls the WinRT `KeyCredentialManager` API. `protec-gui` wires the existing `helloAvailable` seam: enable/disable commands, a Settings toggle, a first-run offer, and the lock-screen Hello button. The master-password wrap is never removed, so every Hello failure falls back to the password.

**Tech Stack:** Rust. The `windows` crate (already in the tree via Tauri) with the `Security_Credentials` feature for `KeyCredentialManager`. `zeroize`, `serde`. Envelope tests use `cargo test`; the raw TPM calls are verified by a manual checklist on a real machine.

**Environment (verified):** Rust 1.96 (cargo at `~/.cargo/bin`; PowerShell `$env:Path += ";$env:USERPROFILE\.cargo\bin"`). Tauri CLI 2.11. `windows` crate + `windows-core` already in Cargo.lock via Tauri. Use `--manifest-path "<repo>\Cargo.toml"` for cargo if `-p` won't resolve. Git: `-c user.name="dev" -c user.email="daman.apuri2000@gmail.com"`. Runs in a dedicated worktree created before execution.

**Existing seams this builds on:**
- `crates/protec-core/src/wrap.rs`: `pub enum WrapKind { MasterPassword, /* WindowsHello commented */ }`; `pub struct KeyWrap { kind, nonce, wrapped }` with `KeyWrap::seal(kind, wrapping_key: &[u8;32], vault_key: &[u8;32]) -> Result<KeyWrap, VaultError>` and `KeyWrap::open(&self, wrapping_key: &[u8;32]) -> Result<Zeroizing<[u8;32]>, VaultError>`. These do the envelope crypto generically.
- `crates/protec-core/src/vault.rs`: unlock finds the `MasterPassword` wrap via `header.wraps.iter().find(|w| w.kind == WrapKind::MasterPassword)`. `UnlockedVault` holds the vault key.
- `src/lib/components/LockScreen.svelte`: has `const helloAvailable = false;` and a hidden `{#if helloAvailable}` button.

---

## File Structure

```
Protec/
├── Cargo.toml                              # workspace — add "crates/protec-hello"
├── crates/
│   ├── protec-core/src/
│   │   ├── wrap.rs                          # add WindowsHello variant
│   │   └── vault.rs                         # add: export vault key, add/remove a wrap
│   └── protec-hello/                        # NEW crate
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs                       # public API: is_available/enable/unlock/disable
│           ├── envelope.rs                  # KeyProvider trait + wrap/unwrap (tested, no HW)
│           ├── error.rs                     # HelloError
│           └── tpm.rs                       # WinRT KeyCredentialManager provider (#[cfg(windows)])
├── src-tauri/src/
│   ├── commands/hello.rs                    # NEW: enable/disable/status commands
│   └── (main.rs registers them; Cargo.toml gains protec-hello dep)
└── src/lib/components/
    ├── LockScreen.svelte                    # wire helloAvailable + unlock-with-hello
    ├── Settings.svelte                      # add Hello toggle (gated on availability)
    └── FirstRun.svelte                      # add skippable Hello offer after create
```

---

## Phase A — protec-core: the WindowsHello wrap

### Task 1: Add the WindowsHello WrapKind variant

**Files:**
- Modify: `crates/protec-core/src/wrap.rs`

- [ ] **Step 1: Write the failing test**

In `crates/protec-core/src/wrap.rs`, replace the `WrapKind` enum (currently has `MasterPassword` and a commented `WindowsHello`) with:
```rust
/// Identifies which mechanism wraps the vault key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapKind {
    MasterPassword,
    WindowsHello,
}
```

Add a test to the existing `#[cfg(test)] mod tests` block in wrap.rs:
```rust
    #[test]
    fn windows_hello_wrap_round_trips() {
        // A Hello wrap uses a different wrapping key than the master-password wrap,
        // but the seal/open envelope is identical.
        let vault_key = [4u8; 32];
        let hello_key = [9u8; 32];
        let w = KeyWrap::seal(WrapKind::WindowsHello, &hello_key, &vault_key).unwrap();
        assert_eq!(w.kind, WrapKind::WindowsHello);
        assert_eq!(w.open(&hello_key).unwrap().as_ref(), &vault_key);
    }

    #[test]
    fn windows_hello_wrap_serde_round_trips() {
        let w = KeyWrap::seal(WrapKind::WindowsHello, &[9u8; 32], &[4u8; 32]).unwrap();
        let bytes = bincode::serialize(&w).unwrap();
        let back: KeyWrap = bincode::deserialize(&bytes).unwrap();
        assert_eq!(w, back);
        assert_eq!(back.kind, WrapKind::WindowsHello);
    }
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-core wrap::`
Expected: all wrap tests PASS including the 2 new ones.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/wrap.rs
git commit -m "feat(core): add WindowsHello WrapKind variant"
```

### Task 2: Vault key export + add/remove-wrap on UnlockedVault

**Files:**
- Modify: `crates/protec-core/src/vault.rs`

> Hello enable needs the vault key (to wrap it with the TPM key) and a way to add the
> resulting wrap to the header; disable needs to remove the Hello wrap. Unlock-via-Hello
> needs to open the body with a vault key recovered from the Hello wrap. We add three small
> methods to `UnlockedVault` and one to `LockedVault`. The vault key is exposed only from an
> already-`UnlockedVault` (you must already be unlocked to enable Hello), preserving the
> type-state guarantee.

- [ ] **Step 1: Write the failing test**

First, read `vault.rs` to find the `UnlockedVault` struct (it holds `vault_key: Zeroizing<[u8;32]>`, `header: Header`, `path`, `entries`) and the `Header` type (from `format.rs`, has `wraps: Vec<KeyWrap>`). Add these methods inside `impl UnlockedVault` (after the existing methods like `save`):
```rust
    /// Expose a copy of the vault key so an additional wrap (e.g. Windows Hello)
    /// can be created. Only available on an already-unlocked vault.
    pub fn vault_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.vault_key)
    }

    /// Add a pre-built key-wrap to the header and persist. Replaces any existing
    /// wrap of the same kind (so re-enabling Hello overwrites the old wrap).
    pub fn add_wrap(&mut self, wrap: crate::wrap::KeyWrap) -> Result<(), VaultError> {
        self.header.wraps.retain(|w| w.kind != wrap.kind);
        self.header.wraps.push(wrap);
        self.save()
    }

    /// Remove all wraps of the given kind and persist. The MasterPassword wrap
    /// must never be removed; callers must not pass WrapKind::MasterPassword.
    pub fn remove_wrap(&mut self, kind: crate::wrap::WrapKind) -> Result<(), VaultError> {
        if kind == crate::wrap::WrapKind::MasterPassword {
            return Err(VaultError::Corrupted); // guard: never remove the password wrap
        }
        self.header.wraps.retain(|w| w.kind != kind);
        self.save()
    }

    /// True if the header contains a wrap of the given kind.
    pub fn has_wrap(&self, kind: &crate::wrap::WrapKind) -> bool {
        self.header.wraps.iter().any(|w| &w.kind == kind)
    }
```
NOTE: confirm the field is named `vault_key` and is `Zeroizing<[u8;32]>` (deref-copy via `*self.vault_key` yields `[u8;32]`). If `save()` borrows `&self` (it does) there's no borrow conflict since `add_wrap`/`remove_wrap` take `&mut self` and call `save()` after mutating `self.header`. If `save()` reads `self.header` to re-encrypt, the mutation is already applied — correct.

Now add an unlock-via-arbitrary-wrap path on `LockedVault`. Read the existing `LockedVault::unlock` (master-password path). Add this method to `impl LockedVault`:
```rust
    /// Unlock using a vault key recovered from a non-password wrap (e.g. the
    /// Windows Hello wrap, whose wrapping key came from the TPM). The caller has
    /// already produced `wrapping_key` via the external mechanism.
    pub fn unlock_with_wrap(
        self,
        kind: crate::wrap::WrapKind,
        wrapping_key: &[u8; 32],
    ) -> Result<UnlockedVault, VaultError> {
        let wrap = self
            .file
            .header
            .wraps
            .iter()
            .find(|w| w.kind == kind)
            .ok_or(VaultError::Corrupted)?;
        let vault_key = wrap.open(wrapping_key)?;
        let entries = decrypt_body(&self.file, &vault_key)?;
        Ok(UnlockedVault {
            path: self.path,
            header: self.file.header,
            vault_key,
            entries,
            last_activity: std::time::Instant::now(),
        })
    }
```
NOTE: match the EXACT field names and the `decrypt_body` helper used by the existing `unlock`. Read `unlock` first and mirror its construction of `UnlockedVault` exactly (field names, `last_activity` init). If `unlock` uses a private helper to build the struct, reuse it.

Add tests to the `#[cfg(test)] mod tests` block in vault.rs:
```rust
    #[test]
    fn add_then_unlock_with_second_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();

        // Unlock with password, grab the vault key, add a Hello-style wrap under a
        // separate wrapping key, save.
        let hello_key = [7u8; 32];
        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            v.add(Entry::new("Site", 1));
            let vk = v.vault_key();
            let wrap = crate::wrap::KeyWrap::seal(
                crate::wrap::WrapKind::WindowsHello, &hello_key, &vk).unwrap();
            v.add_wrap(wrap).unwrap();
        }

        // Now unlock via the second wrap (no password) and see the entry.
        let v = Vault::open(&path).unwrap()
            .unlock_with_wrap(crate::wrap::WrapKind::WindowsHello, &hello_key).unwrap();
        assert_eq!(v.list_entries().len(), 1);
    }

    #[test]
    fn password_still_works_after_adding_hello_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            let vk = v.vault_key();
            let wrap = crate::wrap::KeyWrap::seal(
                crate::wrap::WrapKind::WindowsHello, &[7u8; 32], &vk).unwrap();
            v.add_wrap(wrap).unwrap();
        }
        // The golden rule: master password still unlocks.
        assert!(Vault::open(&path).unwrap().unlock("pw").is_ok());
    }

    #[test]
    fn remove_hello_wrap_keeps_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            let vk = v.vault_key();
            let wrap = crate::wrap::KeyWrap::seal(
                crate::wrap::WrapKind::WindowsHello, &[7u8; 32], &vk).unwrap();
            v.add_wrap(wrap).unwrap();
            v.remove_wrap(crate::wrap::WrapKind::WindowsHello).unwrap();
            assert!(!v.has_wrap(&crate::wrap::WrapKind::WindowsHello));
        }
        assert!(Vault::open(&path).unwrap().unlock("pw").is_ok());
    }

    #[test]
    fn cannot_remove_master_password_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        assert!(v.remove_wrap(crate::wrap::WrapKind::MasterPassword).is_err());
    }
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-core vault::`
Expected: all vault tests PASS including the 4 new ones.

- [ ] **Step 3: Run the full core suite**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-core`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/protec-core/src/vault.rs
git commit -m "feat(core): vault key export + add/remove wrap for Hello (golden-rule guarded)"
```

---

## Phase B — protec-hello crate: envelope (testable) + TPM provider

### Task 3: Scaffold protec-hello + the KeyProvider trait & envelope (no hardware)

**Files:**
- Create: `crates/protec-hello/Cargo.toml`, `crates/protec-hello/src/lib.rs`, `crates/protec-hello/src/error.rs`, `crates/protec-hello/src/envelope.rs`
- Modify: root `Cargo.toml`

- [ ] **Step 1: Add the crate to the workspace**

In root `Cargo.toml`, change members to include the new crate:
`members = ["crates/protec-core", "crates/protec-host", "crates/protec-hello", "src-tauri"]`

- [ ] **Step 2: Create `crates/protec-hello/Cargo.toml`**

```toml
[package]
name = "protec-hello"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
zeroize = "1"

[target.'cfg(windows)'.dependencies]
sha2 = "0.10"
windows = { version = "0.62", features = [
    "Security_Credentials",
    "Security_Cryptography",
    "Storage_Streams",
    "Foundation",
] }
```
NOTE: the `windows` crate major version must match what's already resolved in the workspace `Cargo.lock` (Tauri pulls `windows-core 0.62`). If `0.62` does not resolve for the `windows` crate itself, set the version to the one already in the lockfile (check `Cargo.lock` for `name = "windows"`). Report the version used.

- [ ] **Step 3: Create the error type**

Create `crates/protec-hello/src/error.rs`:
```rust
/// Errors from Windows Hello operations. All map to friendly, non-leaky messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// No TPM / Hello not configured on this device.
    Unavailable,
    /// The user cancelled or failed the Hello prompt.
    UserCancelled,
    /// The TPM key Protec created is missing (e.g. Hello/TPM was reset).
    KeyMissing,
    /// Any other failure (TPM busy, OS error). `0` is a short, safe label.
    Backend(String),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::Unavailable => write!(f, "Windows Hello is not available on this device"),
            HelloError::UserCancelled => write!(f, "Windows Hello was cancelled"),
            HelloError::KeyMissing => write!(f, "The Windows Hello key is missing — use your master password"),
            HelloError::Backend(_) => write!(f, "Windows Hello could not be used — use your master password"),
        }
    }
}

impl std::error::Error for HelloError {}
```

- [ ] **Step 4: Create the envelope (the testable core)**

Create `crates/protec-hello/src/envelope.rs`:
```rust
use crate::error::HelloError;
use zeroize::Zeroizing;

/// Abstracts the source of the 32-byte wrapping key. The real implementation
/// (tpm.rs) derives it from a TPM-bound, Hello-gated credential. Tests use a
/// fake provider so the envelope logic is verifiable without hardware.
pub trait KeyProvider {
    /// Produce the 32-byte wrapping key, prompting Hello if needed.
    /// Called for both enable (to wrap) and unlock (to unwrap).
    fn wrapping_key(&self) -> Result<Zeroizing<[u8; 32]>, HelloError>;
}

/// The data persisted alongside a Hello wrap that the provider needs to
/// reproduce the same wrapping key later. For the TPM provider this is empty
/// (the key lives in the TPM, addressed by a fixed container name), but the
/// type leaves room for per-vault salt if a future provider needs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HelloWrapData;

/// Compute the wrapping key for enabling Hello on a vault. Returns the 32-byte
/// key the caller passes to `KeyWrap::seal(WrapKind::WindowsHello, key, vault_key)`.
pub fn wrapping_key_for_enable(provider: &impl KeyProvider)
    -> Result<Zeroizing<[u8; 32]>, HelloError>
{
    provider.wrapping_key()
}

/// Compute the wrapping key for unlocking via Hello. Same key the enable step
/// produced (the provider is deterministic for a given device + credential).
pub fn wrapping_key_for_unlock(provider: &impl KeyProvider)
    -> Result<Zeroizing<[u8; 32]>, HelloError>
{
    provider.wrapping_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic fake provider — returns a fixed key. Stands in for the TPM.
    struct FakeProvider {
        key: [u8; 32],
        fail: Option<HelloError>,
    }
    impl KeyProvider for FakeProvider {
        fn wrapping_key(&self) -> Result<Zeroizing<[u8; 32]>, HelloError> {
            if let Some(e) = &self.fail {
                return Err(e.clone());
            }
            Ok(Zeroizing::new(self.key))
        }
    }

    #[test]
    fn enable_and_unlock_produce_the_same_key() {
        let p = FakeProvider { key: [3u8; 32], fail: None };
        let a = wrapping_key_for_enable(&p).unwrap();
        let b = wrapping_key_for_unlock(&p).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn provider_failure_propagates() {
        let p = FakeProvider { key: [0u8; 32], fail: Some(HelloError::UserCancelled) };
        assert_eq!(wrapping_key_for_unlock(&p), Err(HelloError::UserCancelled));
    }

    /// End-to-end envelope check using protec-core's KeyWrap with the fake key:
    /// wrap a vault key with the provider's key, then unwrap it. This proves the
    /// Hello wrap integrates with the core envelope without any TPM.
    #[test]
    fn envelope_round_trip_via_core_keywrap() {
        let p = FakeProvider { key: [5u8; 32], fail: None };
        let vault_key = [8u8; 32];
        let wk = wrapping_key_for_enable(&p).unwrap();
        let wrap = protec_core::KeyWrap::seal(
            protec_core::WrapKind::WindowsHello, &wk, &vault_key).unwrap();
        let wk2 = wrapping_key_for_unlock(&p).unwrap();
        let recovered = wrap.open(&wk2).unwrap();
        assert_eq!(recovered.as_ref(), &vault_key);
    }
}
```
NOTE: this test imports `protec_core::{KeyWrap, WrapKind}`. Add `protec-core = { path = "../protec-core" }` to `protec-hello`'s `[dev-dependencies]` so the test compiles (keep it a dev-dependency — the envelope itself doesn't need core, only the integration test does). Also confirm `KeyWrap` and `WrapKind` are re-exported from `protec_core` (check `crates/protec-core/src/lib.rs`); if they are NOT public, add `pub use wrap::{KeyWrap, WrapKind};` to core's lib.rs in this task and commit that with it.

- [ ] **Step 5: Create the lib.rs public API (envelope-only for now; TPM in Task 4)**

Create `crates/protec-hello/src/lib.rs`:
```rust
//! Optional Windows Hello unlock for Protec: a TPM-bound, Hello-gated second
//! wrap of the vault key. The master-password wrap is never removed, so Hello
//! is always strictly additive.

mod envelope;
mod error;

pub use envelope::{wrapping_key_for_enable, wrapping_key_for_unlock, HelloWrapData, KeyProvider};
pub use error::HelloError;

#[cfg(windows)]
mod tpm;

/// True if this device can use Windows Hello (TPM present + Hello configured).
/// On non-Windows builds this is always false.
pub fn is_available() -> bool {
    #[cfg(windows)]
    {
        tpm::is_available()
    }
    #[cfg(not(windows))]
    {
        false
    }
}
```
NOTE: `tpm` is created in Task 4. For THIS task, create a stub `crates/protec-hello/src/tpm.rs` containing:
```rust
// Real TPM provider implemented in Task 4.
pub fn is_available() -> bool {
    false
}
```
so the crate compiles now.

- [ ] **Step 6: Test + build**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-hello`
Expected: 3 envelope tests PASS.
Run: `cargo build --manifest-path "<repo>\Cargo.toml" -p protec-hello`
Expected: compiles.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/protec-hello/ crates/protec-core/src/lib.rs
git commit -m "feat(hello): scaffold crate + tested envelope (KeyProvider trait, no hardware)"
```

### Task 4: The real TPM provider (KeyCredentialManager) — Windows, manual-verified

**Files:**
- Modify: `crates/protec-hello/src/tpm.rs`, `crates/protec-hello/src/lib.rs`

> This is the only file with Windows FFI. It uses the WinRT `KeyCredentialManager`
> API (in the `windows` crate). The functions cannot be unit-tested in CI (no TPM/biometric),
> so they are kept minimal and behind the `is_available` gate; correctness is verified by the
> manual checklist in Task 8. The provider derives a STABLE 32-byte wrapping key from a signed
> challenge: the TPM key signs a fixed constant, and we hash the signature to 32 bytes — the
> same input yields the same key, so enable and unlock agree.

- [ ] **Step 1: Implement the TPM provider**

Replace `crates/protec-hello/src/tpm.rs` with:
```rust
//! Windows Hello TPM provider via the WinRT KeyCredentialManager API.
//! Not unit-tested (requires real TPM + biometric); verified by manual checklist.

use crate::envelope::KeyProvider;
use crate::error::HelloError;
use zeroize::Zeroizing;
use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};

/// Fixed container name for Protec's Hello credential. Creating/using/deleting
/// THIS name never touches any other key.
const CRED_NAME: &str = "dev.protec.hello";

/// A fixed challenge the TPM key signs; the signature is hashed to the wrapping
/// key. Constant input => stable key across enable and unlock.
const CHALLENGE: &[u8] = b"protec-hello-wrapping-key-v1";

/// True if Hello is usable on this device.
pub fn is_available() -> bool {
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|op| op.get())
        .unwrap_or(false)
}

/// Ensure Protec's Hello credential exists (creating it prompts Hello once).
fn ensure_credential() -> Result<(), HelloError> {
    let name = HSTRING::from(CRED_NAME);
    // Try to open; if absent, create.
    if let Ok(op) = KeyCredentialManager::OpenAsync(&name) {
        if let Ok(res) = op.get() {
            if res.Status().map_err(|e| HelloError::Backend(e.code().0.to_string()))?
                == KeyCredentialStatus::Success
            {
                return Ok(());
            }
        }
    }
    let op = KeyCredentialManager::RequestCreateAsync(
        &name,
        KeyCredentialCreationOption::FailIfExists,
    )
    .map_err(|e| HelloError::Backend(e.code().0.to_string()))?;
    let res = op.get().map_err(|_| HelloError::UserCancelled)?;
    match res.Status() {
        Ok(KeyCredentialStatus::Success) => Ok(()),
        Ok(KeyCredentialStatus::CredentialAlreadyExists) => Ok(()),
        Ok(KeyCredentialStatus::UserCanceled) => Err(HelloError::UserCancelled),
        _ => Err(HelloError::Backend("create failed".into())),
    }
}

/// Delete Protec's Hello credential (used by disable).
pub fn delete_credential() -> Result<(), HelloError> {
    let name = HSTRING::from(CRED_NAME);
    KeyCredentialManager::DeleteAsync(&name)
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?
        .get()
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?;
    Ok(())
}

/// Sign the fixed challenge with Protec's Hello key (prompts Hello), then hash
/// the signature to a stable 32-byte wrapping key.
fn derive_wrapping_key() -> Result<Zeroizing<[u8; 32]>, HelloError> {
    ensure_credential()?;
    let name = HSTRING::from(CRED_NAME);
    let res = KeyCredentialManager::OpenAsync(&name)
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?
        .get()
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?;
    match res.Status() {
        Ok(KeyCredentialStatus::Success) => {}
        Ok(KeyCredentialStatus::NotFound) => return Err(HelloError::KeyMissing),
        _ => return Err(HelloError::Backend("open failed".into())),
    }
    let cred = res.Credential().map_err(|e| HelloError::Backend(e.code().0.to_string()))?;

    // Build an IBuffer from the challenge and request a signature (prompts Hello).
    let buf = crypto_buffer_from(CHALLENGE)?;
    let sign_op = cred
        .RequestSignAsync(&buf)
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?;
    let sign_res = sign_op.get().map_err(|_| HelloError::UserCancelled)?;
    match sign_res.Status() {
        Ok(KeyCredentialStatus::Success) => {}
        Ok(KeyCredentialStatus::UserCanceled) => return Err(HelloError::UserCancelled),
        Ok(KeyCredentialStatus::NotFound) => return Err(HelloError::KeyMissing),
        _ => return Err(HelloError::Backend("sign failed".into())),
    }
    let sig = sign_res.Result().map_err(|e| HelloError::Backend(e.code().0.to_string()))?;
    let sig_bytes = Zeroizing::new(ibuffer_to_vec(&sig)?);

    // Derive the 32-byte wrapping key as SHA-256 of the TPM signature. The
    // signature is deterministic for a fixed challenge + this device's key, so
    // enable and unlock produce the same key. SHA-256 normalizes length and
    // domain-separates from the raw signature.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"protec-hello-kdf-v1");
    hasher.update(&sig_bytes);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(Zeroizing::new(key))
}

fn crypto_buffer_from(bytes: &[u8]) -> Result<windows::Storage::Streams::IBuffer, HelloError> {
    use windows::Security::Cryptography::CryptographicBuffer;
    CryptographicBuffer::CreateFromByteArray(bytes)
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))
}

fn ibuffer_to_vec(buf: &windows::Storage::Streams::IBuffer) -> Result<Vec<u8>, HelloError> {
    use windows::Security::Cryptography::CryptographicBuffer;
    let mut out = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buf, &mut out)
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?;
    Ok(out.as_slice().to_vec())
}

/// The provider the GUI uses.
pub struct TpmProvider;

impl KeyProvider for TpmProvider {
    fn wrapping_key(&self) -> Result<Zeroizing<[u8; 32]>, HelloError> {
        derive_wrapping_key()
    }
}
```
NOTE on the `windows` crate features: `RequestSignAsync`/`CryptographicBuffer` require the `Security_Cryptography` feature and `Storage_Streams`. Update `crates/protec-hello/Cargo.toml`'s windows features to:
```toml
features = [
    "Security_Credentials",
    "Security_Cryptography",
    "Storage_Streams",
    "Foundation",
]
```
The exact method names (`RequestCreateAsync`, `OpenAsync`, `RequestSignAsync`, `DeleteAsync`, `Status`, `Credential`, `Result`) are from the WinRT `KeyCredentialManager`/`KeyCredential` API as exposed by the `windows` crate. If a name differs slightly in the resolved crate version, adjust to the crate's actual API (the implementer should run `cargo build` and fix signatures against compiler errors) WITHOUT changing the logic: ensure-create, open, sign-challenge, hash-to-32-bytes, delete. Report any API adjustments.

- [ ] **Step 2: Export the provider + enable/unlock/disable in lib.rs**

Add to `crates/protec-hello/src/lib.rs` (Windows-only public surface):
```rust
#[cfg(windows)]
pub use tpm::TpmProvider;

/// Produce the wrapping key to ENABLE Hello (prompts Hello, creates the TPM key
/// if needed). The caller seals the vault key with this via core's KeyWrap.
#[cfg(windows)]
pub fn enable_wrapping_key() -> Result<zeroize::Zeroizing<[u8; 32]>, HelloError> {
    use envelope::wrapping_key_for_enable;
    wrapping_key_for_enable(&tpm::TpmProvider)
}

/// Produce the wrapping key to UNLOCK via Hello (prompts Hello).
#[cfg(windows)]
pub fn unlock_wrapping_key() -> Result<zeroize::Zeroizing<[u8; 32]>, HelloError> {
    use envelope::wrapping_key_for_unlock;
    wrapping_key_for_unlock(&tpm::TpmProvider)
}

/// Delete Protec's TPM credential (DISABLE Hello).
#[cfg(windows)]
pub fn disable() -> Result<(), HelloError> {
    tpm::delete_credential()
}
```

- [ ] **Step 3: Build on Windows**

Run: `cargo build --manifest-path "<repo>\Cargo.toml" -p protec-hello`
Expected: compiles on Windows. Fix any `windows`-crate API signature mismatches against compiler errors (report them). The envelope tests still pass: `cargo test --manifest-path "<repo>\Cargo.toml" -p protec-hello` (3 pass; the TPM code has no unit tests).

- [ ] **Step 4: Commit**

```bash
git add crates/protec-hello/src/tpm.rs crates/protec-hello/src/lib.rs crates/protec-hello/Cargo.toml
git commit -m "feat(hello): TPM provider via KeyCredentialManager (manual-verified)"
```

---

## Phase C — protec-gui wiring

### Task 5: Hello commands (status/enable/disable)

**Files:**
- Create: `src-tauri/src/commands/hello.rs`
- Modify: `src-tauri/src/commands/mod.rs`, `src-tauri/src/main.rs`, `src-tauri/Cargo.toml`

- [ ] **Step 1: Add the dependency**

In `src-tauri/Cargo.toml` `[dependencies]`, add:
`protec-hello = { path = "../crates/protec-hello" }`

- [ ] **Step 2: Create the commands**

Create `src-tauri/src/commands/hello.rs`:
```rust
use crate::state::{AppState, VaultSlot};
use protec_core::{KeyWrap, WrapKind};
use tauri::State;

/// Whether this device supports Windows Hello AND the open vault has a Hello wrap.
#[derive(serde::Serialize)]
pub struct HelloStatus {
    pub available: bool,
    pub enabled: bool,
}

#[tauri::command]
pub fn hello_status(state: State<AppState>) -> HelloStatus {
    let available = protec_hello::is_available();
    let enabled = {
        let inner = state.lock();
        match &inner.slot {
            VaultSlot::Unlocked(v) => v.has_wrap(&WrapKind::WindowsHello),
            VaultSlot::Locked => false,
        }
    };
    HelloStatus { available, enabled }
}

/// Enable Hello: requires the vault unlocked. Prompts Hello, wraps the vault key,
/// adds the WindowsHello wrap. Never removes the master-password wrap.
#[tauri::command]
pub fn hello_enable(state: State<AppState>) -> Result<(), String> {
    if !protec_hello::is_available() {
        return Err("Windows Hello is not available on this device".into());
    }
    // Snapshot the vault key under the lock, then drop the lock before the Hello prompt.
    let vault_key = {
        let inner = state.lock();
        match &inner.slot {
            VaultSlot::Unlocked(v) => v.vault_key(),
            VaultSlot::Locked => return Err("Unlock the vault first".into()),
        }
    };
    let wrapping_key = hello_wrapping_key_enable().map_err(|e| e.to_string())?;
    let wrap = KeyWrap::seal(WrapKind::WindowsHello, &wrapping_key, &vault_key)
        .map_err(|_| "Failed to wrap the vault key".to_string())?;
    let mut inner = state.lock();
    match &mut inner.slot {
        VaultSlot::Unlocked(v) => v.add_wrap(wrap).map_err(|_| "Failed to save".to_string()),
        VaultSlot::Locked => Err("Vault locked".into()),
    }
}

/// Disable Hello: remove the WindowsHello wrap + delete the TPM key. Master
/// password unaffected.
#[tauri::command]
pub fn hello_disable(state: State<AppState>) -> Result<(), String> {
    {
        let mut inner = state.lock();
        if let VaultSlot::Unlocked(v) = &mut inner.slot {
            // Remove the wrap first (the vault is the source of truth).
            let _ = v.remove_wrap(WrapKind::WindowsHello);
        } else {
            return Err("Unlock the vault first".into());
        }
    }
    // Best-effort TPM key delete; a failure here is non-fatal (wrap already gone).
    let _ = hello_delete_key();
    Ok(())
}

// ---- platform shims so non-Windows builds compile ----
#[cfg(windows)]
fn hello_wrapping_key_enable() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    protec_hello::enable_wrapping_key()
}
#[cfg(not(windows))]
fn hello_wrapping_key_enable() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    Err(protec_hello::HelloError::Unavailable)
}
#[cfg(windows)]
fn hello_delete_key() -> Result<(), protec_hello::HelloError> {
    protec_hello::disable()
}
#[cfg(not(windows))]
fn hello_delete_key() -> Result<(), protec_hello::HelloError> {
    Ok(())
}
```
NOTE: this needs `zeroize` available in `src-tauri`. If not already a dep, add `zeroize = "1"` to `src-tauri/Cargo.toml`. Also requires `protec_core::{KeyWrap, WrapKind}` to be public — ensured in Task 3 Step 4. `AppState::lock()` is the poison-recovering helper.

- [ ] **Step 3: Add an unlock-with-hello command (for the lock screen)**

Append to `src-tauri/src/commands/hello.rs`:
```rust
/// Unlock the vault using Windows Hello (lock screen path). Prompts Hello,
/// recovers the vault key from the WindowsHello wrap. On any failure the caller
/// falls back to the master-password field.
#[tauri::command]
pub fn hello_unlock(state: State<AppState>) -> Result<(), String> {
    if !protec_hello::is_available() {
        return Err("Windows Hello is not available".into());
    }
    let wrapping_key = hello_wrapping_key_unlock().map_err(|e| e.to_string())?;
    let mut inner = state.lock();
    // Open the vault file fresh and unlock via the Hello wrap.
    let path = inner.vault_path.clone();
    let locked = protec_core::Vault::open(&path).map_err(|_| "Could not open vault".to_string())?;
    let unlocked = locked
        .unlock_with_wrap(WrapKind::WindowsHello, &wrapping_key)
        .map_err(|_| "Windows Hello unlock failed — use your master password".to_string())?;
    inner.slot = VaultSlot::Unlocked(unlocked);
    Ok(())
}

#[cfg(windows)]
fn hello_wrapping_key_unlock() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    protec_hello::unlock_wrapping_key()
}
#[cfg(not(windows))]
fn hello_wrapping_key_unlock() -> Result<zeroize::Zeroizing<[u8; 32]>, protec_hello::HelloError> {
    Err(protec_hello::HelloError::Unavailable)
}
```

- [ ] **Step 4: Register the commands**

In `src-tauri/src/commands/mod.rs`, add `pub mod hello;`.
In `src-tauri/src/main.rs` `generate_handler!`, append:
`commands::hello::hello_status, commands::hello::hello_enable, commands::hello::hello_disable, commands::hello::hello_unlock`

- [ ] **Step 5: Build**

Run: `cargo build --manifest-path "<repo>\Cargo.toml" -p protec-gui`
Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/commands/hello.rs src-tauri/src/commands/mod.rs src-tauri/src/main.rs src-tauri/Cargo.toml
git commit -m "feat(gui): Hello status/enable/disable/unlock commands"
```

### Task 6: Frontend — lock screen, settings toggle, first-run offer

**Files:**
- Modify: `src/lib/api.ts`, `src/lib/components/LockScreen.svelte`, `src/lib/components/Settings.svelte`, `src/lib/components/FirstRun.svelte`

- [ ] **Step 1: Add the api methods**

In `src/lib/api.ts`, add to the `api` object (read the file to match the existing style — each method wraps `invoke`):
```ts
  helloStatus: () => invoke<{ available: boolean; enabled: boolean }>("hello_status"),
  helloEnable: () => invoke<void>("hello_enable"),
  helloDisable: () => invoke<void>("hello_disable"),
  helloUnlock: () => invoke<void>("hello_unlock"),
```

- [ ] **Step 2: Wire the lock screen**

In `src/lib/components/LockScreen.svelte`, replace the hardcoded `const helloAvailable = false;` with real detection and add the unlock handler. Read the file first; update the `<script>`:
```ts
  import { onMount } from "svelte";
  // ...existing imports (api, unlocked, invoke)...
  let helloAvailable = false;

  onMount(async () => {
    try {
      const s = await api.helloStatus();
      helloAvailable = s.available && s.enabled;
    } catch {
      helloAvailable = false;
    }
    // Offer Hello first if available.
    if (helloAvailable) void unlockWithHello();
  });

  async function unlockWithHello() {
    try {
      await api.helloUnlock();
      unlocked.set(true);
    } catch (e) {
      // Fall back silently to the master-password field.
      error = "Use your master password.";
    }
  }
```
And in the markup, replace the existing hidden `{#if helloAvailable}` button with a working one:
```svelte
  {#if helloAvailable}
    <button class="hello" on:click={unlockWithHello}>Unlock with Windows Hello</button>
  {/if}
```
(Keep the master-password input and Unlock button exactly as they are — always visible.)

- [ ] **Step 3: Add the Settings toggle (gated on availability)**

In `src/lib/components/Settings.svelte`, read the file. Add Hello state + handlers in `<script>`:
```ts
  let helloAvailable = false;
  let helloEnabled = false;

  // inside the existing onMount (after loading cfg), add:
  try {
    const s = await api.helloStatus();
    helloAvailable = s.available;
    helloEnabled = s.enabled;
  } catch { helloAvailable = false; }

  async function toggleHello() {
    try {
      if (helloEnabled) {
        await api.helloDisable();
        helloEnabled = false;
      } else {
        await api.helloEnable();
        helloEnabled = true;
      }
    } catch (e) {
      // surface a friendly message; leave state unchanged on failure
      alert(String(e));
    }
  }
```
And in the markup, add (only when available) a row:
```svelte
    {#if helloAvailable}
      <label>Unlock with Windows Hello
        <input type="checkbox" checked={helloEnabled} on:change={toggleHello} />
      </label>
      <p class="hint">Your master password will still work.</p>
    {/if}
```
(Match the existing Settings styling; if there's no `.hint` class, add a small dim-text style or reuse an existing one.)

- [ ] **Step 4: Add the first-run offer**

In `src/lib/components/FirstRun.svelte`, read the file. After a successful vault create + unlock (the existing `create()` sets `unlocked`/`vaultExists`), instead of immediately routing away, show a one-time skippable offer if Hello is available. Add to `<script>`:
```ts
  let offerHello = false;

  // In create(), after `await api.createVault(pw); await api.unlock(pw);`
  // and BEFORE setting the stores that route to main, check availability:
  // (Replace the store-setting tail of create() with:)
  //   const s = await api.helloStatus().catch(() => ({ available: false, enabled: false }));
  //   if (s.available) { offerHello = true; }  // show the offer card
  //   else { vaultExists.set(true); unlocked.set(true); }

  async function acceptHello() {
    try { await api.helloEnable(); } catch { /* ignore; password still works */ }
    vaultExists.set(true);
    unlocked.set(true);
  }
  function skipHello() {
    vaultExists.set(true);
    unlocked.set(true);
  }
```
And add the offer card to the markup (shown when `offerHello`):
```svelte
  {#if offerHello}
    <div class="offer">
      <p>Enable Windows Hello unlock? You can also do this later in Settings.</p>
      <p class="hint">Your master password will still work.</p>
      <div class="row">
        <button class="primary" on:click={acceptHello}>Enable Windows Hello</button>
        <button on:click={skipHello}>Skip</button>
      </div>
    </div>
  {/if}
```
Adjust `create()` exactly as the comments describe: on success, if Hello is available set `offerHello = true` (and do NOT yet flip the routing stores); the user's Enable/Skip choice flips them. If Hello is unavailable, flip the stores immediately as before. Read the current `create()` body and integrate cleanly.

- [ ] **Step 5: Build the frontend**

Run: `npm run build`
Expected: `dist/` builds (a11y warnings OK).
Run: `npm run test`
Expected: existing frontend tests still pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib/api.ts src/lib/components/LockScreen.svelte src/lib/components/Settings.svelte src/lib/components/FirstRun.svelte
git commit -m "feat(gui): Hello lock-screen unlock, settings toggle, first-run offer"
```

---

## Phase D — Integration, CI, docs

### Task 7: Workspace tests, clippy/fmt, CI, README

**Files:**
- Modify: `.github/workflows/ci.yml`, `README.md`

- [ ] **Step 1: Full Rust suite + lint/fmt**

Run: `cargo test --manifest-path "<repo>\Cargo.toml" --workspace`
Expected: all pass (core incl. new wrap/vault tests, hello envelope 3, host, gui).
Run: `cargo clippy --manifest-path "<repo>\Cargo.toml" --workspace --all-targets -- -D warnings`
Fix any warnings minimally (the `windows`-FFI file may need targeted `#[allow]` for unavoidable lints; justify each). Re-run until clean.
Run: `cargo fmt --manifest-path "<repo>\Cargo.toml" --all` then `--all -- --check` (clean). Re-run tests after fmt.

- [ ] **Step 2: Extend CI with the hello crate**

In `.github/workflows/ci.yml`, add a `hello` job (it must run on Windows because the TPM code is Windows-only):
```yaml
  hello:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - run: cargo clippy -p protec-hello --all-targets -- -D warnings
      - run: cargo test -p protec-hello
      - run: cargo build -p protec-hello
```
(The `gui` job already covers `protec-gui` which now depends on `protec-hello`.)

- [ ] **Step 3: Update README**

Append to `README.md` a subsection under the security/usage area:
```markdown
### Windows Hello unlock (optional)

On devices with a TPM and Windows Hello configured, Protec can unlock with your
fingerprint, face, or PIN in addition to your master password. It is **opt-in**
(enable it in Settings, or accept the offer when you first create your vault) and
**additive** — your master password always still works. Hello uses a
non-exportable, machine-bound TPM key; disabling it deletes that key. On devices
without Hello, the option simply doesn't appear.
```
Also add a `protec-hello` row to the Components table ("available (dev)", "optional Windows Hello unlock").

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci+docs: build/test protec-hello on Windows; document Hello unlock"
```

### Task 8: Manual verification checklist (operator-run, real TPM machine)

**Files:**
- Create: `docs/protec-hello-smoke.md`

- [ ] **Step 1: Write the checklist**

Create `docs/protec-hello-smoke.md`:
```markdown
# Protec — Windows Hello manual smoke checklist

Run on a real Windows machine with a TPM + Windows Hello configured.

1. Build & run: `cargo tauri build` then launch the exe.
2. **First-run offer:** create a new vault → the "Enable Windows Hello?" card appears →
   click Enable → Hello prompts → succeeds → main view opens.
3. **Hello unlock:** Lock (Ctrl+L) → lock screen auto-offers Hello (or click the button) →
   fingerprint/PIN → vault unlocks.
4. **Golden rule:** Lock → ignore Hello → type the master password → still unlocks.
5. **Settings toggle:** Settings → "Unlock with Windows Hello" shows enabled → toggle OFF →
   the lock-screen Hello button disappears on next lock → toggle ON again → Hello prompts.
6. **Cancel fallback:** Lock → start Hello → cancel the prompt → the master-password field is
   right there and works.
7. **Disable cleanup:** disable Hello → confirm the TPM credential is gone (it will re-prompt
   to create on next enable).
8. **Unsupported device (if available):** on a machine without Hello, confirm neither the
   Settings toggle nor the lock-screen button appear, and no errors occur.
```

- [ ] **Step 2: Commit**

```bash
git add docs/protec-hello-smoke.md
git commit -m "docs(hello): manual smoke checklist for real-TPM verification"
```

---

## Definition of Done

- `cargo test --workspace` passes: core (WindowsHello wrap round-trip, add/unlock/remove wrap, golden-rule + cannot-remove-password tests), protec-hello envelope (3 tests with the fake provider), host, gui.
- `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --all -- --check` clean.
- `protec-hello` builds on Windows (TPM provider compiles against the `windows` crate).
- The master-password wrap is never removed; `cannot_remove_master_password_wrap` enforces it; `password_still_works_after_adding_hello_wrap` proves the golden rule.
- GUI: Settings toggle and lock-screen button render only when Hello is available; first-run offers Hello and is skippable; every Hello failure falls back to the master-password field.
- CI builds + tests `protec-hello` on Windows.
- README documents Hello as optional/opt-in/additive; manual smoke checklist committed.

## Manual verification (post-implementation — needs a real TPM+Hello machine)

The raw TPM/biometric path cannot be unit-tested. After implementation, the operator runs
`docs/protec-hello-smoke.md` on a real machine to verify enable / Hello-unlock / golden-rule
fallback / disable / unsupported-device behavior.
