# protec-core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `protec-core`, a Rust library crate that securely stores and retrieves secrets — encrypted at rest, unlocked by a master password, with a compile-time-enforced locked/unlocked API.

**Architecture:** Envelope encryption — a random vault key encrypts secrets (XChaCha20-Poly1305 AEAD); the master key (Argon2id-derived) *wraps* the vault key. The on-disk format stores a *list* of key-wraps so Windows Hello can later add a second wrap with no re-encryption. A type-state API (`LockedVault` vs `UnlockedVault`) makes reading a secret from a locked vault a compile error. All key material is `zeroize`-wiped on drop.

**Tech Stack:** Rust (2021 edition), `argon2`, `chacha20poly1305`, `zeroize`/`secrecy`, `serde` + `bincode`, `uuid`, `thiserror`. Tests via built-in `cargo test`.

---

## File Structure

Cargo workspace at repo root; the core lives in its own crate so future clients (`protec-cli`, `protec-gui`) join the workspace later.

```
Protec/
├── Cargo.toml                      # workspace manifest (members = ["crates/protec-core"])
├── crates/
│   └── protec-core/
│       ├── Cargo.toml              # crate manifest + deps
│       └── src/
│           ├── lib.rs              # public re-exports, crate docs
│           ├── error.rs            # VaultError enum
│           ├── crypto.rs           # KDF + AEAD primitives (derive_key, encrypt, decrypt)
│           ├── wrap.rs             # KeyWrap: wrap/unwrap the vault key
│           ├── entry.rs            # Entry, Totp, CustomField models
│           ├── format.rs           # on-disk header + body (de)serialization, version byte
│           ├── storage.rs          # atomic file read/write + .bak
│           └── vault.rs            # Vault / LockedVault / UnlockedVault state machine
```

Responsibilities are split so each file holds one concern and stays small. `crypto.rs` knows nothing about files; `storage.rs` knows nothing about crypto; `vault.rs` composes them.

---

## Task 0: Prerequisite — Install Rust toolchain

**This is a one-time environment step, not code.**

- [ ] **Step 1: Install rustup (Windows)**

Download and run the installer from https://rustup.rs (or `winget install Rustlang.Rustup`). Accept defaults (stable toolchain, MSVC).

- [ ] **Step 2: Verify in a fresh shell**

Run: `cargo --version && rustc --version`
Expected: both print version strings (e.g. `cargo 1.8x.x`, `rustc 1.8x.x`). If "command not found", open a new terminal so the updated PATH is loaded.

- [ ] **Step 3: Install component for formatting/linting**

Run: `rustup component add clippy rustfmt`
Expected: `info: installing component 'clippy'` / `'rustfmt'` (or "up to date").

---

## Task 1: Workspace + crate skeleton

**Files:**
- Create: `Cargo.toml` (workspace)
- Create: `crates/protec-core/Cargo.toml`
- Create: `crates/protec-core/src/lib.rs`

- [ ] **Step 1: Create the workspace manifest**

Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/protec-core"]

[workspace.package]
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/USERNAME/protec"
```

- [ ] **Step 2: Create the crate manifest**

Create `crates/protec-core/Cargo.toml`:

```toml
[package]
name = "protec-core"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
argon2 = "0.5"
chacha20poly1305 = "0.10"
zeroize = { version = "1", features = ["derive"] }
secrecy = "0.8"
serde = { version = "1", features = ["derive"] }
bincode = "1"
uuid = { version = "1", features = ["v4", "serde"] }
thiserror = "1"
rand_core = { version = "0.6", features = ["getrandom"] }

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Create the crate root**

Create `crates/protec-core/src/lib.rs`:

```rust
//! protec-core: secure local vault engine.
//!
//! Envelope encryption (Argon2id + XChaCha20-Poly1305) with a compile-time
//! locked/unlocked API. No UI, no network.

mod error;

pub use error::VaultError;
```

> Note: each later task adds its own `mod <name>;` and any `pub use` lines to this file as
> that module is created. This keeps `lib.rs` always-compilable after every task. The
> module-creation step in Tasks 3–9 explicitly says which line to add.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/protec-core/Cargo.toml crates/protec-core/src/lib.rs
git commit -m "chore: scaffold protec-core workspace and crate"
```

---

## Task 2: Error type

**Files:**
- Create: `crates/protec-core/src/error.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/protec-core/src/error.rs`:

```rust
use thiserror::Error;

/// All fallible operations in protec-core return `Result<_, VaultError>`.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("incorrect master password")]
    WrongPassword,
    #[error("vault file is corrupted")]
    Corrupted,
    #[error("vault authentication failed (data was tampered with)")]
    Tampered,
    #[error("vault format version {0} is not supported")]
    VersionUnsupported(u8),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_password_and_tampered_have_distinct_variants_but_generic_messages() {
        assert_eq!(VaultError::WrongPassword.to_string(), "incorrect master password");
        assert_eq!(
            VaultError::Tampered.to_string(),
            "vault authentication failed (data was tampered with)"
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p protec-core error::`
Expected: PASS. (`lib.rs` from Task 1 declares only `mod error;`, so the crate compiles with just this module present.)

- [ ] **Step 3: (implementation already written in Step 1)**

The enum is the implementation. No additional code needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p protec-core error::`
Expected: `test error::tests::wrong_password_and_tampered_... ok`

- [ ] **Step 5: Commit**

```bash
git add crates/protec-core/src/error.rs
git commit -m "feat: add VaultError type"
```

---

## Task 3: Crypto primitives — key derivation

**Files:**
- Create: `crates/protec-core/src/crypto.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/protec-core/src/crypto.rs`:

```rust
use crate::error::VaultError;
use argon2::{Argon2, Algorithm, Params, Version};
use zeroize::Zeroizing;

/// Parameters for Argon2id, stored in the vault header so they travel with the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub salt: [u8; 16],
    pub mem_kib: u32,
    pub iters: u32,
    pub lanes: u32,
}

impl KdfParams {
    /// Sensible defaults tuned for ~250-500ms on a typical machine.
    pub fn recommended(salt: [u8; 16]) -> Self {
        Self { salt, mem_kib: 19_456, iters: 2, lanes: 1 }
    }
}

/// Derive a 32-byte master key from the password + params. Output is zeroized on drop.
pub fn derive_key(password: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(p.mem_kib, p.iters, p.lanes, Some(32))
        .map_err(|_| VaultError::Corrupted)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, &p.salt, out.as_mut())
        .map_err(|_| VaultError::Corrupted)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_for_same_inputs() {
        let p = KdfParams::recommended([7u8; 16]);
        let a = derive_key(b"hunter2", &p).unwrap();
        let b = derive_key(b"hunter2", &p).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn derive_differs_for_different_passwords() {
        let p = KdfParams::recommended([7u8; 16]);
        let a = derive_key(b"hunter2", &p).unwrap();
        let b = derive_key(b"hunter3", &p).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn derive_differs_for_different_salts() {
        let a = derive_key(b"hunter2", &KdfParams::recommended([1u8; 16])).unwrap();
        let b = derive_key(b"hunter2", &KdfParams::recommended([2u8; 16])).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }
}
```

Add the line `mod crypto;` to `lib.rs` (after `mod error;`).

- [ ] **Step 2: Run test to verify it fails / then passes**

Run: `cargo test -p protec-core crypto::`
Expected: compiles and PASSES all three (the implementation is in Step 1; the "failing" state here is the pre-code compile error if you run before pasting).

- [ ] **Step 3: Verify zeroization type is in use**

Confirm `derive_key` returns `Zeroizing<[u8; 32]>` (already in Step 1). No extra code.

- [ ] **Step 4: Commit**

```bash
git add crates/protec-core/src/crypto.rs crates/protec-core/src/lib.rs
git commit -m "feat: add Argon2id key derivation"
```

---

## Task 4: Crypto primitives — AEAD encrypt/decrypt

**Files:**
- Modify: `crates/protec-core/src/crypto.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/protec-core/src/crypto.rs` (above the `#[cfg(test)]` block, add the functions; inside the test module, add the tests):

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};

/// A 24-byte XChaCha20 nonce.
pub fn random_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn random_bytes_32() -> Zeroizing<[u8; 32]> {
    let mut b = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(b.as_mut());
    b
}

/// Encrypt `plaintext` with `key`, binding `aad` (additional authenticated data).
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8])
    -> Result<Vec<u8>, VaultError>
{
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| VaultError::Corrupted)
}

/// Decrypt; returns `Tampered` if authentication fails.
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8])
    -> Result<Vec<u8>, VaultError>
{
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| VaultError::Tampered)
}
```

Add to the `tests` module:

```rust
    #[test]
    fn encrypt_decrypt_round_trips() {
        let key = [3u8; 32];
        let nonce = random_nonce();
        let ct = encrypt(&key, &nonce, b"top secret", b"hdr").unwrap();
        let pt = decrypt(&key, &nonce, &ct, b"hdr").unwrap();
        assert_eq!(pt, b"top secret");
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = [3u8; 32];
        let nonce = random_nonce();
        let mut ct = encrypt(&key, &nonce, b"top secret", b"hdr").unwrap();
        ct[0] ^= 0xFF;
        assert!(matches!(decrypt(&key, &nonce, &ct, b"hdr"), Err(VaultError::Tampered)));
    }

    #[test]
    fn wrong_aad_fails_auth() {
        let key = [3u8; 32];
        let nonce = random_nonce();
        let ct = encrypt(&key, &nonce, b"top secret", b"hdr").unwrap();
        assert!(matches!(decrypt(&key, &nonce, &ct, b"DIFFERENT"), Err(VaultError::Tampered)));
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p protec-core crypto::`
Expected: all crypto tests PASS, including the three new ones.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/crypto.rs
git commit -m "feat: add XChaCha20-Poly1305 encrypt/decrypt"
```

---

## Task 5: Key wrapping (envelope encryption + multi-wrap hook)

**Files:**
- Create: `crates/protec-core/src/wrap.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/protec-core/src/wrap.rs`:

```rust
use crate::crypto::{decrypt, encrypt, random_nonce};
use crate::error::VaultError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Identifies which mechanism wraps the vault key. Hello adds a variant later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapKind {
    MasterPassword,
    // WindowsHello,  // added in sub-project 4
}

/// A single encrypted copy of the vault key, wrapped by some wrapping key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWrap {
    pub kind: WrapKind,
    pub nonce: [u8; 24],
    pub wrapped: Vec<u8>, // encrypted 32-byte vault key
}

impl KeyWrap {
    /// Wrap `vault_key` under `wrapping_key`.
    pub fn seal(kind: WrapKind, wrapping_key: &[u8; 32], vault_key: &[u8; 32])
        -> Result<Self, VaultError>
    {
        let nonce = random_nonce();
        let wrapped = encrypt(wrapping_key, &nonce, vault_key, b"protec-keywrap")?;
        Ok(Self { kind, nonce, wrapped })
    }

    /// Recover the vault key. Auth failure => wrong wrapping key (e.g. wrong password).
    pub fn open(&self, wrapping_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let pt = decrypt(wrapping_key, &self.nonce, &self.wrapped, b"protec-keywrap")
            .map_err(|_| VaultError::WrongPassword)?;
        let arr: [u8; 32] = pt.as_slice().try_into().map_err(|_| VaultError::Corrupted)?;
        Ok(Zeroizing::new(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_recovers_vault_key() {
        let wrapping = [9u8; 32];
        let vault_key = [4u8; 32];
        let w = KeyWrap::seal(WrapKind::MasterPassword, &wrapping, &vault_key).unwrap();
        let recovered = w.open(&wrapping).unwrap();
        assert_eq!(recovered.as_ref(), &vault_key);
    }

    #[test]
    fn open_with_wrong_key_yields_wrong_password() {
        let w = KeyWrap::seal(WrapKind::MasterPassword, &[9u8; 32], &[4u8; 32]).unwrap();
        assert!(matches!(w.open(&[0u8; 32]), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn two_independent_wraps_of_same_key_both_open() {
        // Proves the multi-wrap design: Windows Hello will add a second wrap later.
        let vault_key = [4u8; 32];
        let pw_key = [1u8; 32];
        let hello_key = [2u8; 32];
        let w1 = KeyWrap::seal(WrapKind::MasterPassword, &pw_key, &vault_key).unwrap();
        let w2 = KeyWrap::seal(WrapKind::MasterPassword, &hello_key, &vault_key).unwrap();
        assert_eq!(w1.open(&pw_key).unwrap().as_ref(), &vault_key);
        assert_eq!(w2.open(&hello_key).unwrap().as_ref(), &vault_key);
    }
}
```

Add the line `mod wrap;` to `lib.rs`.

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p protec-core wrap::`
Expected: all three PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/wrap.rs crates/protec-core/src/lib.rs
git commit -m "feat: add envelope key-wrapping with multi-wrap support"
```

---

## Task 6: Entry model

**Files:**
- Create: `crates/protec-core/src/entry.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/protec-core/src/entry.rs`:

```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totp {
    pub secret: String,   // base32
    pub digits: u8,       // typically 6
    pub period: u16,      // seconds, typically 30
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
        e.totp = Some(Totp { secret: "JBSWY3DPEHPK3PXP".into(), digits: 6, period: 30 });
        let bytes = bincode::serialize(&e).unwrap();
        let back: Entry = bincode::deserialize(&bytes).unwrap();
        assert_eq!(e, back);
    }
}
```

Add to `lib.rs`: the line `mod entry;` and the line `pub use entry::{CustomField, Entry, Totp};`.

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p protec-core entry::`
Expected: both PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/entry.rs crates/protec-core/src/lib.rs
git commit -m "feat: add Entry model with TOTP and custom fields"
```

---

## Task 7: On-disk format (header + body serialization)

**Files:**
- Create: `crates/protec-core/src/format.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/protec-core/src/format.rs`:

```rust
use crate::crypto::KdfParams;
use crate::error::VaultError;
use crate::wrap::KeyWrap;
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 6] = b"PROTEC";
pub const FORMAT_VERSION: u8 = 1;

/// Plaintext-but-authenticated header. Serialized bytes are used as AEAD aad for the body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub magic: [u8; 6],
    pub version: u8,
    pub kdf_salt: [u8; 16],
    pub kdf_mem_kib: u32,
    pub kdf_iters: u32,
    pub kdf_lanes: u32,
    pub wraps: Vec<KeyWrap>,
}

impl Header {
    pub fn new(params: &KdfParams, wraps: Vec<KeyWrap>) -> Self {
        Self {
            magic: *MAGIC,
            version: FORMAT_VERSION,
            kdf_salt: params.salt,
            kdf_mem_kib: params.mem_kib,
            kdf_iters: params.iters,
            kdf_lanes: params.lanes,
            wraps,
        }
    }

    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            salt: self.kdf_salt,
            mem_kib: self.kdf_mem_kib,
            iters: self.kdf_iters,
            lanes: self.kdf_lanes,
        }
    }

    pub fn validate(&self) -> Result<(), VaultError> {
        if &self.magic != MAGIC {
            return Err(VaultError::Corrupted);
        }
        if self.version != FORMAT_VERSION {
            return Err(VaultError::VersionUnsupported(self.version));
        }
        Ok(())
    }
}

/// The complete on-disk file: a length-prefixed header, then nonce + ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFile {
    pub header: Header,
    pub body_nonce: [u8; 24],
    pub body_ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self).map_err(|_| VaultError::Corrupted)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, VaultError> {
        let f: VaultFile = bincode::deserialize(b).map_err(|_| VaultError::Corrupted)?;
        f.header.validate()?;
        Ok(f)
    }
    /// Bytes of the header used as AEAD aad, binding header to body.
    pub fn header_aad(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(&self.header).map_err(|_| VaultError::Corrupted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultFile {
        let params = KdfParams::recommended([5u8; 16]);
        let header = Header::new(&params, vec![]);
        VaultFile { header, body_nonce: [1u8; 24], body_ciphertext: vec![9, 9, 9] }
    }

    #[test]
    fn vaultfile_bytes_round_trip() {
        let f = sample();
        let bytes = f.to_bytes().unwrap();
        let back = VaultFile::from_bytes(&bytes).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn bad_magic_is_corrupted() {
        let mut f = sample();
        f.header.magic = *b"XXXXXX";
        let bytes = f.to_bytes().unwrap();
        assert!(matches!(VaultFile::from_bytes(&bytes), Err(VaultError::Corrupted)));
    }

    #[test]
    fn unknown_version_is_version_unsupported() {
        let mut f = sample();
        f.header.version = 99;
        let bytes = f.to_bytes().unwrap();
        assert!(matches!(
            VaultFile::from_bytes(&bytes),
            Err(VaultError::VersionUnsupported(99))
        ));
    }
}
```

Add the line `mod format;` to `lib.rs`.

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p protec-core format::`
Expected: all three PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/format.rs crates/protec-core/src/lib.rs
git commit -m "feat: add versioned on-disk vault format"
```

---

## Task 8: Atomic storage (read / write / .bak)

**Files:**
- Create: `crates/protec-core/src/storage.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/protec-core/src/storage.rs`:

```rust
use crate::error::VaultError;
use std::fs;
use std::path::Path;

/// Write `bytes` to `path` atomically: write a temp file, fsync, then rename.
/// If `path` already exists, its previous contents are copied to `path.bak` first.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if path.exists() {
        let bak = bak_path(path);
        fs::copy(path, &bak)?;
    }
    let tmp = tmp_path(path);
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_all(path: &Path) -> Result<Vec<u8>, VaultError> {
    Ok(fs::read(path)?)
}

fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut p = path.to_path_buf();
    let name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    let mut name = name;
    name.push(".tmp");
    p.set_file_name(name);
    p
}

fn bak_path(path: &Path) -> std::path::PathBuf {
    let mut p = path.to_path_buf();
    let name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    let mut name = name;
    name.push(".bak");
    p.set_file_name(name);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        write_atomic(&path, b"hello").unwrap();
        assert_eq!(read_all(&path).unwrap(), b"hello");
    }

    #[test]
    fn second_write_creates_bak_of_previous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        write_atomic(&path, b"v1").unwrap();
        write_atomic(&path, b"v2").unwrap();
        assert_eq!(read_all(&path).unwrap(), b"v2");
        let bak = dir.path().join("vault.dat.bak");
        assert_eq!(read_all(&bak).unwrap(), b"v1");
    }
}
```

Add the line `mod storage;` to `lib.rs`.

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p protec-core storage::`
Expected: both PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/storage.rs crates/protec-core/src/lib.rs
git commit -m "feat: add atomic file storage with .bak backup"
```

---

## Task 9: Vault state machine — create / open / unlock / lock

**Files:**
- Create: `crates/protec-core/src/vault.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/protec-core/src/vault.rs`:

```rust
use crate::crypto::{decrypt, derive_key, encrypt, random_bytes_32, random_nonce, KdfParams};
use crate::entry::Entry;
use crate::error::VaultError;
use crate::format::{Header, VaultFile};
use crate::storage::{read_all, write_atomic};
use crate::wrap::{KeyWrap, WrapKind};
use rand_core::{OsRng, RngCore};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zeroize::Zeroizing;

/// Entry point. Use `create` for a new vault or `open` to load an existing one.
pub struct Vault;

impl Vault {
    /// Create a brand-new vault on disk, protected by `master_password`.
    pub fn create(path: impl AsRef<Path>, master_password: &str) -> Result<(), VaultError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let params = KdfParams::recommended(salt);
        let master_key = derive_key(master_password.as_bytes(), &params)?;
        let vault_key = random_bytes_32();
        let wrap = KeyWrap::seal(WrapKind::MasterPassword, &master_key, &vault_key)?;
        let header = Header::new(&params, vec![wrap]);

        let file = encrypt_body(header, &vault_key, &[])?;
        write_atomic(path.as_ref(), &file.to_bytes()?)?;
        Ok(())
    }

    /// Load (but do not unlock) a vault from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<LockedVault, VaultError> {
        let bytes = read_all(path.as_ref())?;
        let file = VaultFile::from_bytes(&bytes)?;
        Ok(LockedVault { path: path.as_ref().to_path_buf(), file })
    }
}

/// A loaded-but-locked vault. Holds no key material and exposes no secrets.
pub struct LockedVault {
    path: PathBuf,
    file: VaultFile,
}

impl LockedVault {
    /// Unlock with the master password. Wrong password => `VaultError::WrongPassword`.
    pub fn unlock(self, master_password: &str) -> Result<UnlockedVault, VaultError> {
        let params = self.file.header.kdf_params();
        let master_key = derive_key(master_password.as_bytes(), &params)?;
        let wrap = self
            .file
            .header
            .wraps
            .iter()
            .find(|w| w.kind == WrapKind::MasterPassword)
            .ok_or(VaultError::Corrupted)?;
        let vault_key = wrap.open(&master_key)?;
        let entries = decrypt_body(&self.file, &vault_key)?;
        Ok(UnlockedVault {
            path: self.path,
            header: self.file.header,
            vault_key,
            entries,
            last_activity: Instant::now(),
        })
    }
}

/// An unlocked vault. ONLY this type exposes secret access. Keys wiped on drop.
pub struct UnlockedVault {
    path: PathBuf,
    header: Header,
    vault_key: Zeroizing<[u8; 32]>,
    entries: Vec<Entry>,
    last_activity: Instant,
}

impl UnlockedVault {
    pub fn lock(self) -> LockedVault {
        // vault_key is dropped (and zeroized) when self is consumed.
        let file = encrypt_body(self.header.clone(), &self.vault_key, &self.entries)
            .unwrap_or_else(|_| panic!("re-seal on lock should not fail"));
        LockedVault { path: self.path, file }
    }

    pub fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() >= timeout
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

// ---- internal helpers ----

fn encrypt_body(header: Header, vault_key: &[u8; 32], entries: &[Entry])
    -> Result<VaultFile, VaultError>
{
    let plaintext = bincode::serialize(entries).map_err(|_| VaultError::Corrupted)?;
    let nonce = random_nonce();
    // aad binds the header to the body.
    let aad = bincode::serialize(&header).map_err(|_| VaultError::Corrupted)?;
    let ct = encrypt(vault_key, &nonce, &plaintext, &aad)?;
    Ok(VaultFile { header, body_nonce: nonce, body_ciphertext: ct })
}

fn decrypt_body(file: &VaultFile, vault_key: &[u8; 32]) -> Result<Vec<Entry>, VaultError> {
    let aad = file.header_aad()?;
    let pt = decrypt(vault_key, &file.body_nonce, &file.body_ciphertext, &aad)?;
    bincode::deserialize(&pt).map_err(|_| VaultError::Corrupted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_open_unlock_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "correct horse").unwrap();
        let locked = Vault::open(&path).unwrap();
        let unlocked = locked.unlock("correct horse").unwrap();
        assert!(!unlocked.is_expired(std::time::Duration::from_secs(600)));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "right").unwrap();
        let locked = Vault::open(&path).unwrap();
        assert!(matches!(locked.unlock("wrong"), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn tampered_body_fails_auth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        // Corrupt one byte of the file body.
        let mut bytes = read_all(&path).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        write_atomic(&path, &bytes).unwrap();
        let locked = Vault::open(&path).unwrap();
        let res = locked.unlock("pw");
        assert!(res.is_err());
    }
}
```

Add to `lib.rs`: the line `mod vault;` and the line `pub use vault::{LockedVault, UnlockedVault, Vault};`. At this point `lib.rs` declares all eight modules.

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p protec-core vault::`
Expected: all three PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/vault.rs crates/protec-core/src/lib.rs
git commit -m "feat: add Vault create/open/unlock/lock state machine"
```

---

## Task 10: Secret CRUD + save (on UnlockedVault only)

**Files:**
- Modify: `crates/protec-core/src/vault.rs`

- [ ] **Step 1: Write the failing test**

In `crates/protec-core/src/vault.rs`, add these methods inside `impl UnlockedVault` (after `touch`):

```rust
    pub fn list_entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, id: uuid::Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn add(&mut self, entry: Entry) {
        self.touch();
        self.entries.push(entry);
    }

    pub fn update(&mut self, id: uuid::Uuid, updated: Entry) -> Result<(), VaultError> {
        self.touch();
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(VaultError::Corrupted)?;
        *slot = updated;
        Ok(())
    }

    pub fn delete(&mut self, id: uuid::Uuid) -> Result<(), VaultError> {
        self.touch();
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        if self.entries.len() == before {
            return Err(VaultError::Corrupted);
        }
        Ok(())
    }

    /// Re-encrypt the current entries and write to disk atomically.
    pub fn save(&self) -> Result<(), VaultError> {
        let file = encrypt_body(self.header.clone(), &self.vault_key, &self.entries)?;
        write_atomic(&self.path, &file.to_bytes()?)
    }
```

Add to the `tests` module:

```rust
    #[test]
    fn add_save_reopen_persists_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();

        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            let mut e = Entry::new("GitHub", 1);
            e.username = "octocat".into();
            e.password = "s3cr3t".into();
            v.add(e);
            v.save().unwrap();
        }

        let v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        let list = v.list_entries();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "GitHub");
        assert_eq!(list[0].password, "s3cr3t");
    }

    #[test]
    fn update_and_delete_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();

        let mut e = Entry::new("Site", 1);
        let id = e.id;
        v.add(e.clone());

        e.password = "new".into();
        v.update(id, e).unwrap();
        assert_eq!(v.get(id).unwrap().password, "new");

        v.delete(id).unwrap();
        assert!(v.get(id).is_none());
        assert!(matches!(v.delete(id), Err(VaultError::Corrupted)));
    }
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p protec-core vault::`
Expected: all vault tests PASS, including the two new ones.

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/vault.rs
git commit -m "feat: add secret CRUD and save to UnlockedVault"
```

---

## Task 11: Compile-time security guarantee (doc + trybuild-style note)

**Files:**
- Modify: `crates/protec-core/src/lib.rs`

- [ ] **Step 1: Add a doctest that proves locked vaults expose no secrets**

Add to `crates/protec-core/src/lib.rs` (below the existing `//!` docs), a compile-fail doc example:

````rust
//! # Compile-time security
//!
//! Secret access exists only on [`UnlockedVault`]. The following does NOT compile,
//! because [`LockedVault`] has no `list_entries` method:
//!
//! ```compile_fail
//! use protec_core::Vault;
//! let locked = Vault::open("vault.dat").unwrap();
//! let _ = locked.list_entries(); // ERROR: no method `list_entries` on LockedVault
//! ```
````

- [ ] **Step 2: Run doctests**

Run: `cargo test -p protec-core --doc`
Expected: the `compile_fail` example PASSES (it passes *because* it fails to compile).

- [ ] **Step 3: Commit**

```bash
git add crates/protec-core/src/lib.rs
git commit -m "docs: prove locked vault exposes no secrets at compile time"
```

---

## Task 12: Full suite, clippy, fmt, and CI

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `rustfmt.toml` (optional defaults)

- [ ] **Step 1: Run the whole suite**

Run: `cargo test --workspace`
Expected: ALL tests across all modules PASS.

- [ ] **Step 2: Lint and format gates**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings (fix any that appear).
Run: `cargo fmt --all -- --check`
Expected: no diff (run `cargo fmt --all` to fix, then re-check).

- [ ] **Step 3: Add CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-audit
      - run: cargo audit
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add test, clippy, fmt, and audit workflow"
```

---

## Task 13: Open-source project files

**Files:**
- Create: `LICENSE` (Apache-2.0)
- Create: `README.md`
- Create: `SECURITY.md`

- [ ] **Step 1: Add the Apache-2.0 license**

Download the canonical text to `LICENSE`:

```bash
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
```

If offline, generate it via `cargo install cargo-license` is **not** needed — instead use any local copy of the Apache-2.0 text. The license text itself is unmodified; attribution/copyright is conveyed via the `license = "Apache-2.0"` field already set in `Cargo.toml` (Task 1) and a `NOTICE` file is optional for this project.

- [ ] **Step 2: Add README.md**

Create `README.md`:

```markdown
# Protec

A fully local, open-source password manager. Your secrets never leave your machine.

> **Status:** early development. `protec-core` (the secure engine) is the first component.

## Security model

- **Argon2id** key derivation; **XChaCha20-Poly1305** authenticated encryption.
- **Envelope encryption:** a random vault key encrypts your data; your master password
  only wraps that vault key — enabling future unlock methods (e.g. Windows Hello) with
  no re-encryption.
- **No cloud, no account, no telemetry.** A single encrypted file you control.
- Key material is wiped from memory on lock.

## Components

| Crate | Status | Purpose |
|-------|--------|---------|
| `protec-core` | in progress | the secure vault engine |
| `protec-cli`  | planned | terminal client |
| `protec-gui`  | planned | desktop app (Tauri) |

## License

Apache-2.0.
```

- [ ] **Step 3: Add SECURITY.md**

Create `SECURITY.md`:

```markdown
# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
(Security tab → Report a vulnerability) rather than public issues.

## Scope and design

- Crypto: Argon2id (KDF) + XChaCha20-Poly1305 (AEAD).
- Envelope encryption with a versioned, authenticated on-disk format.
- No network access of any kind. The vault file is the only persistence.

This software has **not** undergone a third-party audit. Use at your own risk
until it reaches a reviewed release.
```

- [ ] **Step 4: Commit**

```bash
git add LICENSE README.md SECURITY.md
git commit -m "docs: add license, README, and security policy"
```

---

## Definition of Done

- `cargo test --workspace` passes (all unit + doc tests).
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- `cargo fmt --all -- --check` is clean.
- A vault can be created, closed, reopened, unlocked, mutated, saved, and reopened with
  data intact.
- Wrong password, tampered header, and tampered body are all rejected.
- A locked vault cannot expose secrets — enforced at compile time (Task 11 doctest).
- The on-disk format carries a version byte and supports multiple key-wraps (Hello-ready).
- Repo has LICENSE, README, SECURITY.md, and CI.
