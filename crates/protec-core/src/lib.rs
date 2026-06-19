//! protec-core: secure local vault engine.
//!
//! Envelope encryption (Argon2id + XChaCha20-Poly1305) with a compile-time
//! locked/unlocked API. No UI, no network.
//!
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

mod crypto;
mod entry;
mod error;
mod format;
mod generator;
mod storage;
mod vault;
mod wrap;

pub use entry::{CustomField, Entry, Totp};
pub use error::VaultError;
pub use generator::{generate_password, CharsetOptions};
pub use vault::{LockedVault, UnlockedVault, Vault};
