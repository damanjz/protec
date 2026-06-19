//! protec-core: secure local vault engine.
//!
//! Envelope encryption (Argon2id + XChaCha20-Poly1305) with a compile-time
//! locked/unlocked API. No UI, no network.

mod error;
mod crypto;
mod wrap;

pub use error::VaultError;
