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
