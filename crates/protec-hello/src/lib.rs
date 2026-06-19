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

#[cfg(windows)]
pub use tpm::TpmProvider;

/// Produce the wrapping key to ENABLE Hello (prompts Hello, creates the TPM key
/// if needed). The caller seals the vault key with this via core's KeyWrap.
#[cfg(windows)]
pub fn enable_wrapping_key() -> Result<zeroize::Zeroizing<[u8; 32]>, HelloError> {
    wrapping_key_for_enable(&tpm::TpmProvider)
}

/// Produce the wrapping key to UNLOCK via Hello (prompts Hello).
#[cfg(windows)]
pub fn unlock_wrapping_key() -> Result<zeroize::Zeroizing<[u8; 32]>, HelloError> {
    wrapping_key_for_unlock(&tpm::TpmProvider)
}

/// Delete Protec's TPM credential (DISABLE Hello).
#[cfg(windows)]
pub fn disable() -> Result<(), HelloError> {
    tpm::delete_credential()
}
