//! Windows Hello TPM provider via the WinRT KeyCredentialManager API.
//! Not unit-tested (requires real TPM + biometric); verified by manual checklist.

use crate::envelope::KeyProvider;
use crate::error::HelloError;
use sha2::{Digest, Sha256};
use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use zeroize::Zeroizing;

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
    if let Ok(op) = KeyCredentialManager::OpenAsync(&name) {
        if let Ok(res) = op.get() {
            if res
                .Status()
                .map_err(|e| HelloError::Backend(e.code().0.to_string()))?
                == KeyCredentialStatus::Success
            {
                return Ok(());
            }
        }
    }
    let op =
        KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::FailIfExists)
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
    let cred = res
        .Credential()
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?;

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
    let sig = sign_res
        .Result()
        .map_err(|e| HelloError::Backend(e.code().0.to_string()))?;
    let sig_bytes = Zeroizing::new(ibuffer_to_vec(&sig)?);

    // Derive the 32-byte wrapping key as SHA-256 of the TPM signature with a
    // domain-separation prefix. The signature is deterministic for a fixed
    // challenge + this device's key, so enable and unlock produce the same key.
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
