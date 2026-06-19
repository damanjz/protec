use crate::error::VaultError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
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
        Self {
            salt,
            mem_kib: 19_456,
            iters: 2,
            lanes: 1,
        }
    }
}

/// Derive a 32-byte master key from the password + params. Output is zeroized on drop.
pub fn derive_key(password: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params =
        Params::new(p.mem_kib, p.iters, p.lanes, Some(32)).map_err(|_| VaultError::Corrupted)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, &p.salt, out.as_mut())
        .map_err(|_| VaultError::Corrupted)?;
    Ok(out)
}

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
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Corrupted)
}

/// Decrypt; returns `Tampered` if authentication fails.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::Tampered)
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
        assert!(matches!(
            decrypt(&key, &nonce, &ct, b"hdr"),
            Err(VaultError::Tampered)
        ));
    }

    #[test]
    fn wrong_aad_fails_auth() {
        let key = [3u8; 32];
        let nonce = random_nonce();
        let ct = encrypt(&key, &nonce, b"top secret", b"hdr").unwrap();
        assert!(matches!(
            decrypt(&key, &nonce, &ct, b"DIFFERENT"),
            Err(VaultError::Tampered)
        ));
    }
}
