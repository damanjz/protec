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
