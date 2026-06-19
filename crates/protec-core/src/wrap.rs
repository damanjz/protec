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
        let pt = Zeroizing::new(
            decrypt(wrapping_key, &self.nonce, &self.wrapped, b"protec-keywrap")
                .map_err(|_| VaultError::WrongPassword)?,
        );
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
