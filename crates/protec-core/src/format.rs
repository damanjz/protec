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
        // Reject absurd KDF params from a tampered/hostile vault file before they
        // reach Argon2 (which would otherwise burn CPU/RAM on a value the AEAD
        // check would ultimately reject anyway).
        if self.kdf_mem_kib > 1_048_576 {
            // > 1 GiB memory cost is not a legitimate Protec vault.
            return Err(VaultError::Corrupted);
        }
        if self.kdf_iters > 100 {
            return Err(VaultError::Corrupted);
        }
        if self.kdf_lanes == 0 || self.kdf_lanes > 64 {
            return Err(VaultError::Corrupted);
        }
        Ok(())
    }

    /// The per-vault Argon2 salt (random 16 bytes set at vault creation). Stable
    /// across the vault's lifetime; used as a per-vault salt for the Hello KDF.
    pub fn kdf_salt(&self) -> [u8; 16] {
        self.kdf_salt
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
        VaultFile {
            header,
            body_nonce: [1u8; 24],
            body_ciphertext: vec![9, 9, 9],
        }
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
        assert!(matches!(
            VaultFile::from_bytes(&bytes),
            Err(VaultError::Corrupted)
        ));
    }

    #[test]
    fn rejects_absurd_kdf_params() {
        let mut f = sample();
        f.header.kdf_mem_kib = 4_000_000; // ~4 GiB — hostile
        let bytes = f.to_bytes().unwrap();
        assert!(matches!(
            VaultFile::from_bytes(&bytes),
            Err(VaultError::Corrupted)
        ));
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
