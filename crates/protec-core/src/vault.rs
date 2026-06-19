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
        // Re-encryption uses a correctly-sized key and a fresh nonce, so AEAD
        // encryption cannot fail here; bincode serialization of Vec<Entry> is
        // likewise infallible. expect documents that invariant.
        let file = encrypt_body(self.header.clone(), &self.vault_key, &self.entries)
            .expect("re-seal on lock is infallible for valid key/nonce sizes");
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
    let plaintext = Zeroizing::new(
        bincode::serialize(entries).map_err(|_| VaultError::Corrupted)?,
    );
    let nonce = random_nonce();
    // aad binds the header to the body.
    let aad = bincode::serialize(&header).map_err(|_| VaultError::Corrupted)?;
    let ct = encrypt(vault_key, &nonce, &plaintext, &aad)?;
    Ok(VaultFile { header, body_nonce: nonce, body_ciphertext: ct })
}

fn decrypt_body(file: &VaultFile, vault_key: &[u8; 32]) -> Result<Vec<Entry>, VaultError> {
    let aad = file.header_aad()?;
    let pt = Zeroizing::new(
        decrypt(vault_key, &file.body_nonce, &file.body_ciphertext, &aad)?,
    );
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
        assert!(matches!(res, Err(VaultError::Tampered)));
    }
}
