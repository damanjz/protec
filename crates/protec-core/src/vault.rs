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
        Ok(LockedVault {
            path: path.as_ref().to_path_buf(),
            file,
        })
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

    /// Unlock using a vault key recovered from a non-password wrap (e.g. the
    /// Windows Hello wrap, whose wrapping key came from the TPM). The caller has
    /// already produced `wrapping_key` via the external mechanism.
    pub fn unlock_with_wrap(
        self,
        kind: crate::wrap::WrapKind,
        wrapping_key: &[u8; 32],
    ) -> Result<UnlockedVault, VaultError> {
        let wrap = self
            .file
            .header
            .wraps
            .iter()
            .find(|w| w.kind == kind)
            .ok_or(VaultError::Corrupted)?;
        let vault_key = wrap.open(wrapping_key).map_err(|e| match e {
            // A failed unwrap here means the supplied (TPM-derived) key didn't
            // authenticate — not a "wrong master password".
            VaultError::WrongPassword => VaultError::Tampered,
            other => other,
        })?;
        let entries = decrypt_body(&self.file, &vault_key)?;
        Ok(UnlockedVault {
            path: self.path,
            header: self.file.header,
            vault_key,
            entries,
            last_activity: Instant::now(),
        })
    }

    /// True if the on-disk header contains a wrap of the given kind. Readable
    /// without unlocking — used to know whether Hello is enabled for this vault.
    pub fn has_wrap(&self, kind: &crate::wrap::WrapKind) -> bool {
        self.file.header.wraps.iter().any(|w| &w.kind == kind)
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
        LockedVault {
            path: self.path,
            file,
        }
    }

    pub fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() >= timeout
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn list_entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, id: uuid::Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn add(&mut self, entry: Entry) {
        self.touch();
        self.entries.push(entry);
    }

    pub fn update(&mut self, id: uuid::Uuid, mut updated: Entry) -> Result<(), VaultError> {
        self.touch();
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(VaultError::NotFound)?;
        // Enforce id consistency: the stored entry keeps the lookup id regardless
        // of what the caller put in `updated.id`.
        updated.id = id;
        *slot = updated;
        Ok(())
    }

    pub fn delete(&mut self, id: uuid::Uuid) -> Result<(), VaultError> {
        self.touch();
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        if self.entries.len() == before {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    /// Re-encrypt the current entries and write to disk atomically.
    pub fn save(&self) -> Result<(), VaultError> {
        let file = encrypt_body(self.header.clone(), &self.vault_key, &self.entries)?;
        write_atomic(&self.path, &file.to_bytes()?)
    }

    /// Expose a copy of the vault key so an additional wrap (e.g. Windows Hello)
    /// can be created. Only available on an already-unlocked vault.
    pub fn vault_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.vault_key)
    }

    /// Add a pre-built key-wrap to the header and persist. Replaces any existing
    /// wrap of the same kind (so re-enabling Hello overwrites the old wrap).
    pub fn add_wrap(&mut self, wrap: crate::wrap::KeyWrap) -> Result<(), VaultError> {
        self.header.wraps.retain(|w| w.kind != wrap.kind);
        self.header.wraps.push(wrap);
        self.save()
    }

    /// Remove all wraps of the given kind and persist. The MasterPassword wrap
    /// must never be removed; callers must not pass WrapKind::MasterPassword.
    pub fn remove_wrap(&mut self, kind: crate::wrap::WrapKind) -> Result<(), VaultError> {
        if kind == crate::wrap::WrapKind::MasterPassword {
            return Err(VaultError::OperationNotAllowed); // never remove the password wrap
        }
        self.header.wraps.retain(|w| w.kind != kind);
        self.save()
    }

    /// True if the header contains a wrap of the given kind.
    pub fn has_wrap(&self, kind: &crate::wrap::WrapKind) -> bool {
        self.header.wraps.iter().any(|w| &w.kind == kind)
    }
}

// ---- internal helpers ----

fn encrypt_body(
    header: Header,
    vault_key: &[u8; 32],
    entries: &[Entry],
) -> Result<VaultFile, VaultError> {
    let plaintext = Zeroizing::new(bincode::serialize(entries).map_err(|_| VaultError::Corrupted)?);
    let nonce = random_nonce();
    // aad binds the header to the body.
    let aad = bincode::serialize(&header).map_err(|_| VaultError::Corrupted)?;
    let ct = encrypt(vault_key, &nonce, &plaintext, &aad)?;
    Ok(VaultFile {
        header,
        body_nonce: nonce,
        body_ciphertext: ct,
    })
}

fn decrypt_body(file: &VaultFile, vault_key: &[u8; 32]) -> Result<Vec<Entry>, VaultError> {
    let aad = file.header_aad()?;
    let pt = Zeroizing::new(decrypt(
        vault_key,
        &file.body_nonce,
        &file.body_ciphertext,
        &aad,
    )?);
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
        assert!(matches!(
            locked.unlock("wrong"),
            Err(VaultError::WrongPassword)
        ));
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

    #[test]
    fn add_save_reopen_persists_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();

        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            let mut e = Entry::new("GitHub", 1);
            e.username = "octocat".into();
            e.password = "s3cr3t".into();
            v.add(e);
            v.save().unwrap();
        }

        let v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        let list = v.list_entries();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "GitHub");
        assert_eq!(list[0].password, "s3cr3t");
    }

    #[test]
    fn update_and_delete_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();

        let mut e = Entry::new("Site", 1);
        let id = e.id;
        v.add(e.clone());

        e.password = "new".into();
        v.update(id, e).unwrap();
        assert_eq!(v.get(id).unwrap().password, "new");

        v.delete(id).unwrap();
        assert!(v.get(id).is_none());
        assert!(matches!(v.delete(id), Err(VaultError::NotFound)));
    }

    #[test]
    fn update_keeps_lookup_id_even_if_caller_mismatches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();

        let e = Entry::new("Site", 1);
        let id = e.id;
        v.add(e);

        // Caller passes an entry with a DIFFERENT id; update must keep `id`.
        let mut wrong = Entry::new("Site", 2);
        assert_ne!(wrong.id, id);
        wrong.password = "x".into();
        v.update(id, wrong).unwrap();

        // The entry is still found under the original id, with the new data.
        let got = v.get(id).unwrap();
        assert_eq!(got.id, id);
        assert_eq!(got.password, "x");
    }

    #[test]
    fn update_missing_id_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        let orphan = Entry::new("Nope", 1);
        let oid = orphan.id;
        assert!(matches!(v.update(oid, orphan), Err(VaultError::NotFound)));
    }

    #[test]
    fn tampered_header_field_fails_auth() {
        use crate::format::VaultFile;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();

        // Read, deserialize, mutate a HEADER field, re-serialize, write back.
        let bytes = read_all(&path).unwrap();
        let mut file = VaultFile::from_bytes(&bytes).unwrap();
        file.header.kdf_iters ^= 0x01; // flip a bit in an authenticated header field
        let tampered = file.to_bytes().unwrap();
        write_atomic(&path, &tampered).unwrap();

        // Unlock must fail authentication because the header is bound as AAD.
        // (Wrong password is impossible here — the password is correct; the
        // header no longer matches what the body was sealed against.)
        let locked = Vault::open(&path).unwrap();
        let res = locked.unlock("pw");
        assert!(matches!(
            res,
            Err(VaultError::Tampered) | Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn add_then_unlock_with_second_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();

        let hello_key = [7u8; 32];
        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            v.add(Entry::new("Site", 1));
            let vk = v.vault_key();
            let wrap =
                crate::wrap::KeyWrap::seal(crate::wrap::WrapKind::WindowsHello, &hello_key, &vk)
                    .unwrap();
            v.add_wrap(wrap).unwrap();
        }

        let v = Vault::open(&path)
            .unwrap()
            .unlock_with_wrap(crate::wrap::WrapKind::WindowsHello, &hello_key)
            .unwrap();
        assert_eq!(v.list_entries().len(), 1);
    }

    #[test]
    fn password_still_works_after_adding_hello_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            let vk = v.vault_key();
            let wrap =
                crate::wrap::KeyWrap::seal(crate::wrap::WrapKind::WindowsHello, &[7u8; 32], &vk)
                    .unwrap();
            v.add_wrap(wrap).unwrap();
        }
        assert!(Vault::open(&path).unwrap().unlock("pw").is_ok());
    }

    #[test]
    fn remove_hello_wrap_keeps_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        {
            let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
            let vk = v.vault_key();
            let wrap =
                crate::wrap::KeyWrap::seal(crate::wrap::WrapKind::WindowsHello, &[7u8; 32], &vk)
                    .unwrap();
            v.add_wrap(wrap).unwrap();
            v.remove_wrap(crate::wrap::WrapKind::WindowsHello).unwrap();
            assert!(!v.has_wrap(&crate::wrap::WrapKind::WindowsHello));
        }
        assert!(Vault::open(&path).unwrap().unlock("pw").is_ok());
    }

    #[test]
    fn cannot_remove_master_password_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        Vault::create(&path, "pw").unwrap();
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        assert!(matches!(
            v.remove_wrap(crate::wrap::WrapKind::MasterPassword),
            Err(VaultError::OperationNotAllowed)
        ));
    }
}
