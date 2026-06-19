use protec_core::{Entry, Vault};

#[test]
fn restore_from_bak_recovers_previous_vault() {
    let dir = std::env::temp_dir().join("protec_gui_restoreflow");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.dat");

    // First good save creates the vault.
    Vault::create(&path, "pw").unwrap();
    {
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        v.add(Entry::new("Original", 1));
        v.save().unwrap();
    }
    // Second save writes a .bak of the previous (1-entry) state.
    {
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        v.add(Entry::new("Second", 2));
        v.save().unwrap();
    }
    let bak = dir.join("vault.dat.bak");
    assert!(bak.exists(), "expected a .bak after the second save");

    // Simulate corruption of the main file, then restore from .bak.
    std::fs::write(&path, b"corrupted-bytes").unwrap();
    assert!(Vault::open(&path).is_err() || Vault::open(&path).unwrap().unlock("pw").is_err());
    std::fs::copy(&bak, &path).unwrap();

    let v = Vault::open(&path).unwrap().unlock("pw").unwrap();
    assert_eq!(v.list_entries().len(), 1); // the previous (pre-second-save) state
    let _ = std::fs::remove_dir_all(&dir);
}
