// Integration test exercising create/unlock through protec-core directly
// (commands are thin wrappers; this guards the create->unlock->persist path).
use protec_core::{Entry, Vault};

#[test]
fn create_unlock_add_save_reopen() {
    let dir = std::env::temp_dir().join("protec_gui_authflow");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.dat");

    Vault::create(&path, "pw").unwrap();
    {
        let mut v = Vault::open(&path).unwrap().unlock("pw").unwrap();
        v.add(Entry::new("GitHub", 1));
        v.save().unwrap();
    }
    let v = Vault::open(&path).unwrap().unlock("pw").unwrap();
    assert_eq!(v.list_entries().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
