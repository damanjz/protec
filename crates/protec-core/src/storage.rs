use crate::error::VaultError;
use std::fs;
use std::path::Path;

/// Write `bytes` to `path` atomically: write a temp file, fsync, then rename.
/// If `path` already exists, its previous contents are copied to `path.bak` first.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if path.exists() {
        let bak = bak_path(path);
        fs::copy(path, &bak)?;
    }
    let tmp = tmp_path(path);
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_all(path: &Path) -> Result<Vec<u8>, VaultError> {
    Ok(fs::read(path)?)
}

fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut p = path.to_path_buf();
    let name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    let mut name = name;
    name.push(".tmp");
    p.set_file_name(name);
    p
}

fn bak_path(path: &Path) -> std::path::PathBuf {
    let mut p = path.to_path_buf();
    let name = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    let mut name = name;
    name.push(".bak");
    p.set_file_name(name);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        write_atomic(&path, b"hello").unwrap();
        assert_eq!(read_all(&path).unwrap(), b"hello");
    }

    #[test]
    fn second_write_creates_bak_of_previous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        write_atomic(&path, b"v1").unwrap();
        write_atomic(&path, b"v2").unwrap();
        assert_eq!(read_all(&path).unwrap(), b"v2");
        let bak = dir.path().join("vault.dat.bak");
        assert_eq!(read_all(&bak).unwrap(), b"v1");
    }
}
