use std::io::{Read, Write};

/// Windows named pipe the app listens on.
#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\protec-ipc-v1";

/// Resolve the macOS Unix-socket path. This MUST stay in sync with the app's
/// `ipc::protocol::endpoint()` (the host cannot depend on the gui crate):
/// HOME -> "Library/Application Support" -> "Protec" -> "protec-ipc-v1.sock".
#[cfg(target_os = "macos")]
fn unix_socket_path() -> std::path::PathBuf {
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join("Library/Application Support"))
        .unwrap_or_else(std::env::temp_dir);
    base.join("Protec").join("protec-ipc-v1.sock")
}

/// Trait-object helper so both platforms share one request/response body.
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Open the platform connection to the running app. Err if the app isn't running.
#[cfg(windows)]
fn connect() -> std::io::Result<Box<dyn ReadWrite>> {
    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)?;
    Ok(Box::new(pipe))
}

#[cfg(target_os = "macos")]
fn connect() -> std::io::Result<Box<dyn ReadWrite>> {
    let sock = std::os::unix::net::UnixStream::connect(unix_socket_path())?;
    Ok(Box::new(sock))
}

/// Send a JSON request to the app and read the JSON reply. Same 4-byte LE
/// length-prefix framing as native messaging. Err if the app isn't running
/// (connect fails) or on IO error.
pub fn round_trip(request_json: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut conn = connect()?;

    conn.write_all(&(request_json.len() as u32).to_le_bytes())?;
    conn.write_all(request_json)?;
    conn.flush()?;

    let mut len = [0u8; 4];
    conn.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    let mut body = vec![0u8; n];
    conn.read_exact(&mut body)?;
    Ok(body)
}
