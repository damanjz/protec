use std::io::{Read, Write};

/// Same pipe name the app's server listens on (kept in sync manually; the host
/// cannot depend on the gui crate).
const PIPE_NAME: &str = r"\\.\pipe\protec-ipc-v1";

/// Send a JSON request to the app over the named pipe and read the JSON reply.
/// Framing on the pipe is the same 4-byte LE length prefix as native messaging.
/// Returns Err if the app isn't running (pipe open fails) or on IO error.
pub fn round_trip(request_json: &[u8]) -> std::io::Result<Vec<u8>> {
    // A Windows named pipe client is opened like a file.
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)?;

    pipe.write_all(&(request_json.len() as u32).to_le_bytes())?;
    pipe.write_all(request_json)?;
    pipe.flush()?;

    let mut len = [0u8; 4];
    pipe.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    let mut body = vec![0u8; n];
    pipe.read_exact(&mut body)?;
    Ok(body)
}
