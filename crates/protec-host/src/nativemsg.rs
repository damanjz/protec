use std::io::{Read, Write};

/// Browser native messaging frames each message as a 4-byte little-endian
/// length prefix followed by that many bytes of UTF-8 JSON.
/// Chrome caps messages at 1 MB inbound; we enforce a sane limit.
const MAX_MESSAGE: u32 = 64 * 1024 * 1024;

/// Read one framed message from `r`. Returns None on clean EOF (browser closed).
pub fn read_message(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one framed message to `w`.
pub fn write_message(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    let len = body.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_then_read_round_trips() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"{\"hello\":1}").unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(got, b"{\"hello\":1}");
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn oversize_length_is_rejected() {
        let mut bytes = (u32::MAX).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"x");
        let mut cur = Cursor::new(bytes);
        assert!(read_message(&mut cur).is_err());
    }
}
