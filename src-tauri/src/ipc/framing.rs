//! Transport-agnostic wire framing: a 4-byte little-endian length prefix followed
//! by a JSON body. Works over any async stream (Windows named pipe, Unix socket),
//! so the listen/connect transport can be swapped per platform without touching
//! the wire format.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum accepted request size (mirrors the previous inline guard).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Read one length-prefixed frame. Returns the JSON body bytes.
/// Errors if the declared length exceeds `MAX_FRAME` or the stream ends early.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    // u32 always fits in usize on all supported targets (usize >= 32 bits).
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Write one length-prefixed frame. Rejects bodies larger than `MAX_FRAME`
/// (or above `u32::MAX`) so the sender enforces the same contract the reader does.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    let n = u32::try_from(body.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame body exceeds u32")
    })?;
    if n as usize > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    w.write_all(&n.to_le_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trips_over_a_duplex_pipe() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, b"{\"type\":\"status\"}").await.unwrap();
        let got = read_frame(&mut b).await.unwrap();
        assert_eq!(got, b"{\"type\":\"status\"}");
    }

    #[tokio::test]
    async fn oversized_declared_length_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(8);
        // Declare a length above MAX_FRAME without sending a body.
        let huge = (u32::try_from(MAX_FRAME).unwrap() + 1).to_le_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut a, &huge)
            .await
            .unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_body_is_unexpected_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Declare 10 bytes but only send 3, then close the writer.
        tokio::io::AsyncWriteExt::write_all(&mut a, &10u32.to_le_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut a, b"abc")
            .await
            .unwrap();
        drop(a); // close the stream so read_exact sees EOF
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
