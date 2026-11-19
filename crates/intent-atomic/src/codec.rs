//! Bounded length-prefixed JSON framing shared with host acceptance fixtures.

use intent_atomic_proto::MAX_FRAME_BYTES;
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{HostError, Result};

/// Decode one frame, refusing invalid lengths before allocating the body.
/// # Errors
/// Returns transport, framing or strict JSON decoding errors.
pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(HostError::FrameLength(length));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// Encode exactly one bounded message. Larger content requires a spool reference.
/// # Errors
/// Returns serialization, frame-budget or transport errors.
pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(HostError::FrameLength(body.len()));
    }
    let length = u32::try_from(body.len()).map_err(|_| HostError::FrameLength(body.len()))?;
    writer.write_u32(length).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_header_is_refused_without_waiting_for_a_body() {
        let (mut sender, mut receiver) = tokio::io::duplex(4);
        sender.write_u32(65_537).await.unwrap();
        let result: Result<String> = read_frame(&mut receiver).await;
        assert!(matches!(result, Err(HostError::FrameLength(65_537))));
    }

    #[tokio::test]
    async fn oversized_payload_does_not_emit_a_partial_frame() {
        let (mut sender, mut receiver) = tokio::io::duplex(4);
        let result = write_frame(&mut sender, &"x".repeat(MAX_FRAME_BYTES)).await;
        assert!(matches!(result, Err(HostError::FrameLength(_))));
        drop(sender);
        assert_eq!(
            receiver.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
