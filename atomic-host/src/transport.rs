//! Length-bounded synchronous codec; native work runs on the connection worker.

use std::io::{Read, Write};

use intent_atomic_proto::{Outcome, Request, Response, MAX_FRAME_BYTES};

use crate::{Host, HostError, Result, Session};

/// Serve one frame. Returns false on clean EOF, true after a Shutdown reply.
/// # Errors
/// Truncated, oversized, empty or invalid frames close the connection; no command
/// is interpreted until its complete bounded body has been decoded.
pub fn serve_frame(
    host: &Host,
    session: &mut Session,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<Option<bool>> {
    let mut prefix = [0_u8; 4];
    let first = reader.read(&mut prefix[..1])?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..])?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| HostError::Invalid("invalid frame length"))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(HostError::Invalid("invalid frame length"));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    let request: Request = serde_json::from_slice(&bytes)?;
    let outcome = match host.handle(session, request.command) {
        Ok(reply) => Outcome::Success(Box::new(reply)),
        Err(error) => Outcome::Failure(error),
    };
    let shutdown = matches!(
        &outcome,
        Outcome::Success(reply) if matches!(reply.as_ref(), intent_atomic_proto::Reply::Shutdown)
    );
    let bytes = serde_json::to_vec(&Response {
        id: request.id,
        outcome,
    })?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(HostError::Invalid("host reply exceeds frame bound"));
    }
    writer.write_all(
        &u32::try_from(bytes.len())
            .map_err(|_| HostError::Invalid("host reply exceeds frame bound"))?
            .to_be_bytes(),
    )?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(Some(shutdown))
}
