//! Outer length-prefix framing: `u32 length (BE) || frame-body`.

use crate::ProtoError;

/// Maximum allowed frame body size. Handshake frames carry PQ blobs (possibly
/// several, in multi-suite offers) plus early data; record frames stay well
/// under this. Bumped to comfortably hold multi-suite ClientHellos.
pub const MAX_FRAME: usize = 4 * 1024 * 1024; // 4 MiB

/// Prefix a frame body with its big-endian u32 length. Errors if the body is
/// larger than [`MAX_FRAME`] (which also guarantees the `u32` cast is lossless).
pub fn encode_framed(body: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if body.len() > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Parse the 4-byte length prefix, validating it against [`MAX_FRAME`].
pub fn parse_len(prefix: [u8; 4]) -> Result<usize, ProtoError> {
    let n = u32::from_be_bytes(prefix) as usize;
    if n > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge(n));
    }
    Ok(n)
}
