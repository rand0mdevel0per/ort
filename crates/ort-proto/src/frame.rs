//! Outer length-prefix framing: `u32 length (BE) || frame-body`.

use crate::ProtoError;

/// Maximum allowed frame body size. Handshake frames carry PQ blobs (ML-KEM ct
/// ~1088 B, ML-DSA vk ~1952 B + sig ~3309 B) plus early data, so the cap is
/// generous; record frames are bounded well under this.
pub const MAX_FRAME: usize = 1 << 20; // 1 MiB

/// Prefix a frame body with its big-endian u32 length.
pub fn encode_framed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Parse the 4-byte length prefix, validating it against [`MAX_FRAME`].
pub fn parse_len(prefix: [u8; 4]) -> Result<usize, ProtoError> {
    let n = u32::from_be_bytes(prefix) as usize;
    if n > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge(n));
    }
    Ok(n)
}
