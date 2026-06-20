//! ORT wire format: frame message types and an explicit length-prefixed binary
//! codec. (Deliberately hand-rolled rather than FlatBuffers so the build needs
//! no external codegen toolchain and the parser is trivial to fuzz.)

#![forbid(unsafe_code)]

pub mod codec;
pub mod frame;
pub mod messages;

pub use frame::{encode_framed, parse_len, MAX_FRAME};
pub use messages::{reject, Frame, FrameType, KemPayload, SuiteOffer, EK_HASH_LEN, MAX_SUITES};

use thiserror::Error;

/// Errors produced while encoding/decoding ORT frames.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    /// Ran out of bytes while decoding.
    #[error("truncated frame")]
    Truncated,
    /// Extra bytes remained after decoding a frame.
    #[error("{0} trailing bytes after frame")]
    TrailingBytes(usize),
    /// Unknown frame type tag.
    #[error("unknown frame type {0:#04x}")]
    UnknownFrameType(u8),
    /// Frame length prefix exceeds [`MAX_FRAME`].
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    /// A field held a value outside its permitted set.
    #[error("invalid value for {0}")]
    InvalidValue(&'static str),
    /// A repeated field exceeded its maximum count.
    #[error("too many {0}")]
    TooMany(&'static str),
    /// A required repeated field was empty.
    #[error("empty {0}")]
    Empty(&'static str),
}
