//! Error types for the ORT core.

use thiserror::Error;

/// Result alias used throughout `ort-core`.
pub type Result<T> = core::result::Result<T, Error>;

/// All failures that the sans-IO core can produce.
#[derive(Debug, Error)]
pub enum Error {
    /// A byte slice had the wrong length for the target key/ciphertext type.
    #[error("invalid length for {what}: expected {expected}, got {got}")]
    InvalidLength {
        /// What was being decoded (e.g. "encapsulation key").
        what: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },

    /// A key, ciphertext or signature failed to decode/parse.
    #[error("malformed {0}")]
    Malformed(&'static str),

    /// Signature verification failed.
    #[error("signature verification failed")]
    BadSignature,

    /// AEAD open (decrypt/authenticate) failed.
    #[error("AEAD authentication failed")]
    AeadFailure,

    /// The advertised cipher suite id is not supported.
    #[error("unsupported cipher suite: {0:#06x}")]
    UnsupportedSuite(u16),

    /// The connection metadata timestamp is outside the accepted window.
    #[error("stale or future timestamp (outside replay window)")]
    StaleTimestamp,

    /// The source IP in the signed ConnMeta does not match the observed peer.
    #[error("source ip mismatch")]
    SourceIpMismatch,

    /// This ClientHello was already seen within the replay window.
    #[error("replayed handshake")]
    Replayed,

    /// The server-derived key hash did not match the client's expectation.
    #[error("key confirmation mismatch")]
    KeyConfirmationMismatch,

    /// A handshake message arrived in a state that does not expect it.
    #[error("unexpected handshake message in state {0}")]
    UnexpectedMessage(&'static str),
}
