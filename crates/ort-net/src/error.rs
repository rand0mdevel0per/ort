//! ort-net error type.

use thiserror::Error;

/// Result alias for ort-net.
pub type Result<T> = std::result::Result<T, OrtError>;

/// Errors from the networked ORT session/handshake/forwarding layer.
#[derive(Debug, Error)]
pub enum OrtError {
    /// Underlying socket I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Frame encode/decode error.
    #[error("proto: {0}")]
    Proto(#[from] ort_proto::ProtoError),
    /// Core protocol/crypto error.
    #[error("core: {0}")]
    Core(#[from] ort_core::Error),
    /// Peer sent an unexpected frame for the current state.
    #[error("unexpected frame: {0}")]
    Unexpected(&'static str),
    /// Server key confirmation (ServerAck ek_hash) mismatch.
    #[error("server key confirmation failed")]
    KeyConfirmation,
    /// Pinned server public key did not match (possible MITM).
    #[error("server public key pin mismatch")]
    PinMismatch,
    /// Certificate verification failed.
    #[error("certificate verification failed: {0}")]
    Cert(String),
    /// Connection closed before the handshake completed.
    #[error("connection closed during handshake")]
    EarlyClose,
}
