//! ORT protocol core — sans-IO cipher suites, key schedule, handshake state
//! machine and record layer. Contains no networking; everything here is a pure
//! function of its inputs so it can be exercised with deterministic test
//! vectors and a mock clock.

#![forbid(unsafe_code)]

pub mod connmeta;
pub mod error;
pub mod handshake;
pub mod kdf;
pub mod pool;
pub mod record;
pub mod replay;
pub mod suite;
pub mod time;

pub use error::{Error, Result};
pub use suite::{CipherSuite, SuiteId};

/// Protocol label prefix mixed into every domain-separated derivation/signature.
pub const PROTOCOL_LABEL: &str = "ORT-v1";
