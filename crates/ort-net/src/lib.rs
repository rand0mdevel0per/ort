//! ORT networking layer: framed TCP transport, the session/handshake driver,
//! transparent forwarding, and server-key verification.

#![forbid(unsafe_code)]

pub mod cert;
pub mod error;
pub mod forward;
pub mod run;
pub mod session;
pub mod transport;

pub use cert::{ServerVerifier, SERVERPK_OID_STR, SERVERPK_OID_U64};
pub use error::{OrtError, Result};
pub use forward::forward;
pub use run::{ip_to_bytes, run_client, run_server};
pub use session::{client_open, server_accept, ClientOutcome, OrtConn, Role, ServerOutcome};
