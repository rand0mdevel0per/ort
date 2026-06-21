//! ORT networking layer: framed TCP transport, the session/handshake driver,
//! transparent forwarding, a lock-free replay guard, and cert verification.

#![forbid(unsafe_code)]

pub mod cert;
pub mod error;
pub mod forward;
pub mod replay;
pub mod run;
pub mod session;
pub mod transport;

pub use cert::ServerVerifier;
pub use error::{OrtError, Result};
pub use forward::forward;
pub use replay::ConcurrentStrikeCache;
pub use run::{ip_to_bytes, run_client, run_server, ClientParams};
pub use session::{
    client_0rtt, client_1rtt, server_accept, ClientOutcome, Learned, OrtConn, Role, ServerOutcome,
};
