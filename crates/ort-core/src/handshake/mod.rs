//! Sans-IO handshake: client/server logic as pure transforms over frames.
//!
//! Multi-suite, DEK-wrapping design. The client generates a random session key
//! `enc_sk`, encrypts the early data once, and for each suite it offers wraps a
//! copy of `enc_sk` under that suite's KEM shared secret. One signature (under
//! the client's chosen `sig_alg`, independent of the KEM suites) covers the
//! whole payload. The server adopts whichever offered suite it supports,
//! unwraps `enc_sk`, and decrypts; if it shares no suite it replies
//! `ServerReject` instead of failing.

mod client;
mod server;

pub use client::{
    client_offer_zero_rtt, client_one_rtt_finish, client_one_rtt_hello, ClientConfig,
    ClientEstablished,
};
pub use server::{
    server_on_client_data, server_on_first, ServerConfig, ServerEstablished, ServerStep, SuiteKey,
};

use crate::prim;
use ort_proto::SuiteOffer;

/// Deterministic hash of the offered suites (binds suite ids + ciphertexts +
/// wrapped keys into the client signature). Must match on both peers.
pub fn offers_hash(offers: &[SuiteOffer]) -> [u8; 32] {
    let mut buf = Vec::new();
    for o in offers {
        buf.extend_from_slice(&o.suite_id.to_be_bytes());
        buf.extend_from_slice(&(o.ciphertext.len() as u32).to_be_bytes());
        buf.extend_from_slice(&o.ciphertext);
        buf.extend_from_slice(&(o.wrapped_enc_sk.len() as u32).to_be_bytes());
        buf.extend_from_slice(&o.wrapped_enc_sk);
    }
    prim::hash256(&buf)
}
