//! Sans-IO handshake: client/server logic as pure transforms over frames.
//!
//! Two modes:
//! - **0-RTT** (client already holds a verified `server_pk`): the client
//!   encapsulates immediately and sends [`Frame::ClientHelloZeroRtt`] with early
//!   data; the server replies [`Frame::ServerAck`] and forwards the data.
//! - **1-RTT** (first contact): client sends [`Frame::ClientHelloOneRtt`], the
//!   server replies [`Frame::ServerHello`] with its cert + public key, then the
//!   client sends [`Frame::ClientData`] (same KEM payload as 0-RTT).

mod client;
mod server;

pub use client::{
    client_one_rtt_finish, client_one_rtt_hello, client_zero_rtt, ClientConfig, ClientEstablished,
};
pub use server::{
    server_on_client_data, server_on_first, ServerConfig, ServerEstablished, ServerStep,
};
