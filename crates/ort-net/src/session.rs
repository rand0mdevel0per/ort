//! Session driver: runs the ORT handshake over a framed TCP connection and
//! yields an established [`OrtConn`] ready for transparent forwarding.

use crate::cert::ServerVerifier;
use crate::error::{OrtError, Result};
use crate::transport::{FramedReader, FramedWriter};

use ort_core::handshake::{
    client_one_rtt_finish, client_one_rtt_hello, client_zero_rtt, server_on_client_data,
    server_on_first, ClientConfig, ServerConfig, ServerStep,
};
use ort_core::pool::Direction;
use ort_core::record::RecordLayer;
use ort_core::replay::StrikeCache;
use ort_core::suite::v1::V1;
use ort_core::time::Clock;
use ort_proto::Frame;

use std::sync::Arc;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Which end of the tunnel a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `ortc`: local app side.
    Client,
    /// `ortd`: target/backend side.
    Server,
}

impl Role {
    /// Direction used when sealing data this side sends into the tunnel.
    pub fn send_dir(self) -> Direction {
        match self {
            Role::Client => Direction::ClientToServer,
            Role::Server => Direction::ServerToClient,
        }
    }
    /// Direction used when opening data received from the tunnel.
    pub fn recv_dir(self) -> Direction {
        self.send_dir().flip()
    }
}

/// An established ORT connection: framed transport halves + record layer.
pub struct OrtConn {
    /// Framed reader over the tunnel socket.
    pub reader: FramedReader<OwnedReadHalf>,
    /// Framed writer over the tunnel socket.
    pub writer: FramedWriter<OwnedWriteHalf>,
    /// AEAD record layer for application traffic.
    pub record: RecordLayer<V1>,
    /// This connection's role.
    pub role: Role,
}

/// Result of a client handshake.
pub struct ClientOutcome {
    /// Established connection.
    pub conn: OrtConn,
    /// If 0-RTT, the expected `BLAKE3-512(enc_key)` to validate the ServerAck.
    pub expect_ack: Option<[u8; 64]>,
    /// The server KEM public key in use (to pin/cache for future 0-RTT).
    pub server_pk: Vec<u8>,
}

/// Drive the client side of the handshake.
#[allow(clippy::too_many_arguments)]
pub async fn client_open<C: Clock>(
    stream: TcpStream,
    ccfg: &ClientConfig<V1>,
    src_ip: [u8; 16],
    cached_server_pk: Option<Vec<u8>>,
    force_1rtt: bool,
    verifier: &ServerVerifier,
    clock: &C,
    early_data: &[u8],
) -> Result<ClientOutcome> {
    let _ = stream.set_nodelay(true);
    let (r, w) = stream.into_split();
    let mut reader = FramedReader::new(r);
    let mut writer = FramedWriter::new(w);

    match (&cached_server_pk, force_1rtt) {
        (Some(spk), false) => {
            // 0-RTT
            let (frame, est) = client_zero_rtt(ccfg, spk, src_ip, clock, early_data)?;
            writer.write_frame(&frame.encode()).await?;
            Ok(ClientOutcome {
                conn: OrtConn { reader, writer, record: est.record, role: Role::Client },
                expect_ack: Some(est.expected_ek_hash),
                server_pk: spk.clone(),
            })
        }
        _ => {
            // 1-RTT
            writer.write_frame(&client_one_rtt_hello(ccfg).encode()).await?;
            let body = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
            let (server_pk, certificate) = match Frame::decode(&body)? {
                Frame::ServerHello { server_pk, certificate, .. } => (server_pk, certificate),
                _ => return Err(OrtError::Unexpected("expected ServerHello")),
            };
            verifier.verify(&server_pk, &certificate)?;
            if let Some(pin) = &cached_server_pk {
                if pin != &server_pk {
                    return Err(OrtError::PinMismatch);
                }
            }
            let (frame, est) = client_one_rtt_finish(ccfg, &server_pk, src_ip, clock, early_data)?;
            writer.write_frame(&frame.encode()).await?;
            Ok(ClientOutcome {
                conn: OrtConn { reader, writer, record: est.record, role: Role::Client },
                expect_ack: None,
                server_pk,
            })
        }
    }
}

/// Result of a server handshake.
pub struct ServerOutcome {
    /// Established connection.
    pub conn: OrtConn,
    /// Decrypted first/early data block to forward to the target.
    pub early_data: Vec<u8>,
}

/// Drive the server side of the handshake.
pub async fn server_accept<C: Clock>(
    stream: TcpStream,
    peer_ip: [u8; 16],
    scfg: &ServerConfig<V1>,
    strike: &Arc<Mutex<StrikeCache>>,
    clock: &C,
) -> Result<ServerOutcome> {
    let _ = stream.set_nodelay(true);
    let (r, w) = stream.into_split();
    let mut reader = FramedReader::new(r);
    let mut writer = FramedWriter::new(w);

    let body = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
    let frame = Frame::decode(&body)?;

    let step = {
        let mut s = strike.lock().await;
        server_on_first(scfg, &frame, peer_ip, clock, &mut s)?
    };

    match step {
        ServerStep::ZeroRtt { ack, established } => {
            writer.write_frame(&ack.encode()).await?;
            Ok(ServerOutcome {
                conn: OrtConn { reader, writer, record: established.record, role: Role::Server },
                early_data: established.early_data,
            })
        }
        ServerStep::OneRtt { hello } => {
            writer.write_frame(&hello.encode()).await?;
            let body2 = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
            let frame2 = Frame::decode(&body2)?;
            let established = {
                let mut s = strike.lock().await;
                server_on_client_data(scfg, &frame2, peer_ip, clock, &mut s)?
            };
            Ok(ServerOutcome {
                conn: OrtConn { reader, writer, record: established.record, role: Role::Server },
                early_data: established.early_data,
            })
        }
    }
}
