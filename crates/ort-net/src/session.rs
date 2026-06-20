//! Session driver: runs the ORT handshake over a framed TCP connection and
//! yields an established [`OrtConn`] ready for transparent forwarding.

use crate::cert::ServerVerifier;
use crate::error::{OrtError, Result};
use crate::transport::{FramedReader, FramedWriter};

use ort_core::handshake::{
    client_offer_zero_rtt, client_one_rtt_finish, client_one_rtt_hello, server_on_client_data,
    server_on_first, ClientConfig, ServerConfig, ServerStep,
};
use ort_core::pool::Direction;
use ort_core::record::RecordLayer;
use ort_core::replay::ReplayGuard;
use ort_core::suite::SuiteId;
use ort_core::time::Clock;
use ort_proto::Frame;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// Which end of the tunnel a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `ortc`: local app side (seals client→server).
    Client,
    /// `ortd`: target/backend side (seals server→client).
    Server,
}

impl Role {
    /// Direction this side seals into.
    pub fn send_dir(self) -> Direction {
        match self {
            Role::Client => Direction::ClientToServer,
            Role::Server => Direction::ServerToClient,
        }
    }
}

/// An established ORT connection: framed transport halves + record layer.
pub struct OrtConn {
    /// Framed reader over the tunnel socket.
    pub reader: FramedReader<OwnedReadHalf>,
    /// Framed writer over the tunnel socket.
    pub writer: FramedWriter<OwnedWriteHalf>,
    /// AEAD record layer for application traffic.
    pub record: RecordLayer,
    /// This connection's role.
    pub role: Role,
}

/// Server key info learned from a 1-RTT handshake, to cache for 0-RTT.
#[derive(Debug, Clone)]
pub struct Learned {
    /// Client source IP as observed by the server (NAT-safe).
    pub observed_ip: [u8; 16],
    /// Suite the server accepted.
    pub accepted_suite: SuiteId,
    /// Server KEM public key for that suite.
    pub server_pk: Vec<u8>,
}

/// Result of a client handshake.
pub struct ClientOutcome {
    /// Established connection.
    pub conn: OrtConn,
    /// 0-RTT only: `(expected ek_hash, offered suites)` for ServerAck checking.
    pub expect_ack: Option<([u8; 64], Vec<SuiteId>)>,
    /// 1-RTT only: server key info to cache for future 0-RTT.
    pub learned: Option<Learned>,
}

fn split(stream: TcpStream) -> (FramedReader<OwnedReadHalf>, FramedWriter<OwnedWriteHalf>) {
    let _ = stream.set_nodelay(true);
    let (r, w) = stream.into_split();
    (FramedReader::new(r), FramedWriter::new(w))
}

/// Drive the client's 1-RTT handshake (first contact). Advertises `kem_suites`.
pub async fn client_1rtt<C: Clock>(
    stream: TcpStream,
    cfg: &ClientConfig,
    kem_suites: &[SuiteId],
    verifier: &ServerVerifier,
    pinned: Option<&[u8]>,
    clock: &C,
    early_data: &[u8],
) -> Result<ClientOutcome> {
    let (mut reader, mut writer) = split(stream);
    writer
        .write_frame(&client_one_rtt_hello(cfg, kem_suites).encode())
        .await?;

    let body = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
    let (accepted_suite, server_pk, certificate, observed_ip) = match Frame::decode(&body)? {
        Frame::ServerHello {
            accepted_suite,
            server_pk,
            certificate,
            observed_ip,
            ..
        } => (accepted_suite, server_pk, certificate, observed_ip),
        Frame::ServerReject { reason } => return Err(OrtError::Rejected(reason)),
        _ => return Err(OrtError::Unexpected("expected ServerHello")),
    };

    let suite =
        SuiteId::from_code(accepted_suite).ok_or(OrtError::UnexpectedSuite(accepted_suite))?;
    if !kem_suites.contains(&suite) {
        return Err(OrtError::UnexpectedSuite(accepted_suite));
    }
    verifier.verify(&server_pk, &certificate)?;
    if let Some(pin) = pinned {
        if pin != server_pk {
            return Err(OrtError::PinMismatch);
        }
    }

    let (frame, est) =
        client_one_rtt_finish(cfg, suite, &server_pk, observed_ip, clock, early_data)?;
    writer.write_frame(&frame.encode()).await?;

    Ok(ClientOutcome {
        conn: OrtConn {
            reader,
            writer,
            record: est.record,
            role: Role::Client,
        },
        expect_ack: None,
        learned: Some(Learned {
            observed_ip,
            accepted_suite: suite,
            server_pk,
        }),
    })
}

/// Drive the client's 0-RTT handshake using cached `offers` and the previously
/// server-observed `src_ip`.
pub async fn client_0rtt<C: Clock>(
    stream: TcpStream,
    cfg: &ClientConfig,
    offers: &[(SuiteId, Vec<u8>)],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<ClientOutcome> {
    let (reader, mut writer) = split(stream);
    let (frame, est) = client_offer_zero_rtt(cfg, offers, src_ip, clock, early_data)?;
    writer.write_frame(&frame.encode()).await?;
    Ok(ClientOutcome {
        conn: OrtConn {
            reader,
            writer,
            record: est.record,
            role: Role::Client,
        },
        expect_ack: Some((est.expected_ek_hash, est.offered_suites)),
        learned: None,
    })
}

/// Result of a server handshake.
pub struct ServerOutcome {
    /// Established connection.
    pub conn: OrtConn,
    /// Decrypted first/early data block to forward to the target.
    pub early_data: Vec<u8>,
}

/// Drive the server side of the handshake. On no-common-suite the server sends
/// a ServerReject and this returns [`OrtError::Rejected`].
pub async fn server_accept<C: Clock, G: ReplayGuard>(
    stream: TcpStream,
    peer_ip: [u8; 16],
    scfg: &ServerConfig,
    guard: &G,
    clock: &C,
) -> Result<ServerOutcome> {
    let (mut reader, mut writer) = split(stream);

    let body = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
    let frame = Frame::decode(&body)?;
    let step = server_on_first(scfg, &frame, peer_ip, clock, guard)?;

    match step {
        ServerStep::ZeroRtt {
            ack, established, ..
        } => {
            writer.write_frame(&ack.encode()).await?;
            Ok(ServerOutcome {
                conn: OrtConn {
                    reader,
                    writer,
                    record: established.record,
                    role: Role::Server,
                },
                early_data: established.early_data,
            })
        }
        ServerStep::OneRtt { hello } => {
            writer.write_frame(&hello.encode()).await?;
            let body2 = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
            let frame2 = Frame::decode(&body2)?;
            let established = server_on_client_data(scfg, &frame2, peer_ip, clock, guard)?;
            Ok(ServerOutcome {
                conn: OrtConn {
                    reader,
                    writer,
                    record: established.record,
                    role: Role::Server,
                },
                early_data: established.early_data,
            })
        }
        ServerStep::Reject { frame } => {
            let reason = match &frame {
                Frame::ServerReject { reason } => *reason,
                _ => 0,
            };
            writer.write_frame(&frame.encode()).await?;
            let _ = writer.shutdown().await;
            Err(OrtError::Rejected(reason))
        }
    }
}
