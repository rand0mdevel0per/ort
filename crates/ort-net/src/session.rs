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
    /// Server's certificate (DER), for Half-RTT signature verification.
    pub certificate: Vec<u8>,
}

/// Result of a client handshake.
pub struct ClientOutcome {
    /// Established connection (handshake fully complete, incl. 0-RTT ServerAck).
    pub conn: OrtConn,
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
    let (accepted_suite, server_pk, server_pk_signature, certificate, observed_ip) = match Frame::decode(&body)? {
        Frame::ServerHello {
            accepted_suite,
            server_pk,
            server_pk_signature,
            certificate,
            observed_ip,
            ..
        } => (accepted_suite, server_pk, server_pk_signature, certificate, observed_ip),
        Frame::ServerReject { reason } => return Err(OrtError::Rejected(reason)),
        _ => return Err(OrtError::Unexpected("expected ServerHello")),
    };

    let suite =
        SuiteId::from_code(accepted_suite).ok_or(OrtError::UnexpectedSuite(accepted_suite))?;
    if !kem_suites.contains(&suite) {
        return Err(OrtError::UnexpectedSuite(accepted_suite));
    }

    // Verify certificate (if present) and server_pk signature
    if !certificate.is_empty() {
        verifier.verify(&certificate)?;
        let (cert_vk, sig_suite) = crate::cert::extract_signing_key(&certificate)?;

        // Verify server_pk signature to prove ownership
        // In strict mode, empty signature is a hard failure (MITM risk)
        if server_pk_signature.is_empty() {
            if matches!(verifier, ServerVerifier::Strict { .. }) {
                return Err(OrtError::Cert("server_pk_signature is required in strict mode".into()));
            }
        } else {
            let server_pk_hash = ort_core::prim::hash256(&server_pk);
            ort_core::suite::agile::sig_verify(sig_suite, &cert_vk, &server_pk_hash, &server_pk_signature)?;
        }
    } else {
        // No certificate: TOFU mode or test environment
        // Signature verification is skipped (trust on first use)
    }

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
        learned: Some(Learned {
            observed_ip,
            accepted_suite: suite,
            server_pk,
            certificate,
        }),
    })
}

/// Drive the client's 0-RTT handshake resuming a single cached `suite` (with
/// its `server_pk`) and the previously server-observed `src_ip`. The ServerAck
/// is read and verified inline, so the returned connection is fully confirmed;
/// a `ServerReject` (e.g. the server dropped the suite) surfaces as
/// [`OrtError::Rejected`] so the caller can fall back to 1-RTT.
pub async fn client_0rtt<C: Clock>(
    stream: TcpStream,
    cfg: &ClientConfig,
    suite: SuiteId,
    server_pk: &[u8],
    server_cert: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<ClientOutcome> {
    let (mut reader, mut writer) = split(stream);
    let (frame, mut est) = client_offer_zero_rtt(cfg, suite, server_pk, src_ip, clock, early_data)?;
    writer.write_frame(&frame.encode()).await?;

    // Await server response: ServerAck (0-RTT) or ServerRefuse0RTT (Half-RTT)
    let body = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
    match Frame::decode(&body)? {
        Frame::ServerAck { accepted_suite, ek_hash } => {
            if accepted_suite != est.offered_suite.code() {
                return Err(OrtError::UnexpectedSuite(accepted_suite));
            }
            if ek_hash != est.expected_ek_hash {
                return Err(OrtError::KeyConfirmation);
            }
            // 0-RTT success
            Ok(ClientOutcome {
                conn: OrtConn {
                    reader,
                    writer,
                    record: est.record,
                    role: Role::Client,
                },
                learned: None,
            })
        }
        Frame::ServerRefuse0RTT {
            accepted_suite,
            server_ct,
            nonce,
            server_signature,
        } => {
            // Half-RTT fallback: server rejected 0-RTT but provided server_ct + signature
            if accepted_suite != est.offered_suite.code() {
                return Err(OrtError::UnexpectedSuite(accepted_suite));
            }

            // Extract server's signing public key from cached certificate
            // TODO: This should parse the certificate and extract the public key
            // For now, we need a helper function in cert module
            let (server_vk, sig_suite) = crate::cert::extract_signing_key(server_cert)?;

            // Verify server signature and establish channel
            ort_core::handshake::client_half_rtt_finish(
                &mut est,
                accepted_suite,
                &server_ct,
                &nonce,
                &server_signature,
                &server_vk,
                sig_suite,
            )?;

            // Channel established, early data was NOT delivered (0-RTT rejected)
            Ok(ClientOutcome {
                conn: OrtConn {
                    reader,
                    writer,
                    record: est.record,
                    role: Role::Client,
                },
                learned: None,
            })
        }
        Frame::ServerReject { reason } => Err(OrtError::Rejected(reason)),
        _ => Err(OrtError::Unexpected("expected ServerAck or ServerRefuse0RTT")),
    }
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
        ServerStep::HalfRtt {
            accepted_suite: _,
            frame,
            shared,
            nonce,
        } => {
            // Send ServerRefuse0RTT to client
            writer.write_frame(&frame.encode()).await?;

            // Derive session keys from the shared secret and nonce
            let keys = ort_core::kdf::derive_session_keys(&shared, &nonce);
            let record = ort_core::record::RecordLayer::new(keys, &nonce);

            // Client will process Half-RTT and start sending DataRecords
            // We don't have early_data (0-RTT was rejected), so return empty
            Ok(ServerOutcome {
                conn: OrtConn {
                    reader,
                    writer,
                    record,
                    role: Role::Server,
                },
                early_data: Vec::new(),
            })
        }
        ServerStep::OneRtt { hello, selected } => {
            writer.write_frame(&hello.encode()).await?;
            let body2 = reader.read_frame().await?.ok_or(OrtError::EarlyClose)?;
            let frame2 = Frame::decode(&body2)?;
            let established =
                server_on_client_data(scfg, &frame2, peer_ip, clock, guard, selected)?;
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
