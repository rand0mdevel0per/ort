//! Server-side handshake transforms (stateless apart from the strike cache).

use crate::connmeta::{verify_client_binding, ConnMeta};
use crate::kdf::derive_session_keys;
use crate::pool::Direction;
use crate::record::RecordLayer;
use crate::replay::{replay_tag, StrikeCache};
use crate::suite::{CipherSuite, SuiteId};
use crate::time::{check_window, Clock};
use crate::{Error, Result};
use ort_proto::{Frame, KemPayload};

/// Server configuration for the handshake.
pub struct ServerConfig<S: CipherSuite> {
    /// Server KEM secret (decapsulation key).
    pub kem_secret: S::KemSecret,
    /// Cached server KEM public key bytes.
    pub server_pk: Vec<u8>,
    /// DER certificate chain binding `server_pk` (empty if none configured).
    pub certificate: Vec<u8>,
    /// Anti-replay acceptance window in milliseconds.
    pub window_ms: u64,
    /// Permitted clock skew (future tolerance) in milliseconds.
    pub skew_ms: u64,
}

/// A completed server-side handshake.
pub struct ServerEstablished<S: CipherSuite> {
    /// Ready record layer for application traffic.
    pub record: RecordLayer<S>,
    /// Decrypted early/first data block to forward to the target.
    pub early_data: Vec<u8>,
}

/// Outcome of processing the client's first frame.
#[allow(clippy::large_enum_variant)]
pub enum ServerStep<S: CipherSuite> {
    /// 0-RTT accepted: send `ack` and begin forwarding `established.early_data`.
    ZeroRtt {
        /// ServerAck frame (key confirmation).
        ack: Frame,
        /// Established session.
        established: ServerEstablished<S>,
    },
    /// 1-RTT: send `hello` and await a [`Frame::ClientData`].
    OneRtt {
        /// ServerHello frame (cert + public key).
        hello: Frame,
    },
}

fn check_suite(suite_id: u16) -> Result<()> {
    match SuiteId::from_code(suite_id) {
        Some(_) => Ok(()),
        None => Err(Error::UnsupportedSuite(suite_id)),
    }
}

fn server_hello<S: CipherSuite, C: Clock>(cfg: &ServerConfig<S>, clock: &C) -> Frame {
    Frame::ServerHello {
        suite_id: S::ID.code(),
        server_pk: cfg.server_pk.clone(),
        certificate: cfg.certificate.clone(),
        server_ts: clock.now_millis(),
    }
}

/// Validate and process a client KEM payload, producing an established session.
///
/// Order is chosen for fail-fast/DoS resistance: cheap public checks (source IP,
/// timestamp window) first, then the client signature (authenticates the
/// payload), then the replay strike-cache insert (only authenticated payloads
/// reach it), and finally the expensive decapsulation + early-data open.
fn process_payload<S: CipherSuite, C: Clock>(
    cfg: &ServerConfig<S>,
    client_pk: &[u8],
    payload: &KemPayload,
    peer_ip: [u8; 16],
    clock: &C,
    strike: &mut StrikeCache,
) -> Result<ServerEstablished<S>> {
    let now = clock.now_millis();

    // (a) source IP binding
    if payload.src_ip != peer_ip {
        return Err(Error::SourceIpMismatch);
    }
    // (b) timestamp window
    check_window(now, payload.ts_millis, cfg.window_ms, cfg.skew_ms)?;
    // (c) client binding signature (authenticates ct, enc_data, ConnMeta)
    let cm = ConnMeta {
        src_ip: payload.src_ip,
        ts_millis: payload.ts_millis,
        nonce: payload.nonce,
    };
    verify_client_binding::<S>(client_pk, &cm, &payload.ciphertext, &payload.enc_data, &payload.client_sig)?;
    // (d) replay strike cache (authenticated payloads only)
    let tag = replay_tag::<S>(&payload.nonce, &payload.enc_data);
    strike.check_and_insert(tag, now)?;
    // (e) decapsulate, derive keys, open early data
    let shared = S::kem_decapsulate(&cfg.kem_secret, &payload.ciphertext)?;
    let keys = derive_session_keys::<S>(&shared, &payload.ciphertext);
    let mut record = RecordLayer::<S>::new(keys, &payload.nonce);
    let early_data = record.open(Direction::ClientToServer, &payload.enc_data)?;

    Ok(ServerEstablished { record, early_data })
}

/// Process the client's first frame: 0-RTT ClientHello → established + ack;
/// 1-RTT ClientHello → ServerHello.
pub fn server_on_first<S: CipherSuite, C: Clock>(
    cfg: &ServerConfig<S>,
    frame: &Frame,
    peer_ip: [u8; 16],
    clock: &C,
    strike: &mut StrikeCache,
) -> Result<ServerStep<S>> {
    match frame {
        Frame::ClientHelloOneRtt { suite_id, .. } => {
            check_suite(*suite_id)?;
            Ok(ServerStep::OneRtt {
                hello: server_hello(cfg, clock),
            })
        }
        Frame::ClientHelloZeroRtt {
            suite_id,
            client_pk,
            payload,
        } => {
            check_suite(*suite_id)?;
            let established = process_payload(cfg, client_pk, payload, peer_ip, clock, strike)?;
            let ack = Frame::ServerAck {
                ek_hash: established.record.enc_key_hash().to_vec(),
            };
            Ok(ServerStep::ZeroRtt { ack, established })
        }
        _ => Err(Error::UnexpectedMessage("server_on_first")),
    }
}

/// Process the 1-RTT second flight ([`Frame::ClientData`]).
pub fn server_on_client_data<S: CipherSuite, C: Clock>(
    cfg: &ServerConfig<S>,
    frame: &Frame,
    peer_ip: [u8; 16],
    clock: &C,
    strike: &mut StrikeCache,
) -> Result<ServerEstablished<S>> {
    match frame {
        Frame::ClientData { client_pk, payload } => {
            process_payload(cfg, client_pk, payload, peer_ip, clock, strike)
        }
        _ => Err(Error::UnexpectedMessage("server_on_client_data")),
    }
}
