//! Server-side handshake transforms (stateless apart from the replay guard).

use super::offers_hash;
use crate::connmeta::{verify_client_binding, ConnMeta};
use crate::kdf::derive_session_keys;
use crate::pool::Direction;
use crate::record::RecordLayer;
use crate::replay::ReplayGuard;
use crate::suite::agile::{suite_from_code, ServerKemKey};
use crate::suite::SuiteId;
use crate::time::{check_window, Clock};
use crate::{Error, Result};
use ort_proto::{reject, Frame, KemPayload, SuiteOffer};
use zeroize::Zeroizing;

/// A server KEM keypair for one suite, with its optional binding certificate.
pub struct SuiteKey {
    /// The suite's KEM secret.
    pub key: ServerKemKey,
    /// DER certificate binding the public key (empty if none).
    pub certificate: Vec<u8>,
}

/// Server configuration: the suites it supports (preference order) + windows.
pub struct ServerConfig {
    /// Supported suites, in server preference order.
    pub suites: Vec<SuiteKey>,
    /// Anti-replay acceptance window (ms).
    pub window_ms: u64,
    /// Permitted clock skew / future tolerance (ms).
    pub skew_ms: u64,
}

impl ServerConfig {
    fn find(&self, id: SuiteId) -> Option<&SuiteKey> {
        self.suites.iter().find(|s| s.key.suite_id() == id)
    }
}

/// A completed server-side handshake.
pub struct ServerEstablished {
    /// Ready record layer for application traffic.
    pub record: RecordLayer,
    /// Decrypted early/first data block to forward to the target.
    pub early_data: Vec<u8>,
}

/// Outcome of processing the client's first frame.
#[allow(clippy::large_enum_variant)]
pub enum ServerStep {
    /// 0-RTT accepted: send `ack`, forward `established.early_data`.
    ZeroRtt {
        /// Adopted suite.
        accepted_suite: SuiteId,
        /// ServerAck frame.
        ack: Frame,
        /// Established session.
        established: ServerEstablished,
    },
    /// 1-RTT: send `hello`, await ClientData for `selected`.
    OneRtt {
        /// ServerHello frame.
        hello: Frame,
        /// Suite the server selected (the ClientData offer must match it).
        selected: SuiteId,
    },
    /// Refuse the connection (send `frame`, then close).
    Reject {
        /// ServerReject frame.
        frame: Frame,
    },
}

/// Pick the offered suite to use. With `expected = Some(s)` (1-RTT second
/// flight) the offer must be exactly `s`; otherwise the first client-offered
/// suite the server supports (client preference order) is chosen.
fn select_offered<'a>(
    cfg: &'a ServerConfig,
    payload: &'a KemPayload,
    expected: Option<SuiteId>,
) -> Option<(&'a SuiteOffer, &'a SuiteKey)> {
    for offer in &payload.offers {
        let Some(suite) = SuiteId::from_code(offer.suite_id) else { continue };
        if let Some(exp) = expected {
            if suite != exp {
                continue;
            }
        }
        if let Some(key) = cfg.find(suite) {
            return Some((offer, key));
        }
    }
    None
}

/// Validate and process a client KEM payload. Order is fail-fast/DoS-aware:
/// cheap public checks and suite selection first (so unsupported-suite spam is
/// rejected without expensive signature work), then the client signature, then
/// the replay guard, then the KEM/AEAD work.
fn process_payload<C: Clock, G: ReplayGuard>(
    cfg: &ServerConfig,
    client_pk: &[u8],
    sig_alg_code: u16,
    payload: &KemPayload,
    peer_ip: [u8; 16],
    clock: &C,
    guard: &G,
    expected: Option<SuiteId>,
) -> Result<(SuiteId, ServerEstablished)> {
    let now = clock.now_millis();
    let sig_alg = suite_from_code(sig_alg_code)?;

    // (a) source IP binding
    if payload.src_ip != peer_ip {
        return Err(Error::SourceIpMismatch);
    }
    // (b) timestamp window
    check_window(now, payload.ts_millis, cfg.window_ms, cfg.skew_ms)?;
    // (c) select a mutually-supported suite *before* the expensive signature
    let (offer, suite_key) = select_offered(cfg, payload, expected).ok_or(Error::NoCommonSuite)?;
    let accepted = suite_key.key.suite_id();
    // (d) client binding signature (authenticates all offers + version + sig_alg)
    let cm = ConnMeta { src_ip: payload.src_ip, ts_millis: payload.ts_millis };
    let oh = offers_hash(&payload.offers);
    verify_client_binding(sig_alg, client_pk, &cm, &oh, &payload.client_sig)?;
    // (e) replay strike guard (authenticated payloads only)
    guard.check_and_insert(cm.replay_tag(&offer.nonce), now)?;
    // (f) decapsulate, derive keys from shared secret, open early data
    let shared = Zeroizing::new(suite_key.key.decapsulate(&offer.ciphertext)?);
    let keys = derive_session_keys(&shared, &offer.nonce);
    let mut record = RecordLayer::new(keys, &offer.nonce);
    let early_data = record.open(Direction::ClientToServer, &offer.enc_data)?;

    Ok((accepted, ServerEstablished { record, early_data }))
}

fn reject_frame(reason: u8) -> Frame {
    Frame::ServerReject { reason }
}

/// Process the client's first frame.
pub fn server_on_first<C: Clock, G: ReplayGuard>(
    cfg: &ServerConfig,
    frame: &Frame,
    peer_ip: [u8; 16],
    clock: &C,
    guard: &G,
) -> Result<ServerStep> {
    match frame {
        Frame::ClientHelloOneRtt { available_suites, .. } => {
            let chosen = available_suites
                .iter()
                .filter_map(|c| SuiteId::from_code(*c))
                .find_map(|s| cfg.find(s));
            match chosen {
                Some(suite_key) => Ok(ServerStep::OneRtt {
                    hello: Frame::ServerHello {
                        accepted_suite: suite_key.key.suite_id().code(),
                        server_pk: suite_key.key.public(),
                        certificate: suite_key.certificate.clone(),
                        observed_ip: peer_ip,
                        server_ts: clock.now_millis(),
                    },
                    selected: suite_key.key.suite_id(),
                }),
                None => Ok(ServerStep::Reject { frame: reject_frame(reject::NO_COMMON_SUITE) }),
            }
        }
        Frame::ClientHelloZeroRtt { client_pk, sig_alg, payload } => {
            match process_payload(cfg, client_pk, *sig_alg, payload, peer_ip, clock, guard, None) {
                Ok((accepted_suite, established)) => Ok(ServerStep::ZeroRtt {
                    accepted_suite,
                    ack: Frame::ServerAck {
                        accepted_suite: accepted_suite.code(),
                        ek_hash: established.record.enc_key_hash(),
                    },
                    established,
                }),
                Err(Error::NoCommonSuite) => {
                    Ok(ServerStep::Reject { frame: reject_frame(reject::NO_COMMON_SUITE) })
                }
                Err(e) => Err(e),
            }
        }
        _ => Err(Error::UnexpectedMessage("server_on_first")),
    }
}

/// Process the 1-RTT second flight ([`Frame::ClientData`]); the offer must be
/// for `expected` (the suite announced in ServerHello).
pub fn server_on_client_data<C: Clock, G: ReplayGuard>(
    cfg: &ServerConfig,
    frame: &Frame,
    peer_ip: [u8; 16],
    clock: &C,
    guard: &G,
    expected: SuiteId,
) -> Result<ServerEstablished> {
    match frame {
        Frame::ClientData { client_pk, sig_alg, payload } => {
            let (_suite, established) = process_payload(
                cfg,
                client_pk,
                *sig_alg,
                payload,
                peer_ip,
                clock,
                guard,
                Some(expected),
            )?;
            Ok(established)
        }
        _ => Err(Error::UnexpectedMessage("server_on_client_data")),
    }
}
