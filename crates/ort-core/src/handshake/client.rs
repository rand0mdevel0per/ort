//! Client-side handshake transforms.

use super::offers_hash;
use crate::connmeta::{sign_client_binding, ConnMeta};
use crate::kdf::derive_session_keys;
use crate::pool::Direction;
use crate::record::RecordLayer;
use crate::suite::agile::{self, SigIdentity};
use crate::suite::{fresh_r, SuiteId};
use crate::time::Clock;
use crate::Result;
use ort_proto::{Frame, KemPayload, SuiteOffer};
use zeroize::Zeroizing;

/// Per-client configuration (the client's long-term signing identity).
pub struct ClientConfig {
    /// Client signing identity (its suite id is the on-wire `sig_alg`).
    pub sig: SigIdentity,
    /// Cached client verifying-key bytes.
    pub client_pk: Vec<u8>,
}

impl ClientConfig {
    /// Build a config from a signing identity.
    pub fn new(sig: SigIdentity) -> Self {
        let client_pk = sig.public();
        ClientConfig { sig, client_pk }
    }
}

/// A completed client-side handshake.
pub struct ClientEstablished {
    /// Ready record layer for application traffic.
    pub record: RecordLayer,
    /// Expected `BLAKE3-512(enc_key)`, to validate the server's ServerAck.
    pub expected_ek_hash: [u8; 64],
    /// The suite that was offered (to check the server's accepted suite).
    pub offered_suite: SuiteId,
}

/// Build a single self-contained offer + the record layer. Each connection
/// derives its session keys directly from the KEM shared secret and a fresh
/// nonce, so each suite's keys are cryptographically independent.
fn build_payload<C: Clock>(
    cfg: &ClientConfig,
    suite: SuiteId,
    server_pk: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(KemPayload, ClientEstablished)> {
    let mut nonce = [0u8; 32];
    crate::suite::fill_random(&mut nonce)?;

    // Encapsulate against this suite's server key; derive session keys from the
    // shared secret (zeroized immediately after).
    let r = fresh_r()?;
    let (ciphertext, shared) = agile::kem_encapsulate(suite, server_pk, &r)?;
    let shared = Zeroizing::new(shared);
    let keys = derive_session_keys(&shared, &nonce);

    let mut record = RecordLayer::new(keys, &nonce);
    let expected_ek_hash = record.enc_key_hash();
    let enc_data = record.seal(Direction::ClientToServer, early_data);

    let offer = SuiteOffer { suite_id: suite.code(), ciphertext, nonce, enc_data };
    let offers = vec![offer];
    let oh = offers_hash(&offers);

    let cm = ConnMeta { src_ip, ts_millis: clock.now_millis() };
    let client_sig = sign_client_binding(&cfg.sig, &cm, &cfg.client_pk, &oh);

    let payload = KemPayload { offers, src_ip: cm.src_ip, ts_millis: cm.ts_millis, client_sig };
    Ok((payload, ClientEstablished { record, expected_ek_hash, offered_suite: suite }))
}

/// 1-RTT step 1: advertise supported KEM suites + the signature algorithm.
pub fn client_one_rtt_hello(cfg: &ClientConfig, available: &[SuiteId]) -> Frame {
    Frame::ClientHelloOneRtt {
        client_pk: cfg.client_pk.clone(),
        sig_alg: cfg.sig.suite_id().code(),
        available_suites: available.iter().map(|s| s.code()).collect(),
    }
}

/// 0-RTT: resume with a single cached suite, sending early data.
pub fn client_offer_zero_rtt<C: Clock>(
    cfg: &ClientConfig,
    suite: SuiteId,
    server_pk: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(Frame, ClientEstablished)> {
    let (payload, est) = build_payload(cfg, suite, server_pk, src_ip, clock, early_data)?;
    let frame = Frame::ClientHelloZeroRtt {
        client_pk: cfg.client_pk.clone(),
        sig_alg: cfg.sig.suite_id().code(),
        payload,
    };
    Ok((frame, est))
}

/// 1-RTT step 2: after a ServerHello picks `accepted_suite` and provides its
/// `server_pk` (and the server-observed `src_ip`), send the data flight.
pub fn client_one_rtt_finish<C: Clock>(
    cfg: &ClientConfig,
    accepted_suite: SuiteId,
    server_pk: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(Frame, ClientEstablished)> {
    let (payload, est) = build_payload(cfg, accepted_suite, server_pk, src_ip, clock, early_data)?;
    let frame = Frame::ClientData {
        client_pk: cfg.client_pk.clone(),
        sig_alg: cfg.sig.suite_id().code(),
        payload,
    };
    Ok((frame, est))
}
