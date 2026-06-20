//! Client-side handshake transforms.

use super::offers_hash;
use crate::connmeta::{sign_client_binding, ConnMeta};
use crate::kdf::{derive_session_keys, generate_enc_sk, wrap_enc_sk};
use crate::pool::Direction;
use crate::record::RecordLayer;
use crate::suite::agile::{self, SigIdentity};
use crate::suite::{fresh_r, SuiteId};
use crate::time::Clock;
use crate::Result;
use ort_proto::{Frame, KemPayload, SuiteOffer};

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
    /// Suite ids that were offered, so the client can check the accepted suite.
    pub offered_suites: Vec<SuiteId>,
}

/// Build the multi-suite KEM payload + record layer. `offers` pairs each suite
/// with the server public key the client holds for it.
fn build_payload<C: Clock>(
    cfg: &ClientConfig,
    offers: &[(SuiteId, Vec<u8>)],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(KemPayload, ClientEstablished)> {
    let enc_sk = generate_enc_sk()?;
    let mut nonce = [0u8; 32];
    crate::suite::fill_random(&mut nonce)?;

    let keys = derive_session_keys(&enc_sk, &nonce);
    let mut record = RecordLayer::new(keys, &nonce);
    let expected_ek_hash = record.enc_key_hash();
    let enc_data = record.seal(Direction::ClientToServer, early_data);

    let mut wire_offers = Vec::with_capacity(offers.len());
    let mut offered_suites = Vec::with_capacity(offers.len());
    for (suite, server_pk) in offers {
        let r = fresh_r()?;
        let (ciphertext, shared) = agile::kem_encapsulate(*suite, server_pk, &r)?;
        let wrapped_enc_sk = wrap_enc_sk(&shared, &ciphertext, suite.code(), &enc_sk);
        wire_offers.push(SuiteOffer {
            suite_id: suite.code(),
            ciphertext,
            wrapped_enc_sk,
        });
        offered_suites.push(*suite);
    }

    let oh = offers_hash(&wire_offers);
    let cm = ConnMeta {
        src_ip,
        ts_millis: clock.now_millis(),
        nonce,
    };
    let client_sig = sign_client_binding(&cfg.sig, &cm, &cfg.client_pk, &oh, &enc_data);

    let payload = KemPayload {
        offers: wire_offers,
        src_ip: cm.src_ip,
        ts_millis: cm.ts_millis,
        nonce: cm.nonce,
        client_sig,
        enc_data,
    };
    Ok((
        payload,
        ClientEstablished {
            record,
            expected_ek_hash,
            offered_suites,
        },
    ))
}

/// 1-RTT step 1: advertise supported KEM suites + the signature algorithm.
pub fn client_one_rtt_hello(cfg: &ClientConfig, available: &[SuiteId]) -> Frame {
    Frame::ClientHelloOneRtt {
        client_pk: cfg.client_pk.clone(),
        sig_alg: cfg.sig.suite_id().code(),
        available_suites: available.iter().map(|s| s.code()).collect(),
    }
}

/// 0-RTT: offer one or more cached suites with early data.
pub fn client_offer_zero_rtt<C: Clock>(
    cfg: &ClientConfig,
    offers: &[(SuiteId, Vec<u8>)],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(Frame, ClientEstablished)> {
    let (payload, est) = build_payload(cfg, offers, src_ip, clock, early_data)?;
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
    let offers = [(accepted_suite, server_pk.to_vec())];
    let (payload, est) = build_payload(cfg, &offers, src_ip, clock, early_data)?;
    let frame = Frame::ClientData {
        client_pk: cfg.client_pk.clone(),
        sig_alg: cfg.sig.suite_id().code(),
        payload,
    };
    Ok((frame, est))
}
