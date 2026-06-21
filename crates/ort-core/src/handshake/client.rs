//! Client-side handshake transforms.

use super::offers_hash;
use crate::connmeta::{sign_client_binding, ConnMeta};
use crate::kdf::derive_session_keys;
use crate::pool::Direction;
use crate::record::RecordLayer;
use crate::suite::agile::{self, SigIdentity};
use crate::suite::{fresh_r, SuiteId};
use crate::time::Clock;
use crate::{Error, Result};
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
    /// Ephemeral KEM secret for Half-RTT fallback (0-RTT only).
    pub temp_kem_secret: Option<agile::ServerKemKey>,
}

/// Build a single self-contained offer + the record layer. Each connection
/// derives its session keys directly from the KEM shared secret and a fresh
/// nonce, so each suite's keys are cryptographically independent.
///
/// For 0-RTT, also generates an ephemeral KEM keypair for Half-RTT fallback.
fn build_payload<C: Clock>(
    cfg: &ClientConfig,
    suite: SuiteId,
    server_pk: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
    is_zero_rtt: bool,
) -> Result<(KemPayload, Vec<u8>, Option<agile::ServerKemKey>, ClientEstablished)> {
    let mut nonce = [0u8; 32];
    crate::suite::fill_random(&mut nonce)?;

    // Encapsulate against this suite's server key; derive session keys from the
    // shared secret (zeroized immediately after).
    let r = Zeroizing::new(fresh_r()?);
    let (ciphertext, shared) = agile::kem_encapsulate(suite, server_pk, &r)?;
    let shared = Zeroizing::new(shared);
    let keys = derive_session_keys(&shared, &nonce);

    let mut record = RecordLayer::new(keys, &nonce);
    let expected_ek_hash = record.enc_key_hash();
    let enc_data = record.seal(Direction::ClientToServer, early_data);

    let offer = SuiteOffer { suite_id: suite.code(), ciphertext, nonce, enc_data };
    let offers = vec![offer];
    let oh = offers_hash(&offers);

    // For 0-RTT: generate ephemeral KEM keypair for Half-RTT fallback
    let (temp_kem_secret, client_kem_pk) = if is_zero_rtt {
        let temp = agile::ServerKemKey::generate(suite);
        let pk = temp.public();
        (Some(temp), pk)
    } else {
        (None, Vec::new())
    };

    let sig_pk_hash = crate::prim::hash256(&cfg.client_pk);
    let kem_pk_hash = crate::prim::hash256(&client_kem_pk);

    let cm = ConnMeta { src_ip, ts_millis: clock.now_millis(), sig_pk_hash, kem_pk_hash };
    let client_sig = sign_client_binding(&cfg.sig, &cm, &oh);

    let payload = KemPayload { offers, src_ip: cm.src_ip, ts_millis: cm.ts_millis, client_sig };
    Ok((payload, client_kem_pk, temp_kem_secret, ClientEstablished { record, expected_ek_hash, offered_suite: suite, temp_kem_secret: None }))
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
    let (payload, client_kem_pk, temp_kem_secret, mut est) = build_payload(cfg, suite, server_pk, src_ip, clock, early_data, true)?;
    est.temp_kem_secret = temp_kem_secret;
    let frame = Frame::ClientHelloZeroRtt {
        client_pk: cfg.client_pk.clone(),
        client_kem_pk,
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
    let (payload, _client_kem_pk, _temp_kem_secret, est) = build_payload(cfg, accepted_suite, server_pk, src_ip, clock, early_data, false)?;
    let frame = Frame::ClientData {
        client_pk: cfg.client_pk.clone(),
        sig_alg: cfg.sig.suite_id().code(),
        payload,
    };
    Ok((frame, est))
}

/// Half-RTT: process ServerRefuse0RTT and establish the channel using the
/// server's ciphertext. The server encapsulated to our ephemeral KEM key.
///
/// The server signature must be verified using the cached server certificate's
/// public key (extracted by ort-net layer). This prevents MITM attacks.
pub fn client_half_rtt_finish(
    est: &mut ClientEstablished,
    accepted_suite: u16,
    server_ct: &[u8],
    nonce: &[u8; 32],
    server_signature: &[u8],
    server_vk: &[u8],
    sig_suite: SuiteId,
) -> Result<()> {
    // Verify server signature over (accepted_suite || server_ct || nonce)
    let mut to_verify = Vec::new();
    to_verify.extend_from_slice(&accepted_suite.to_be_bytes());
    to_verify.extend_from_slice(server_ct);
    to_verify.extend_from_slice(nonce);

    agile::sig_verify(sig_suite, server_vk, &to_verify, server_signature)?;

    // Signature verified, now establish channel
    let temp_kem = est.temp_kem_secret.take().ok_or(Error::UnexpectedMessage("no temp KEM secret"))?;
    let shared = Zeroizing::new(temp_kem.decapsulate(server_ct)?);
    let keys = derive_session_keys(&shared, nonce);
    est.record = RecordLayer::new(keys, nonce);
    est.expected_ek_hash = est.record.enc_key_hash();
    Ok(())
}
