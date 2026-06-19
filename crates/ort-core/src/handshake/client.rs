//! Client-side handshake transforms.

use crate::connmeta::{sign_client_binding, ConnMeta};
use crate::kdf::derive_session_keys;
use crate::pool::Direction;
use crate::record::RecordLayer;
use crate::suite::{fresh_r, CipherSuite};
use crate::time::Clock;
use crate::Result;
use ort_proto::{Frame, KemPayload};

/// Per-client configuration for the handshake (the client's long-term
/// identity). The source IP is connection-specific and passed separately.
pub struct ClientConfig<S: CipherSuite> {
    /// Client signing secret (ML-DSA).
    pub sig_secret: S::SigSecret,
    /// Cached client verifying key bytes.
    pub client_pk: Vec<u8>,
}

/// Result of completing the client's side of a handshake.
pub struct ClientEstablished<S: CipherSuite> {
    /// Ready record layer for application traffic.
    pub record: RecordLayer<S>,
    /// Expected `BLAKE3-512(enc_key)`, to validate the server's ServerAck.
    pub expected_ek_hash: [u8; 64],
}

/// Build the shared KEM payload + record layer used by both 0-RTT and the 1-RTT
/// second flight.
fn build_payload<S: CipherSuite, C: Clock>(
    cfg: &ClientConfig<S>,
    server_pk: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(KemPayload, ClientEstablished<S>)> {
    let r = fresh_r();
    let (ciphertext, shared) = S::kem_encapsulate(server_pk, &r)?;

    let keys = derive_session_keys::<S>(&shared, &ciphertext);
    let mut nonce = [0u8; 32];
    crate::suite::fill_random(&mut nonce);

    let mut record = RecordLayer::<S>::new(keys, &nonce);
    let expected_ek_hash = record.enc_key_hash();
    let enc_data = record.seal(Direction::ClientToServer, early_data);

    let cm = ConnMeta {
        src_ip,
        ts_millis: clock.now_millis(),
        nonce,
    };
    let client_sig =
        sign_client_binding::<S>(&cfg.sig_secret, &cm, &cfg.client_pk, &ciphertext, &enc_data);

    let payload = KemPayload {
        ciphertext,
        src_ip: cm.src_ip,
        ts_millis: cm.ts_millis,
        nonce: cm.nonce,
        client_sig,
        enc_data,
    };
    Ok((payload, ClientEstablished { record, expected_ek_hash }))
}

/// 0-RTT: encapsulate against the cached `server_pk` and produce the
/// ClientHello carrying early data. The returned record layer is immediately
/// usable for further application data (no need to wait for ServerAck).
pub fn client_zero_rtt<S: CipherSuite, C: Clock>(
    cfg: &ClientConfig<S>,
    server_pk: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(Frame, ClientEstablished<S>)> {
    let (payload, established) = build_payload(cfg, server_pk, src_ip, clock, early_data)?;
    let frame = Frame::ClientHelloZeroRtt {
        suite_id: S::ID.code(),
        client_pk: cfg.client_pk.clone(),
        payload,
    };
    Ok((frame, established))
}

/// 1-RTT step 1: the bare ClientHello that requests the server's cert + public
/// key.
pub fn client_one_rtt_hello<S: CipherSuite>(cfg: &ClientConfig<S>) -> Frame {
    Frame::ClientHelloOneRtt {
        suite_id: S::ID.code(),
        client_pk: cfg.client_pk.clone(),
    }
}

/// 1-RTT step 2: after verifying the ServerHello's certificate and extracting
/// `server_pk`, produce the ClientData flight with early data.
pub fn client_one_rtt_finish<S: CipherSuite, C: Clock>(
    cfg: &ClientConfig<S>,
    server_pk: &[u8],
    src_ip: [u8; 16],
    clock: &C,
    early_data: &[u8],
) -> Result<(Frame, ClientEstablished<S>)> {
    let (payload, established) = build_payload(cfg, server_pk, src_ip, clock, early_data)?;
    let frame = Frame::ClientData {
        client_pk: cfg.client_pk.clone(),
        payload,
    };
    Ok((frame, established))
}
