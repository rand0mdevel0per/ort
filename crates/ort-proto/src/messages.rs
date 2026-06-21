//! ORT frame message types and their binary encoding.

use crate::codec::{Reader, Writer};
use crate::ProtoError;

/// Maximum number of cipher suites a client may advertise/offer in one hello
/// (bounds allocation when decoding).
pub const MAX_SUITES: usize = 16;

/// BLAKE3-512 key-confirmation hash length.
pub const EK_HASH_LEN: usize = 64;

/// Reason codes for [`Frame::ServerReject`].
pub mod reject {
    /// No cipher suite offered by the client is supported by the server.
    pub const NO_COMMON_SUITE: u8 = 1;
    /// The handshake failed validation (signature/replay/decrypt).
    pub const BAD_HANDSHAKE: u8 = 2;
}

/// Frame type tags (first byte of every frame body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// First flight, 1-RTT mode: advertise supported suites, request cert + key.
    ClientHelloOneRtt = 0x01,
    /// First flight, 0-RTT mode: multi-suite offers + early data.
    ClientHelloZeroRtt = 0x02,
    /// Second flight in 1-RTT mode: offers (for the negotiated suite) + data.
    ClientData = 0x03,
    /// Server response carrying the accepted suite, its public key + cert.
    ServerHello = 0x04,
    /// Server 0-RTT acknowledgement: accepted suite + key-confirmation hash.
    ServerAck = 0x05,
    /// Server refusal (e.g. no common suite, bad handshake).
    ServerReject = 0x06,
    /// Server Half-RTT fallback: 0-RTT rejected but channel can be established.
    ServerRefuse0RTT = 0x09,
    /// An AEAD-protected application data record.
    DataRecord = 0x07,
    /// Orderly shutdown.
    Close = 0x08,
}

impl FrameType {
    fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0x01 => FrameType::ClientHelloOneRtt,
            0x02 => FrameType::ClientHelloZeroRtt,
            0x03 => FrameType::ClientData,
            0x04 => FrameType::ServerHello,
            0x05 => FrameType::ServerAck,
            0x06 => FrameType::ServerReject,
            0x07 => FrameType::DataRecord,
            0x08 => FrameType::Close,
            0x09 => FrameType::ServerRefuse0RTT,
            other => return Err(ProtoError::UnknownFrameType(other)),
        })
    }
}

/// One self-contained per-suite offer. Each offer is cryptographically
/// independent: its own KEM encapsulation against that suite's server key, its
/// own fresh `nonce`, and its own early data. The session key (`enc_sk`) is
/// derived on both peers from this offer's KEM shared secret and `nonce`, so no
/// key is shared across suites (no weakest-link) and nothing extra is wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteOffer {
    /// Cipher-suite id this offer is for.
    pub suite_id: u16,
    /// KEM ciphertext (encapsulation against the suite's server public key).
    pub ciphertext: Vec<u8>,
    /// Fresh per-offer nonce (salts the key schedule and the replay tag).
    pub nonce: [u8; 32],
    /// Early data sealed under this offer's derived `enc_sk`. The record nonce
    /// is pool-derived (not transmitted).
    pub enc_data: Vec<u8>,
}

/// The client's KEM-bearing payload (0-RTT ClientHello or 1-RTT ClientData).
///
/// 0-RTT carries a single offer (the previously-negotiated suite); 1-RTT
/// advertises suites in [`Frame::ClientHelloOneRtt`] and the ClientData carries
/// the one offer the server selected. The wire format permits multiple offers
/// for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemPayload {
    /// One or more self-contained per-suite offers (at least one).
    pub offers: Vec<SuiteOffer>,
    /// Client source IP (16 bytes; for 1-RTT this echoes the server-observed IP).
    pub src_ip: [u8; 16],
    /// Client timestamp in milliseconds since the Unix epoch.
    pub ts_millis: u64,
    /// Signature over the client binding string (one signature, under `sig_alg`).
    pub client_sig: Vec<u8>,
}

impl KemPayload {
    fn write(&self, w: &mut Writer) {
        // Note: encoder does not validate bounds; the decoder will reject invalid payloads.
        // This allows robustness tests to encode malformed frames for testing purposes.
        w.u16(self.offers.len() as u16);
        for o in &self.offers {
            w.u16(o.suite_id)
                .bytes(&o.ciphertext)
                .raw(&o.nonce)
                .bytes(&o.enc_data);
        }
        w.raw(&self.src_ip).u64(self.ts_millis).bytes(&self.client_sig);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let count = r.u16()? as usize;
        if count == 0 {
            return Err(ProtoError::Empty("suite offers"));
        }
        if count > MAX_SUITES {
            return Err(ProtoError::TooMany("suite offers"));
        }
        let mut offers = Vec::with_capacity(count);
        for _ in 0..count {
            offers.push(SuiteOffer {
                suite_id: r.u16()?,
                ciphertext: r.bytes()?.to_vec(),
                nonce: r.array::<32>()?,
                enc_data: r.bytes()?.to_vec(),
            });
        }
        Ok(KemPayload {
            offers,
            src_ip: r.array::<16>()?,
            ts_millis: r.u64()?,
            client_sig: r.bytes()?.to_vec(),
        })
    }
}

/// A decoded ORT protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// 1-RTT ClientHello: advertise suites + present client verifying key.
    ClientHelloOneRtt {
        /// Client verifying key.
        client_pk: Vec<u8>,
        /// Signature algorithm (suite id) that `client_pk`/signatures use.
        sig_alg: u16,
        /// KEM suite ids the client supports, in preference order.
        available_suites: Vec<u16>,
    },
    /// 0-RTT ClientHello: client key + multi-suite KEM payload.
    ClientHelloZeroRtt {
        /// Client verifying key (for signatures).
        client_pk: Vec<u8>,
        /// Ephemeral KEM public key (for Half-RTT fallback).
        client_kem_pk: Vec<u8>,
        /// Signature algorithm (suite id) for `client_pk`/`client_sig`.
        sig_alg: u16,
        /// Multi-suite offers + early data.
        payload: KemPayload,
    },
    /// 1-RTT second flight: KEM payload (for the negotiated suite) + first data.
    ClientData {
        /// Client verifying key (repeated so the frame is self-contained).
        client_pk: Vec<u8>,
        /// Signature algorithm (suite id) for `client_pk`/`client_sig`.
        sig_alg: u16,
        /// KEM payload + first data.
        payload: KemPayload,
    },
    /// Server hello carrying the accepted suite, KEM public key and cert.
    ServerHello {
        /// The cipher suite the server selected.
        accepted_suite: u16,
        /// KEM encapsulation (public) key for the accepted suite.
        server_pk: Vec<u8>,
        /// DER certificate chain binding `server_pk` (empty if none).
        certificate: Vec<u8>,
        /// The client source IP as observed by the server (NAT-safe ConnMeta).
        observed_ip: [u8; 16],
        /// Server timestamp in milliseconds.
        server_ts: u64,
    },
    /// 0-RTT acknowledgement: accepted suite + BLAKE3-512 of the derived key.
    ServerAck {
        /// The cipher suite the server adopted from the offers.
        accepted_suite: u16,
        /// Key-confirmation hash (`EK_HASH_LEN` bytes).
        ek_hash: [u8; EK_HASH_LEN],
    },
    /// Server refusal with a reason code (see [`reject`]).
    ServerReject {
        /// Reason code.
        reason: u8,
    },
    /// Half-RTT fallback: 0-RTT rejected (replay/window) but channel can be
    /// established. Server encapsulated to client's ephemeral KEM key.
    ServerRefuse0RTT {
        /// Accepted cipher suite.
        accepted_suite: u16,
        /// Server's KEM ciphertext (encapsulation to client_kem_pk).
        server_ct: Vec<u8>,
        /// Server-chosen nonce for key derivation.
        nonce: [u8; 32],
    },
    /// Application data record.
    DataRecord {
        /// `true` if sent by the server (s→c), `false` if by the client (c→s).
        from_server: bool,
        /// AEAD-sealed record (`ciphertext || tag`).
        ciphertext: Vec<u8>,
    },
    /// Orderly close.
    Close,
}

impl Frame {
    /// Encode this frame's body (type tag + fields) without the outer length
    /// prefix (see [`crate::frame`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        match self {
            Frame::ClientHelloOneRtt {
                client_pk,
                sig_alg,
                available_suites,
            } => {
                w.u8(FrameType::ClientHelloOneRtt as u8)
                    .bytes(client_pk)
                    .u16(*sig_alg);
                // Note: encoder does not validate bounds; decoder will reject invalid payloads.
                w.u16(available_suites.len() as u16);
                for s in available_suites {
                    w.u16(*s);
                }
            }
            Frame::ClientHelloZeroRtt {
                client_pk,
                client_kem_pk,
                sig_alg,
                payload,
            } => {
                w.u8(FrameType::ClientHelloZeroRtt as u8)
                    .bytes(client_pk)
                    .bytes(client_kem_pk)
                    .u16(*sig_alg);
                payload.write(&mut w);
            }
            Frame::ClientData {
                client_pk,
                sig_alg,
                payload,
            } => {
                w.u8(FrameType::ClientData as u8)
                    .bytes(client_pk)
                    .u16(*sig_alg);
                payload.write(&mut w);
            }
            Frame::ServerHello {
                accepted_suite,
                server_pk,
                certificate,
                observed_ip,
                server_ts,
            } => {
                w.u8(FrameType::ServerHello as u8)
                    .u16(*accepted_suite)
                    .bytes(server_pk)
                    .bytes(certificate)
                    .raw(observed_ip)
                    .u64(*server_ts);
            }
            Frame::ServerAck {
                accepted_suite,
                ek_hash,
            } => {
                w.u8(FrameType::ServerAck as u8)
                    .u16(*accepted_suite)
                    .raw(ek_hash);
            }
            Frame::ServerReject { reason } => {
                w.u8(FrameType::ServerReject as u8).u8(*reason);
            }
            Frame::ServerRefuse0RTT {
                accepted_suite,
                server_ct,
                nonce,
            } => {
                w.u8(FrameType::ServerRefuse0RTT as u8)
                    .u16(*accepted_suite)
                    .bytes(server_ct)
                    .raw(nonce);
            }
            Frame::DataRecord {
                from_server,
                ciphertext,
            } => {
                w.u8(FrameType::DataRecord as u8)
                    .u8(u8::from(*from_server))
                    .bytes(ciphertext);
            }
            Frame::Close => {
                w.u8(FrameType::Close as u8);
            }
        }
        w.into_bytes()
    }

    /// Decode a frame body (as produced by [`Frame::encode`]).
    pub fn decode(buf: &[u8]) -> Result<Frame, ProtoError> {
        let mut r = Reader::new(buf);
        let ty = FrameType::from_u8(r.u8()?)?;
        let frame = match ty {
            FrameType::ClientHelloOneRtt => {
                let client_pk = r.bytes()?.to_vec();
                let sig_alg = r.u16()?;
                let count = r.u16()? as usize;
                if count == 0 {
                    return Err(ProtoError::Empty("available suites"));
                }
                if count > MAX_SUITES {
                    return Err(ProtoError::TooMany("available suites"));
                }
                let mut available_suites = Vec::with_capacity(count);
                for _ in 0..count {
                    available_suites.push(r.u16()?);
                }
                Frame::ClientHelloOneRtt {
                    client_pk,
                    sig_alg,
                    available_suites,
                }
            }
            FrameType::ClientHelloZeroRtt => Frame::ClientHelloZeroRtt {
                client_pk: r.bytes()?.to_vec(),
                client_kem_pk: r.bytes()?.to_vec(),
                sig_alg: r.u16()?,
                payload: KemPayload::read(&mut r)?,
            },
            FrameType::ClientData => Frame::ClientData {
                client_pk: r.bytes()?.to_vec(),
                sig_alg: r.u16()?,
                payload: KemPayload::read(&mut r)?,
            },
            FrameType::ServerHello => Frame::ServerHello {
                accepted_suite: r.u16()?,
                server_pk: r.bytes()?.to_vec(),
                certificate: r.bytes()?.to_vec(),
                observed_ip: r.array::<16>()?,
                server_ts: r.u64()?,
            },
            FrameType::ServerAck => Frame::ServerAck {
                accepted_suite: r.u16()?,
                ek_hash: r.array::<EK_HASH_LEN>()?,
            },
            FrameType::ServerReject => Frame::ServerReject { reason: r.u8()? },
            FrameType::ServerRefuse0RTT => Frame::ServerRefuse0RTT {
                accepted_suite: r.u16()?,
                server_ct: r.bytes()?.to_vec(),
                nonce: r.array::<32>()?,
            },
            FrameType::DataRecord => {
                let from_server = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtoError::InvalidValue("data record direction")),
                };
                Frame::DataRecord {
                    from_server,
                    ciphertext: r.bytes()?.to_vec(),
                }
            }
            FrameType::Close => Frame::Close,
        };
        r.expect_end()?;
        Ok(frame)
    }
}
