//! ORT frame message types and their binary encoding.

use crate::codec::{Reader, Writer};
use crate::ProtoError;

/// Frame type tags (first byte of every frame body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// First flight, 1-RTT mode: just requests the server cert + public key.
    ClientHelloOneRtt = 0x01,
    /// First flight, 0-RTT mode: full KEM payload + early data.
    ClientHelloZeroRtt = 0x02,
    /// Second flight in 1-RTT mode: the KEM payload + first data.
    ClientData = 0x03,
    /// Server response carrying its public key + certificate.
    ServerHello = 0x04,
    /// Server 0-RTT acknowledgement carrying the key-confirmation hash.
    ServerAck = 0x05,
    /// An AEAD-protected application data record.
    DataRecord = 0x06,
    /// Orderly shutdown.
    Close = 0x07,
}

impl FrameType {
    fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0x01 => FrameType::ClientHelloOneRtt,
            0x02 => FrameType::ClientHelloZeroRtt,
            0x03 => FrameType::ClientData,
            0x04 => FrameType::ServerHello,
            0x05 => FrameType::ServerAck,
            0x06 => FrameType::DataRecord,
            0x07 => FrameType::Close,
            other => return Err(ProtoError::UnknownFrameType(other)),
        })
    }
}

/// The KEM-bearing payload sent by the client (in 0-RTT ClientHello or the
/// 1-RTT second flight). Carries everything the server needs to derive keys,
/// authenticate the handshake and decrypt the first data block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemPayload {
    /// ML-KEM ciphertext (encapsulation against the server public key).
    pub ciphertext: Vec<u8>,
    /// Client source IP (16 bytes, IPv6 or IPv4-mapped).
    pub src_ip: [u8; 16],
    /// Client timestamp in milliseconds since the Unix epoch.
    pub ts_millis: u64,
    /// Fresh per-connection nonce.
    pub nonce: [u8; 32],
    /// ML-DSA signature over the client binding string.
    pub client_sig: Vec<u8>,
    /// AEAD-sealed early data (`ciphertext || tag`). The nonce is derived from
    /// the entropy pool (counter 0, c→s) on both peers, so it is not transmitted.
    pub enc_data: Vec<u8>,
}

impl KemPayload {
    fn write(&self, w: &mut Writer) {
        w.bytes16(&self.ciphertext)
            .raw(&self.src_ip)
            .u64(self.ts_millis)
            .raw(&self.nonce)
            .bytes16(&self.client_sig)
            .bytes32(&self.enc_data);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        Ok(KemPayload {
            ciphertext: r.bytes16()?.to_vec(),
            src_ip: r.array::<16>()?,
            ts_millis: r.u64()?,
            nonce: r.array::<32>()?,
            client_sig: r.bytes16()?.to_vec(),
            enc_data: r.bytes32()?.to_vec(),
        })
    }
}

/// A decoded ORT protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// 1-RTT ClientHello: negotiate suite, present client verifying key.
    ClientHelloOneRtt {
        /// Negotiated cipher-suite id.
        suite_id: u16,
        /// Client ML-DSA verifying key.
        client_pk: Vec<u8>,
    },
    /// 0-RTT ClientHello: suite + client key + full KEM payload.
    ClientHelloZeroRtt {
        /// Negotiated cipher-suite id.
        suite_id: u16,
        /// Client ML-DSA verifying key.
        client_pk: Vec<u8>,
        /// KEM payload and early data.
        payload: KemPayload,
    },
    /// 1-RTT second flight: KEM payload + first data.
    ClientData {
        /// Client ML-DSA verifying key (repeated so the frame is self-contained).
        client_pk: Vec<u8>,
        /// KEM payload and first data.
        payload: KemPayload,
    },
    /// Server hello carrying the KEM public key and (optional) certificate.
    ServerHello {
        /// Negotiated cipher-suite id.
        suite_id: u16,
        /// ML-KEM encapsulation (public) key.
        server_pk: Vec<u8>,
        /// DER certificate chain binding `server_pk` (empty if none).
        certificate: Vec<u8>,
        /// Server timestamp in milliseconds.
        server_ts: u64,
    },
    /// 0-RTT acknowledgement: BLAKE3-512 of the derived enc key.
    ServerAck {
        /// Key-confirmation hash.
        ek_hash: Vec<u8>,
    },
    /// Application data record.
    DataRecord {
        /// Direction tag (0 = c→s, 1 = s→c).
        dir: u8,
        /// AEAD-sealed record (`ciphertext || tag`).
        ciphertext: Vec<u8>,
    },
    /// Orderly close.
    Close,
}

impl Frame {
    /// Encode this frame's body (type tag + fields) — without the outer length
    /// prefix (see [`crate::frame`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        match self {
            Frame::ClientHelloOneRtt { suite_id, client_pk } => {
                w.u8(FrameType::ClientHelloOneRtt as u8)
                    .u16(*suite_id)
                    .bytes16(client_pk);
            }
            Frame::ClientHelloZeroRtt {
                suite_id,
                client_pk,
                payload,
            } => {
                w.u8(FrameType::ClientHelloZeroRtt as u8)
                    .u16(*suite_id)
                    .bytes16(client_pk);
                payload.write(&mut w);
            }
            Frame::ClientData { client_pk, payload } => {
                w.u8(FrameType::ClientData as u8).bytes16(client_pk);
                payload.write(&mut w);
            }
            Frame::ServerHello {
                suite_id,
                server_pk,
                certificate,
                server_ts,
            } => {
                w.u8(FrameType::ServerHello as u8)
                    .u16(*suite_id)
                    .bytes16(server_pk)
                    .bytes32(certificate)
                    .u64(*server_ts);
            }
            Frame::ServerAck { ek_hash } => {
                w.u8(FrameType::ServerAck as u8).bytes16(ek_hash);
            }
            Frame::DataRecord { dir, ciphertext } => {
                w.u8(FrameType::DataRecord as u8).u8(*dir).bytes32(ciphertext);
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
            FrameType::ClientHelloOneRtt => Frame::ClientHelloOneRtt {
                suite_id: r.u16()?,
                client_pk: r.bytes16()?.to_vec(),
            },
            FrameType::ClientHelloZeroRtt => Frame::ClientHelloZeroRtt {
                suite_id: r.u16()?,
                client_pk: r.bytes16()?.to_vec(),
                payload: KemPayload::read(&mut r)?,
            },
            FrameType::ClientData => Frame::ClientData {
                client_pk: r.bytes16()?.to_vec(),
                payload: KemPayload::read(&mut r)?,
            },
            FrameType::ServerHello => Frame::ServerHello {
                suite_id: r.u16()?,
                server_pk: r.bytes16()?.to_vec(),
                certificate: r.bytes32()?.to_vec(),
                server_ts: r.u64()?,
            },
            FrameType::ServerAck => Frame::ServerAck {
                ek_hash: r.bytes16()?.to_vec(),
            },
            FrameType::DataRecord => Frame::DataRecord {
                dir: r.u8()?,
                ciphertext: r.bytes32()?.to_vec(),
            },
            FrameType::Close => Frame::Close,
        };
        r.expect_end()?;
        Ok(frame)
    }
}
