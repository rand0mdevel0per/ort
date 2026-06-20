//! Runtime suite agility: enums that hold a concrete suite's secret and
//! byte-level dispatchers keyed by [`SuiteId`]. This lets the (non-generic)
//! handshake and the networking layer select a suite at runtime — the client's
//! signature identity is decoupled from the negotiated KEM suite, so a single
//! signed ClientHello can offer KEM encapsulations for several suites at once.

use crate::suite::classical::V2;
use crate::suite::v1::V1;
use crate::suite::{CipherSuite, SuiteId, R_LEN, SHARED_LEN};
use crate::{Error, Result};

/// A server-side KEM secret for one concrete suite.
pub enum ServerKemKey {
    /// ML-KEM-768.
    V1(<V1 as CipherSuite>::KemSecret),
    /// DHKEM(X25519).
    V2(<V2 as CipherSuite>::KemSecret),
}

impl ServerKemKey {
    /// Generate a fresh KEM key for `id`.
    pub fn generate(id: SuiteId) -> Self {
        match id {
            SuiteId::V1MlKem768MlDsa65 => ServerKemKey::V1(V1::kem_generate()),
            SuiteId::V2X25519Ed25519 => ServerKemKey::V2(V2::kem_generate()),
        }
    }
    /// Reconstruct a KEM key for `id` from its seed bytes.
    pub fn from_seed(id: SuiteId, seed: &[u8]) -> Result<Self> {
        Ok(match id {
            SuiteId::V1MlKem768MlDsa65 => ServerKemKey::V1(V1::kem_secret_from_bytes(seed)?),
            SuiteId::V2X25519Ed25519 => ServerKemKey::V2(V2::kem_secret_from_bytes(seed)?),
        })
    }
    /// Serialize the KEM secret to seed bytes.
    pub fn to_seed(&self) -> Vec<u8> {
        match self {
            ServerKemKey::V1(k) => V1::kem_secret_to_bytes(k),
            ServerKemKey::V2(k) => V2::kem_secret_to_bytes(k),
        }
    }
    /// The suite id of this key.
    pub fn suite_id(&self) -> SuiteId {
        match self {
            ServerKemKey::V1(_) => SuiteId::V1MlKem768MlDsa65,
            ServerKemKey::V2(_) => SuiteId::V2X25519Ed25519,
        }
    }
    /// Encoded KEM public key bytes.
    pub fn public(&self) -> Vec<u8> {
        match self {
            ServerKemKey::V1(k) => V1::kem_public(k),
            ServerKemKey::V2(k) => V2::kem_public(k),
        }
    }
    /// Decapsulate a ciphertext to the shared secret.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<[u8; SHARED_LEN]> {
        match self {
            ServerKemKey::V1(k) => V1::kem_decapsulate(k, ct),
            ServerKemKey::V2(k) => V2::kem_decapsulate(k, ct),
        }
    }
}

/// A client signing identity for one concrete suite.
pub enum SigIdentity {
    /// ML-DSA-65.
    V1(<V1 as CipherSuite>::SigSecret),
    /// Ed25519.
    V2(<V2 as CipherSuite>::SigSecret),
}

impl SigIdentity {
    /// Generate a fresh signing identity for `id`.
    pub fn generate(id: SuiteId) -> Self {
        match id {
            SuiteId::V1MlKem768MlDsa65 => SigIdentity::V1(V1::sig_generate()),
            SuiteId::V2X25519Ed25519 => SigIdentity::V2(V2::sig_generate()),
        }
    }
    /// Reconstruct a signing identity for `id` from its seed bytes.
    pub fn from_seed(id: SuiteId, seed: &[u8]) -> Result<Self> {
        Ok(match id {
            SuiteId::V1MlKem768MlDsa65 => SigIdentity::V1(V1::sig_secret_from_bytes(seed)?),
            SuiteId::V2X25519Ed25519 => SigIdentity::V2(V2::sig_secret_from_bytes(seed)?),
        })
    }
    /// Serialize the signing secret to seed bytes.
    pub fn to_seed(&self) -> Vec<u8> {
        match self {
            SigIdentity::V1(k) => V1::sig_secret_to_bytes(k),
            SigIdentity::V2(k) => V2::sig_secret_to_bytes(k),
        }
    }
    /// The suite id whose signature algorithm this identity uses.
    pub fn suite_id(&self) -> SuiteId {
        match self {
            SigIdentity::V1(_) => SuiteId::V1MlKem768MlDsa65,
            SigIdentity::V2(_) => SuiteId::V2X25519Ed25519,
        }
    }
    /// Encoded verifying (public) key bytes.
    pub fn public(&self) -> Vec<u8> {
        match self {
            SigIdentity::V1(k) => V1::sig_public(k),
            SigIdentity::V2(k) => V2::sig_public(k),
        }
    }
    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SigIdentity::V1(k) => V1::sig_sign(k, msg),
            SigIdentity::V2(k) => V2::sig_sign(k, msg),
        }
    }
}

/// Deterministic KEM encapsulation against `ek` for suite `id`.
pub fn kem_encapsulate(
    id: SuiteId,
    ek: &[u8],
    r: &[u8; R_LEN],
) -> Result<(Vec<u8>, [u8; SHARED_LEN])> {
    match id {
        SuiteId::V1MlKem768MlDsa65 => V1::kem_encapsulate(ek, r),
        SuiteId::V2X25519Ed25519 => V2::kem_encapsulate(ek, r),
    }
}

/// Verify a signature under suite `id`'s signature algorithm.
pub fn sig_verify(id: SuiteId, vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    match id {
        SuiteId::V1MlKem768MlDsa65 => V1::sig_verify(vk, msg, sig),
        SuiteId::V2X25519Ed25519 => V2::sig_verify(vk, msg, sig),
    }
}

/// Decode a wire suite id or error with [`Error::UnsupportedSuite`].
pub fn suite_from_code(code: u16) -> Result<SuiteId> {
    SuiteId::from_code(code).ok_or(Error::UnsupportedSuite(code))
}
