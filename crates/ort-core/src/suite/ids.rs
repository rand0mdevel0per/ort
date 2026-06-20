//! On-wire cipher-suite identifiers.

/// A 16-bit cipher-suite identifier sent in ClientHello/ServerHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SuiteId {
    /// Post-quantum: ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256 + BLAKE3.
    V1MlKem768MlDsa65 = 0x0001,
    /// Classical (audited primitives): DHKEM(X25519) + Ed25519 + AES-256-GCM +
    /// HKDF-SHA256 + BLAKE3.
    V2X25519Ed25519 = 0x0002,
}

impl SuiteId {
    /// The raw u16 wire code.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Decode a wire code into a known suite, or `None` if unsupported.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(SuiteId::V1MlKem768MlDsa65),
            0x0002 => Some(SuiteId::V2X25519Ed25519),
            _ => None,
        }
    }
}
