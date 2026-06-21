//! On-wire cipher-suite identifiers and their formal names.

/// A 16-bit cipher-suite identifier sent in ClientHello/ServerHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SuiteId {
    /// Post-quantum: ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256 + BLAKE3.
    MlKem768MlDsa65 = 0x0001,
    /// Classical (audited primitives): DHKEM(X25519) + Ed25519 + AES-256-GCM +
    /// HKDF-SHA256 + BLAKE3.
    X25519Ed25519 = 0x0002,
}

impl SuiteId {
    /// The raw u16 wire code.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Decode a wire code into a known suite, or `None` if unsupported.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(SuiteId::MlKem768MlDsa65),
            0x0002 => Some(SuiteId::X25519Ed25519),
            _ => None,
        }
    }

    /// Formal suite name (for display, CLI and documentation).
    pub fn name(self) -> &'static str {
        match self {
            SuiteId::MlKem768MlDsa65 => "PQC-MLKEM768-MLDSA65",
            SuiteId::X25519Ed25519 => "ECDH-X25519-ED25519",
        }
    }

    /// Parse a suite from its formal name or a short alias (`pqc`/`ecdh`),
    /// case-insensitively.
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pqc" | "pqc-mlkem768-mldsa65" => Some(SuiteId::MlKem768MlDsa65),
            "ecdh" | "ecdh-x25519-ed25519" => Some(SuiteId::X25519Ed25519),
            _ => None,
        }
    }
}

impl core::fmt::Display for SuiteId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}
