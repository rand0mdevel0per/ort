//! Cipher-suite abstraction (the crypto-agility seam).
//!
//! Every primitive the protocol needs is exposed through [`CipherSuite`] using
//! byte-oriented signatures so the handshake/record code never touches a
//! concrete crypto crate's generic types. PQC ([`pqc::Pqc`]) binds:
//! ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256 + BLAKE3.
//!
//! Key agreement is a **KEM** (not a NIKE): the client picks a fresh 32-byte
//! seed `r`, runs deterministic encapsulation against the server's public key
//! to get `(ciphertext, shared)` locally, and the server recovers the same
//! `shared` by decapsulating `ciphertext` with its secret key. Because `r` is
//! fresh per connection, every session has an independent shared secret.

pub mod agile;
pub mod ecdh;
pub mod ids;
pub mod pqc;

pub use ids::SuiteId;

use crate::Result;

/// Length in bytes of the KEM shared secret / AEAD key (32).
pub const SHARED_LEN: usize = 32;
/// Length of the encapsulation seed `r`.
pub const R_LEN: usize = 32;

/// A cipher suite's asymmetric primitives (KEM + signature), exposed over
/// bytes. The symmetric primitives (AEAD/KDF/hash) are fixed for all suites and
/// live in [`crate::prim`], so an established session is suite-independent.
pub trait CipherSuite {
    /// On-wire identifier negotiated in ClientHello.
    const ID: SuiteId;

    /// Encoded length of a KEM encapsulation (public) key.
    const KEM_EK_LEN: usize;
    /// Encoded length of a KEM ciphertext.
    const KEM_CT_LEN: usize;
    /// Encoded length of a signature verifying (public) key.
    const SIG_VK_LEN: usize;
    /// Encoded length of a signature.
    const SIG_LEN: usize;

    /// Server-side KEM secret (decapsulation key). Stored seed bytes are
    /// wrapped in `Zeroizing` at the CLI/storage layer.
    type KemSecret;
    /// Signing secret (client or cert key).
    type SigSecret;

    // --- KEM ---------------------------------------------------------------

    /// Generate a fresh KEM keypair using the OS RNG.
    fn kem_generate() -> Self::KemSecret;
    /// Reconstruct a KEM secret from its serialized seed form.
    fn kem_secret_from_bytes(seed: &[u8]) -> Result<Self::KemSecret>;
    /// Serialize a KEM secret to its compact seed form (for at-rest storage).
    fn kem_secret_to_bytes(secret: &Self::KemSecret) -> Vec<u8>;
    /// Encapsulation (public) key bytes for this secret.
    fn kem_public(secret: &Self::KemSecret) -> Vec<u8>;
    /// Decapsulate a ciphertext, recovering the shared secret. A
    /// malformed/forged ct yields a pseudo-random secret rather than an error
    /// (the AEAD open then fails), preserving implicit-rejection semantics.
    fn kem_decapsulate(secret: &Self::KemSecret, ct: &[u8]) -> Result<[u8; SHARED_LEN]>;
    /// Deterministic encapsulation against an encoded public key using seed
    /// `r`. Returns `(ciphertext, shared)`.
    fn kem_encapsulate(ek: &[u8], r: &[u8; R_LEN]) -> Result<(Vec<u8>, [u8; SHARED_LEN])>;

    // --- Signatures --------------------------------------------------------

    /// Generate a fresh signing secret using the OS RNG.
    fn sig_generate() -> Self::SigSecret;
    /// Reconstruct a signing secret from its seed.
    fn sig_secret_from_bytes(seed: &[u8]) -> Result<Self::SigSecret>;
    /// Serialize a signing secret to its seed.
    fn sig_secret_to_bytes(secret: &Self::SigSecret) -> Vec<u8>;
    /// Verifying (public) key bytes for this signing secret.
    fn sig_public(secret: &Self::SigSecret) -> Vec<u8>;
    /// Sign a message.
    fn sig_sign(secret: &Self::SigSecret, msg: &[u8]) -> Vec<u8>;
    /// Verify a signature against an encoded verifying key.
    fn sig_verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
}

/// Fill a buffer with cryptographically secure random bytes from the OS.
/// Returns an error (rather than panicking) if the OS RNG fails, so callers on
/// the per-connection path can reject instead of crashing.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| crate::Error::RngFailure)
}

/// Generate a fresh 32-byte encapsulation seed `r`.
pub fn fresh_r() -> Result<[u8; R_LEN]> {
    let mut r = [0u8; R_LEN];
    fill_random(&mut r)?;
    Ok(r)
}
