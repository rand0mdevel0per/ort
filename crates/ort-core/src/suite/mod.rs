//! Cipher-suite abstraction (the crypto-agility seam).
//!
//! Every primitive the protocol needs is exposed through [`CipherSuite`] using
//! byte-oriented signatures so the handshake/record code never touches a
//! concrete crypto crate's generic types. v1 ([`v1::V1`]) binds:
//! ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256 + BLAKE3.
//!
//! Key agreement is a **KEM** (not a NIKE): the client picks a fresh 32-byte
//! seed `r`, runs deterministic encapsulation against the server's public key
//! to get `(ciphertext, shared)` locally, and the server recovers the same
//! `shared` by decapsulating `ciphertext` with its secret key. Because `r` is
//! fresh per connection, every session has an independent shared secret.

pub mod ids;
pub mod v1;

pub use ids::SuiteId;

use crate::Result;

/// Length in bytes of the KEM shared secret / AEAD key (32 for v1).
pub const SHARED_LEN: usize = 32;
/// AEAD nonce length in bytes (96-bit GCM nonce).
pub const NONCE_LEN: usize = 12;
/// AEAD authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Length of the encapsulation seed `r` (= "shrand").
pub const R_LEN: usize = 32;

/// The full set of primitives for one protocol version, exposed over bytes.
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
    /// Decapsulate a ciphertext, recovering the shared secret. Uses ML-KEM
    /// implicit rejection, so a malformed/forged ct yields a pseudo-random
    /// secret rather than an error (the AEAD open will then fail).
    fn kem_decapsulate(secret: &Self::KemSecret, ct: &[u8]) -> Result<[u8; SHARED_LEN]>;
    /// Deterministic encapsulation against an encoded public key using seed
    /// `r`. Returns `(ciphertext, shared)`.
    fn kem_encapsulate(ek: &[u8], r: &[u8; R_LEN]) -> Result<(Vec<u8>, [u8; SHARED_LEN])>;

    // --- Signatures --------------------------------------------------------

    /// Generate a fresh signing secret using the OS RNG.
    fn sig_generate() -> Self::SigSecret;
    /// Reconstruct a signing secret from its 32-byte seed.
    fn sig_secret_from_bytes(seed: &[u8]) -> Result<Self::SigSecret>;
    /// Serialize a signing secret to its 32-byte seed.
    fn sig_secret_to_bytes(secret: &Self::SigSecret) -> Vec<u8>;
    /// Verifying (public) key bytes for this signing secret.
    fn sig_public(secret: &Self::SigSecret) -> Vec<u8>;
    /// Sign a message.
    fn sig_sign(secret: &Self::SigSecret, msg: &[u8]) -> Vec<u8>;
    /// Verify a signature against an encoded verifying key.
    fn sig_verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;

    // --- AEAD --------------------------------------------------------------

    /// Seal `pt` with associated data `aad`. Returns `ciphertext || tag`.
    fn aead_seal(key: &[u8; SHARED_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Vec<u8>;
    /// Open `ct` (== `ciphertext || tag`); fails authentication on tamper.
    fn aead_open(
        key: &[u8; SHARED_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>>;

    // --- KDF & hash --------------------------------------------------------

    /// HKDF-Extract+Expand into `out`.
    fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]);
    /// 256-bit hash.
    fn hash256(data: &[u8]) -> [u8; 32];
    /// 512-bit hash (XOF-extended).
    fn hash512(data: &[u8]) -> [u8; 64];
}

/// Fill a buffer with cryptographically secure random bytes from the OS.
pub fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS RNG failure");
}

/// Generate a fresh 32-byte encapsulation seed `r` ("shrand").
pub fn fresh_r() -> [u8; R_LEN] {
    let mut r = [0u8; R_LEN];
    fill_random(&mut r);
    r
}
