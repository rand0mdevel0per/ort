//! Fixed symmetric primitives shared by every cipher suite: AES-256-GCM,
//! HKDF-SHA256 and BLAKE3. Suites differ only in their KEM and signature
//! algorithms (see [`crate::suite`]); the record layer and key schedule are
//! suite-independent, which keeps the established session uniform regardless of
//! which suite was negotiated.

use crate::{Error, Result};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// AEAD key length (AES-256).
pub const AEAD_KEY_LEN: usize = 32;
/// AEAD nonce length (96-bit GCM nonce).
pub const NONCE_LEN: usize = 12;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;

/// Seal `pt` with AES-256-GCM, returning `ciphertext || tag`.
pub fn aead_seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .expect("AES-256-GCM seal never fails for a valid key/nonce")
}

/// Open an AES-256-GCM `ciphertext || tag`.
pub fn aead_open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::AeadFailure)
}

/// HKDF-SHA256 Extract+Expand into `out`.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out)
        .expect("HKDF expand length within bounds");
}

/// BLAKE3 256-bit hash.
pub fn hash256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// BLAKE3 512-bit (XOF-extended) hash.
pub fn hash512(data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}
