//! v2 classical cipher suite using audited primitives: DHKEM(X25519) as the KEM
//! together with Ed25519 signatures (and the shared AES-256-GCM / HKDF-SHA256 /
//! BLAKE3 record primitives). Offered alongside the post-quantum v1 suite for
//! deployments that prefer independently audited cryptography.

use super::{CipherSuite, SuiteId, R_LEN, SHARED_LEN};
use crate::prim;
use crate::{Error, Result};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Domain-separation label for the DHKEM key schedule.
const DHKEM_LABEL: &[u8] = b"ORT-dhkem-x25519-v1";

const X25519_LEN: usize = 32;
const ED25519_VK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

/// Zero-sized marker type implementing the v2 [`CipherSuite`].
pub struct Ecdh;

/// Server KEM secret: an X25519 static secret (zeroized on drop by dalek).
pub struct KemSecret(StaticSecret);

/// Signing secret: an Ed25519 signing key (zeroized on drop by dalek).
pub struct SigSecret(SigningKey);

fn arr32(b: &[u8], what: &'static str) -> Result<[u8; 32]> {
    if b.len() != 32 {
        return Err(Error::InvalidLength {
            what,
            expected: 32,
            got: b.len(),
        });
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    Ok(a)
}

/// DHKEM shared-secret derivation: HKDF over the DH output, binding both the
/// ephemeral and static public keys (HPKE-style). The suite label is used as
/// the HKDF salt (rather than an empty salt) for an extra domain-separation /
/// security margin.
fn dhkem_shared(dh: &[u8; 32], eph_pk: &[u8; 32], server_pk: &[u8; 32]) -> [u8; SHARED_LEN] {
    let mut info = Vec::with_capacity(DHKEM_LABEL.len() + 64);
    info.extend_from_slice(DHKEM_LABEL);
    info.extend_from_slice(eph_pk);
    info.extend_from_slice(server_pk);
    let mut out = [0u8; SHARED_LEN];
    prim::hkdf(dh, DHKEM_LABEL, &info, &mut out);
    out
}

impl CipherSuite for Ecdh {
    const ID: SuiteId = SuiteId::X25519Ed25519;
    const KEM_EK_LEN: usize = X25519_LEN;
    const KEM_CT_LEN: usize = X25519_LEN; // ciphertext == ephemeral public key
    const SIG_VK_LEN: usize = ED25519_VK_LEN;
    const SIG_LEN: usize = ED25519_SIG_LEN;

    type KemSecret = KemSecret;
    type SigSecret = SigSecret;

    // --- KEM (DHKEM/X25519) -----------------------------------------------

    fn kem_generate() -> Self::KemSecret {
        let mut seed = [0u8; 32];
        super::fill_random(&mut seed).expect("OS RNG");
        let secret = KemSecret(StaticSecret::from(seed));
        seed.zeroize();
        secret
    }

    fn kem_secret_from_bytes(seed: &[u8]) -> Result<Self::KemSecret> {
        Ok(KemSecret(StaticSecret::from(arr32(seed, "x25519 secret")?)))
    }

    fn kem_secret_to_bytes(secret: &Self::KemSecret) -> Vec<u8> {
        secret.0.to_bytes().to_vec()
    }

    fn kem_public(secret: &Self::KemSecret) -> Vec<u8> {
        PublicKey::from(&secret.0).to_bytes().to_vec()
    }

    fn kem_decapsulate(secret: &Self::KemSecret, ct: &[u8]) -> Result<[u8; SHARED_LEN]> {
        let eph_pk = arr32(ct, "x25519 ciphertext")?;
        let dh = secret.0.diffie_hellman(&PublicKey::from(eph_pk));
        let server_pk = PublicKey::from(&secret.0).to_bytes();
        Ok(dhkem_shared(dh.as_bytes(), &eph_pk, &server_pk))
    }

    fn kem_encapsulate(ek: &[u8], r: &[u8; R_LEN]) -> Result<(Vec<u8>, [u8; SHARED_LEN])> {
        let server_pk_bytes = arr32(ek, "x25519 encapsulation key")?;
        let server_pub = PublicKey::from(server_pk_bytes);
        // The encapsulation seed `r` is the ephemeral scalar.
        let eph_sk = StaticSecret::from(*r);
        let eph_pk = PublicKey::from(&eph_sk).to_bytes();
        let dh = eph_sk.diffie_hellman(&server_pub);
        let shared = dhkem_shared(dh.as_bytes(), &eph_pk, &server_pk_bytes);
        Ok((eph_pk.to_vec(), shared))
    }

    // --- Signatures (Ed25519) ---------------------------------------------

    fn sig_generate() -> Self::SigSecret {
        let mut seed = [0u8; 32];
        super::fill_random(&mut seed).expect("OS RNG");
        let secret = SigSecret(SigningKey::from_bytes(&seed));
        seed.zeroize();
        secret
    }

    fn sig_secret_from_bytes(seed: &[u8]) -> Result<Self::SigSecret> {
        Ok(SigSecret(SigningKey::from_bytes(&arr32(
            seed,
            "ed25519 seed",
        )?)))
    }

    fn sig_secret_to_bytes(secret: &Self::SigSecret) -> Vec<u8> {
        secret.0.to_bytes().to_vec()
    }

    fn sig_public(secret: &Self::SigSecret) -> Vec<u8> {
        secret.0.verifying_key().to_bytes().to_vec()
    }

    fn sig_sign(secret: &Self::SigSecret, msg: &[u8]) -> Vec<u8> {
        secret.0.sign(msg).to_bytes().to_vec()
    }

    fn sig_verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&arr32(vk, "ed25519 verifying key")?)
            .map_err(|_| Error::Malformed("ed25519 verifying key"))?;
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| Error::InvalidLength {
            what: "ed25519 signature",
            expected: 64,
            got: sig.len(),
        })?;
        let signature = Signature::from_bytes(&sig_bytes);
        vk.verify(msg, &signature).map_err(|_| Error::BadSignature)
    }
}
