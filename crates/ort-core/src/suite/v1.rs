//! v1 cipher suite: ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256 + BLAKE3.

use super::{CipherSuite, SuiteId, NONCE_LEN, R_LEN, SHARED_LEN};
use crate::{Error, Result};

use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce};

use hkdf::Hkdf;
use sha2::Sha256;

use ml_kem::kem::Decapsulate;
use ml_kem::{array::Array, B32, EncapsulationKey, KeyExport, KeyInit, MlKem768};
type MlKemDk = ml_kem::DecapsulationKey<MlKem768>;
type MlKemEk = EncapsulationKey<MlKem768>;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as DsaSig, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use ml_dsa::signature::Keypair;

/// FIPS 203 / 204 fixed sizes for the v1 suite.
const ML_KEM_768_EK: usize = 1184;
const ML_KEM_768_CT: usize = 1088;
const ML_DSA_65_VK: usize = 1952;
const ML_DSA_65_SIG: usize = 3309;

/// Zero-sized marker type implementing the v1 [`CipherSuite`].
pub struct V1;

/// Server KEM secret: holds the live ML-KEM decapsulation key.
pub struct KemSecret(MlKemDk);

/// Signing secret: holds the live ML-DSA signing key.
pub struct SigSecret(SigningKey<MlDsa65>);

// Best-effort hygiene: explicit no-op Zeroize so the types can flow through
// generic code expecting the trait. (Live PQ keys are not yet zeroized by the
// upstream crates without their `zeroize` feature — tracked as a hardening item.)
impl zeroize::Zeroize for KemSecret {
    fn zeroize(&mut self) {}
}
impl zeroize::Zeroize for SigSecret {
    fn zeroize(&mut self) {}
}

impl CipherSuite for V1 {
    const ID: SuiteId = SuiteId::V1MlKem768MlDsa65;
    const KEM_EK_LEN: usize = ML_KEM_768_EK;
    const KEM_CT_LEN: usize = ML_KEM_768_CT;
    const SIG_VK_LEN: usize = ML_DSA_65_VK;
    const SIG_LEN: usize = ML_DSA_65_SIG;

    type KemSecret = KemSecret;
    type SigSecret = SigSecret;

    // --- KEM ---------------------------------------------------------------

    fn kem_generate() -> Self::KemSecret {
        // A uniformly random 64-byte (d || z) seed is a valid ML-KEM private
        // key; reconstruct the decapsulation key from it via KeyInit.
        let mut seed = [0u8; 64];
        super::fill_random(&mut seed);
        Self::kem_secret_from_bytes(&seed).expect("64-byte seed is valid")
    }

    fn kem_secret_from_bytes(seed: &[u8]) -> Result<Self::KemSecret> {
        let key = ml_kem::Key::<MlKemDk>::try_from(seed).map_err(|_| Error::InvalidLength {
            what: "ml-kem decapsulation seed",
            expected: 64,
            got: seed.len(),
        })?;
        Ok(KemSecret(MlKemDk::new(&key)))
    }

    fn kem_secret_to_bytes(secret: &Self::KemSecret) -> Vec<u8> {
        secret.0.to_bytes().as_slice().to_vec()
    }

    fn kem_public(secret: &Self::KemSecret) -> Vec<u8> {
        secret.0.encapsulation_key().to_bytes().as_slice().to_vec()
    }

    fn kem_decapsulate(secret: &Self::KemSecret, ct: &[u8]) -> Result<[u8; SHARED_LEN]> {
        if ct.len() != ML_KEM_768_CT {
            return Err(Error::InvalidLength {
                what: "ml-kem ciphertext",
                expected: ML_KEM_768_CT,
                got: ct.len(),
            });
        }
        let shared = secret
            .0
            .decapsulate_slice(ct)
            .map_err(|_| Error::Malformed("ml-kem ciphertext"))?;
        let mut out = [0u8; SHARED_LEN];
        out.copy_from_slice(shared.as_slice());
        Ok(out)
    }

    fn kem_encapsulate(ek: &[u8], r: &[u8; R_LEN]) -> Result<(Vec<u8>, [u8; SHARED_LEN])> {
        let key = ml_kem::Key::<MlKemEk>::try_from(ek).map_err(|_| Error::InvalidLength {
            what: "ml-kem encapsulation key",
            expected: ML_KEM_768_EK,
            got: ek.len(),
        })?;
        let ek = MlKemEk::new(&key).map_err(|_| Error::Malformed("ml-kem encapsulation key"))?;
        let m: B32 = Array(*r);
        let (ct, shared) = ek.encapsulate_deterministic(&m);
        let mut out = [0u8; SHARED_LEN];
        out.copy_from_slice(shared.as_slice());
        Ok((ct.as_slice().to_vec(), out))
    }

    // --- Signatures --------------------------------------------------------

    fn sig_generate() -> Self::SigSecret {
        let mut seed = [0u8; 32];
        super::fill_random(&mut seed);
        SigSecret(SigningKey::<MlDsa65>::from_seed(&Array(seed)))
    }

    fn sig_secret_from_bytes(seed: &[u8]) -> Result<Self::SigSecret> {
        if seed.len() != 32 {
            return Err(Error::InvalidLength {
                what: "ml-dsa signing seed",
                expected: 32,
                got: seed.len(),
            });
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(seed);
        Ok(SigSecret(SigningKey::<MlDsa65>::from_seed(&Array(s))))
    }

    fn sig_secret_to_bytes(secret: &Self::SigSecret) -> Vec<u8> {
        secret.0.to_seed().as_slice().to_vec()
    }

    fn sig_public(secret: &Self::SigSecret) -> Vec<u8> {
        secret.0.verifying_key().encode().as_slice().to_vec()
    }

    fn sig_sign(secret: &Self::SigSecret, msg: &[u8]) -> Vec<u8> {
        secret.0.sign(msg).encode().as_slice().to_vec()
    }

    fn sig_verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
        let enc_vk =
            EncodedVerifyingKey::<MlDsa65>::try_from(vk).map_err(|_| Error::InvalidLength {
                what: "ml-dsa verifying key",
                expected: ML_DSA_65_VK,
                got: vk.len(),
            })?;
        let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
        let enc_sig =
            EncodedSignature::<MlDsa65>::try_from(sig).map_err(|_| Error::InvalidLength {
                what: "ml-dsa signature",
                expected: ML_DSA_65_SIG,
                got: sig.len(),
            })?;
        let sig = DsaSig::<MlDsa65>::decode(&enc_sig).ok_or(Error::BadSignature)?;
        vk.verify(msg, &sig).map_err(|_| Error::BadSignature)
    }

    // --- AEAD --------------------------------------------------------------

    fn aead_seal(key: &[u8; SHARED_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
        cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
            .expect("AES-256-GCM seal never fails for valid key/nonce")
    }

    fn aead_open(
        key: &[u8; SHARED_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| Error::AeadFailure)
    }

    // --- KDF & hash --------------------------------------------------------

    fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        hk.expand(info, out).expect("HKDF expand length within bounds");
    }

    fn hash256(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    fn hash512(data: &[u8]) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);
        out
    }
}
