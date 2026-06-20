//! v1 cipher suite: ML-KEM-768 + ML-DSA-65 + AES-256-GCM + HKDF-SHA256 + BLAKE3.

use super::{CipherSuite, SuiteId, R_LEN, SHARED_LEN};
use crate::{Error, Result};
use zeroize::Zeroizing;

use ml_kem::kem::Decapsulate;
use ml_kem::{array::Array, EncapsulationKey, KeyExport, KeyInit, MlKem768, B32};
type MlKemDk = ml_kem::DecapsulationKey<MlKem768>;
type MlKemEk = EncapsulationKey<MlKem768>;

use ml_dsa::signature::Keypair;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as DsaSig, Signer, SigningKey,
    Verifier, VerifyingKey,
};

/// FIPS 203 / 204 fixed sizes for the v1 suite.
const ML_KEM_768_EK: usize = 1184;
const ML_KEM_768_CT: usize = 1088;
const ML_KEM_768_SEED: usize = 64;
const ML_DSA_65_VK: usize = 1952;
const ML_DSA_65_SIG: usize = 3309;
const ML_DSA_65_SEED: usize = 32;

/// Zero-sized marker type implementing the v1 [`CipherSuite`].
pub struct V1;

/// Server KEM secret. Stored as its zeroizing `(d || z)` seed; the live
/// decapsulation key is reconstructed per operation so the long-term secret is
/// wiped on drop.
pub struct KemSecret(Zeroizing<Vec<u8>>);

/// Signing secret. Stored as its zeroizing 32-byte seed.
pub struct SigSecret(Zeroizing<Vec<u8>>);

impl KemSecret {
    fn dk(&self) -> Result<MlKemDk> {
        let key =
            ml_kem::Key::<MlKemDk>::try_from(&self.0[..]).map_err(|_| Error::InvalidLength {
                what: "ml-kem decapsulation seed",
                expected: ML_KEM_768_SEED,
                got: self.0.len(),
            })?;
        Ok(MlKemDk::new(&key))
    }
}

impl SigSecret {
    fn sk(&self) -> SigningKey<MlDsa65> {
        let mut seed = [0u8; ML_DSA_65_SEED];
        seed.copy_from_slice(&self.0);
        SigningKey::<MlDsa65>::from_seed(&Array(seed))
    }
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
        // A uniformly random 64-byte (d || z) seed is a valid ML-KEM private key.
        let mut seed = vec![0u8; ML_KEM_768_SEED];
        super::fill_random(&mut seed).expect("OS RNG at key generation");
        KemSecret(Zeroizing::new(seed))
    }

    fn kem_secret_from_bytes(seed: &[u8]) -> Result<Self::KemSecret> {
        if seed.len() != ML_KEM_768_SEED {
            return Err(Error::InvalidLength {
                what: "ml-kem decapsulation seed",
                expected: ML_KEM_768_SEED,
                got: seed.len(),
            });
        }
        let secret = KemSecret(Zeroizing::new(seed.to_vec()));
        secret.dk()?; // validate the seed decodes
        Ok(secret)
    }

    fn kem_secret_to_bytes(secret: &Self::KemSecret) -> Vec<u8> {
        secret.0.to_vec()
    }

    fn kem_public(secret: &Self::KemSecret) -> Vec<u8> {
        secret
            .dk()
            .expect("validated seed")
            .encapsulation_key()
            .to_bytes()
            .as_slice()
            .to_vec()
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
            .dk()?
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
        let mut seed = vec![0u8; ML_DSA_65_SEED];
        super::fill_random(&mut seed).expect("OS RNG at key generation");
        SigSecret(Zeroizing::new(seed))
    }

    fn sig_secret_from_bytes(seed: &[u8]) -> Result<Self::SigSecret> {
        if seed.len() != ML_DSA_65_SEED {
            return Err(Error::InvalidLength {
                what: "ml-dsa signing seed",
                expected: ML_DSA_65_SEED,
                got: seed.len(),
            });
        }
        Ok(SigSecret(Zeroizing::new(seed.to_vec())))
    }

    fn sig_secret_to_bytes(secret: &Self::SigSecret) -> Vec<u8> {
        secret.0.to_vec()
    }

    fn sig_public(secret: &Self::SigSecret) -> Vec<u8> {
        secret.sk().verifying_key().encode().as_slice().to_vec()
    }

    fn sig_sign(secret: &Self::SigSecret, msg: &[u8]) -> Vec<u8> {
        secret.sk().sign(msg).encode().as_slice().to_vec()
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
}
