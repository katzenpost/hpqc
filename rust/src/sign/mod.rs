//! Signatures.

pub mod ed25519;
pub mod hybrid;
pub mod mldsa;
pub mod schemes;

use std::any::Any;
use std::fmt::Debug;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::{Result, SecretBytes};

pub trait PublicKey: Any + Debug + Send + Sync {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait PrivateKey: Any + Debug + Send + Sync {
    fn to_bytes(&self) -> SecretBytes;

    fn public_key(&self) -> Box<dyn PublicKey>;
}

pub trait Scheme: Send + Sync {
    fn name(&self) -> &str;

    fn public_key_size(&self) -> usize;

    fn private_key_size(&self) -> usize;

    fn signature_size(&self) -> usize;

    fn seed_size(&self) -> usize;

    fn generate_key(&self, rng: &mut dyn CryptoRng) -> Box<dyn PrivateKey> {
        let mut seed = Zeroizing::new(vec![0; self.seed_size()]);
        rng.fill_bytes(&mut seed);
        self.derive_key(&seed).expect("seed has the right length")
    }

    /// Derives a key deterministically from `seed_size` bytes.
    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn PrivateKey>>;

    /// Signs `message`. Deterministic schemes ignore `rng`.
    fn sign(
        &self,
        private_key: &dyn PrivateKey,
        message: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>>;

    fn verify(&self, public_key: &dyn PublicKey, message: &[u8], signature: &[u8]) -> Result<()>;

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn PublicKey>>;

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn PrivateKey>>;
}

#[cfg(test)]
pub(crate) fn check_scheme(scheme: &dyn Scheme) {
    use crate::Error;

    let rng = &mut crate::util::rng();
    let sk = scheme.generate_key(rng);
    let pk = sk.public_key();
    assert_eq!(pk.to_bytes().len(), scheme.public_key_size());
    assert_eq!(sk.to_bytes().len(), scheme.private_key_size());

    let sig = scheme.sign(&*sk, b"message", rng).unwrap();
    assert_eq!(sig.len(), scheme.signature_size());
    scheme.verify(&*pk, b"message", &sig).unwrap();
    assert_eq!(
        scheme.verify(&*pk, b"massage", &sig).unwrap_err(),
        Error::InvalidSignature
    );
    let mut bad = sig.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(scheme.verify(&*pk, b"message", &bad).is_err());
    assert!(scheme.verify(&*pk, b"message", &sig[1..]).is_err());

    let pk2 = scheme.public_key_from_bytes(&pk.to_bytes()).unwrap();
    scheme.verify(&*pk2, b"message", &sig).unwrap();
    let sk2 = scheme.private_key_from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(sk2.public_key().to_bytes(), pk.to_bytes());

    let seed = vec![7; scheme.seed_size()];
    let derived = scheme.derive_key(&seed).unwrap();
    assert_eq!(
        derived.to_bytes(),
        scheme.derive_key(&seed).unwrap().to_bytes()
    );
    let other = scheme.derive_key(&seed).unwrap().public_key();
    let sig = scheme.sign(&*derived, b"message", rng).unwrap();
    scheme.verify(&*other, b"message", &sig).unwrap();
    assert!(scheme.verify(&*pk, b"message", &sig).is_err());

    assert!(scheme.derive_key(&seed[1..]).is_err());
    assert!(scheme.public_key_from_bytes(&[0; 3]).is_err());
    assert!(scheme.private_key_from_bytes(&[0; 3]).is_err());
}
