//! Key encapsulation.

pub mod adapter;
pub mod combiner;
pub mod mceliece;
pub mod mlkem;
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

    fn ciphertext_size(&self) -> usize;

    fn shared_secret_size(&self) -> usize;

    fn seed_size(&self) -> usize;

    fn generate_key(&self, rng: &mut dyn CryptoRng) -> Box<dyn PrivateKey> {
        let mut seed = Zeroizing::new(vec![0; self.seed_size()]);
        rng.fill_bytes(&mut seed);
        self.derive_key(&seed).expect("seed has the right length")
    }

    /// Derives a key deterministically from `seed_size` bytes.
    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn PrivateKey>>;

    /// Returns the ciphertext and the shared secret.
    fn encapsulate(
        &self,
        public_key: &dyn PublicKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, SecretBytes)>;

    fn decapsulate(&self, private_key: &dyn PrivateKey, ciphertext: &[u8]) -> Result<SecretBytes>;

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

    let (ct, ss) = scheme.encapsulate(&*pk, rng).unwrap();
    assert_eq!(ct.len(), scheme.ciphertext_size());
    assert_eq!(ss.len(), scheme.shared_secret_size());
    assert_eq!(scheme.decapsulate(&*sk, &ct).unwrap(), ss);
    assert_ne!(scheme.encapsulate(&*pk, rng).unwrap().1, ss);

    let pk2 = scheme.public_key_from_bytes(&pk.to_bytes()).unwrap();
    assert_eq!(pk2.to_bytes(), pk.to_bytes());
    let sk2 = scheme.private_key_from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(sk2.to_bytes(), sk.to_bytes());
    assert_eq!(scheme.decapsulate(&*sk2, &ct).unwrap(), ss);

    let seed = vec![7; scheme.seed_size()];
    let derived = scheme.derive_key(&seed).unwrap();
    assert_eq!(
        derived.to_bytes(),
        scheme.derive_key(&seed).unwrap().to_bytes()
    );
    assert_ne!(derived.to_bytes(), sk.to_bytes());
    assert!(matches!(
        scheme.derive_key(&seed[1..]).unwrap_err(),
        Error::InvalidLength { .. }
    ));

    assert!(scheme.decapsulate(&*sk, &ct[1..]).is_err());
    assert!(scheme.public_key_from_bytes(&[0; 3]).is_err());
    assert!(scheme.private_key_from_bytes(&[0; 3]).is_err());
}
