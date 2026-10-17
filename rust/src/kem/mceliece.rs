//! Classic McEliece, wrapping the `pq-mceliece` crate.
//!
//! Keys use the specification's encodings, as Go's circl does: the private
//! key is the full secret key, which begins with the 32-byte seed.

use std::fmt;
use std::sync::OnceLock;

pub use pq_mceliece::Algorithm;
use pq_mceliece::{DecapsulationKey, EncapsulationKey};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::util::{check_len, downcast};
use crate::{Error, Result, SecretBytes};

/// A Classic McEliece parameter set as a [`Scheme`](super::Scheme), named
/// as the parameter set, e.g. `mceliece6960119f`.
#[derive(Clone, Copy, Debug)]
pub struct McEliece(Algorithm);

impl McEliece {
    pub const fn new(algorithm: Algorithm) -> Self {
        Self(algorithm)
    }

    pub const fn algorithm(&self) -> Algorithm {
        self.0
    }

    fn check(&self, algorithm: Algorithm) -> Result<()> {
        if algorithm == self.0 {
            Ok(())
        } else {
            Err(Error::WrongKeyType)
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct PublicKey(pub EncapsulationKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("mceliece::PublicKey")
            .field(&self.0.algorithm())
            .finish_non_exhaustive()
    }
}

/// The public key is derived on first use, which costs a key generation.
pub struct PrivateKey {
    key: DecapsulationKey,
    public: OnceLock<EncapsulationKey>,
}

impl PrivateKey {
    pub fn key(&self) -> &DecapsulationKey {
        &self.key
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("mceliece::PrivateKey")
            .field(&self.key.algorithm())
            .finish_non_exhaustive()
    }
}

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.value().to_vec()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        Zeroizing::new(self.key.value().to_vec())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        let ek = self.public.get_or_init(|| (&self.key).into());
        Box::new(PublicKey(ek.clone()))
    }
}

impl super::Scheme for McEliece {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn public_key_size(&self) -> usize {
        self.0.params().encapsulation_key_length
    }

    fn private_key_size(&self) -> usize {
        self.0.params().decapsulation_key_length
    }

    fn ciphertext_size(&self) -> usize {
        self.0.params().ciphertext_length
    }

    fn shared_secret_size(&self) -> usize {
        self.0.params().shared_secret_length
    }

    fn seed_size(&self) -> usize {
        self.0.params().seed_length
    }

    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        check_len(seed, self.seed_size())?;
        let (ek, key) = self
            .0
            .generate_keypair_from_seed(seed)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(PrivateKey {
            key,
            public: ek.into(),
        }))
    }

    fn encapsulate(
        &self,
        public_key: &dyn super::PublicKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let pk: &PublicKey = downcast(public_key)?;
        self.check(pk.0.algorithm())?;
        let (ct, ss) = self
            .0
            .encapsulate(&pk.0, rng)
            .map_err(|_| Error::InvalidKey)?;
        Ok((ct.value().to_vec(), Zeroizing::new(ss.value().to_vec())))
    }

    fn decapsulate(
        &self,
        private_key: &dyn super::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        self.check(sk.key.algorithm())?;
        check_len(ciphertext, self.ciphertext_size())?;
        let ct = self
            .0
            .ciphertext_from_bytes(ciphertext)
            .map_err(|_| Error::InvalidInput("Classic McEliece ciphertext"))?;
        let ss = self
            .0
            .decapsulate(&sk.key, &ct)
            .map_err(|_| Error::InvalidInput("Classic McEliece ciphertext padding"))?;
        Ok(Zeroizing::new(ss.value().to_vec()))
    }

    /// Rejects keys whose padding bits are set.
    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        check_len(bytes, self.public_key_size())?;
        let ek = self
            .0
            .encapsulation_key_from_bytes(bytes)
            .map_err(|_| Error::InvalidKey)?;
        if !ek.padding_is_zero() {
            return Err(Error::InvalidKey);
        }
        Ok(Box::new(PublicKey(ek)))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        check_len(bytes, self.private_key_size())?;
        let key = self
            .0
            .decapsulation_key_from_bytes(bytes)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(PrivateKey {
            key,
            public: OnceLock::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::*;

    #[test]
    fn mceliece348864() {
        super::super::check_scheme(&McEliece::new(Algorithm::McEliece348864));
    }

    #[test]
    fn sizes_match_go() {
        let kem = McEliece::new(Algorithm::McEliece348864);
        assert_eq!(kem.name(), "mceliece348864");
        assert_eq!(
            (
                kem.public_key_size(),
                kem.private_key_size(),
                kem.ciphertext_size()
            ),
            (261120, 6492, 96)
        );
    }

    #[test]
    fn rejects_keys_of_other_parameter_sets() {
        let rng = &mut crate::util::rng();
        let a = McEliece::new(Algorithm::McEliece348864);
        let b = McEliece::new(Algorithm::McEliece348864f);
        let sk = a.generate_key(rng);
        let (ct, _) = a.encapsulate(&*sk.public_key(), rng).unwrap();
        assert_eq!(
            b.encapsulate(&*sk.public_key(), rng).unwrap_err(),
            Error::WrongKeyType
        );
        assert_eq!(b.decapsulate(&*sk, &ct).unwrap_err(), Error::WrongKeyType);
    }

    #[test]
    fn private_key_round_trip_rederives_public_key() {
        let kem = McEliece::new(Algorithm::McEliece348864f);
        let sk = kem.derive_key(&[3; 32]).unwrap();
        let sk2 = kem.private_key_from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk2.public_key().to_bytes(), sk.public_key().to_bytes());
    }
}
