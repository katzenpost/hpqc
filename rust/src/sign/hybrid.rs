//! Pairs two signature schemes. Keys and signatures are the concatenation
//! of their halves, and a signature verifies only if both halves do.

use std::sync::Arc;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::Scheme;
use crate::util::{downcast, split};
use crate::{Result, SecretBytes};

pub struct Hybrid {
    name: String,
    first: Arc<dyn Scheme>,
    second: Arc<dyn Scheme>,
}

impl Hybrid {
    pub fn new(name: impl Into<String>, first: Arc<dyn Scheme>, second: Arc<dyn Scheme>) -> Self {
        Self {
            name: name.into(),
            first,
            second,
        }
    }

    pub fn first(&self) -> &Arc<dyn Scheme> {
        &self.first
    }

    pub fn second(&self) -> &Arc<dyn Scheme> {
        &self.second
    }
}

#[derive(Debug)]
pub struct PublicKey {
    first: Box<dyn super::PublicKey>,
    second: Box<dyn super::PublicKey>,
}

impl PublicKey {
    pub fn first(&self) -> &dyn super::PublicKey {
        &*self.first
    }

    pub fn second(&self) -> &dyn super::PublicKey {
        &*self.second
    }
}

#[derive(Debug)]
pub struct PrivateKey {
    first: Box<dyn super::PrivateKey>,
    second: Box<dyn super::PrivateKey>,
}

impl PrivateKey {
    pub fn first(&self) -> &dyn super::PrivateKey {
        &*self.first
    }

    pub fn second(&self) -> &dyn super::PrivateKey {
        &*self.second
    }
}

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        [self.first.to_bytes(), self.second.to_bytes()].concat()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        Zeroizing::new([self.first.to_bytes().as_slice(), &self.second.to_bytes()].concat())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey {
            first: self.first.public_key(),
            second: self.second.public_key(),
        })
    }
}

impl Scheme for Hybrid {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key_size(&self) -> usize {
        self.first.public_key_size() + self.second.public_key_size()
    }

    fn private_key_size(&self) -> usize {
        self.first.private_key_size() + self.second.private_key_size()
    }

    fn signature_size(&self) -> usize {
        self.first.signature_size() + self.second.signature_size()
    }

    fn seed_size(&self) -> usize {
        self.first.seed_size() + self.second.seed_size()
    }

    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let seeds = split(seed, [self.first.seed_size(), self.second.seed_size()])?;
        Ok(Box::new(PrivateKey {
            first: self.first.derive_key(seeds[0])?,
            second: self.second.derive_key(seeds[1])?,
        }))
    }

    fn sign(
        &self,
        private_key: &dyn super::PrivateKey,
        message: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>> {
        let sk: &PrivateKey = downcast(private_key)?;
        let first = self.first.sign(&*sk.first, message, rng)?;
        let second = self.second.sign(&*sk.second, message, rng)?;
        Ok([first, second].concat())
    }

    fn verify(
        &self,
        public_key: &dyn super::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let pk: &PublicKey = downcast(public_key)?;
        let sigs = split(
            signature,
            [self.first.signature_size(), self.second.signature_size()],
        )?;
        self.first.verify(&*pk.first, message, sigs[0])?;
        self.second.verify(&*pk.second, message, sigs[1])
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        let parts = split(
            bytes,
            [self.first.public_key_size(), self.second.public_key_size()],
        )?;
        Ok(Box::new(PublicKey {
            first: self.first.public_key_from_bytes(parts[0])?,
            second: self.second.public_key_from_bytes(parts[1])?,
        }))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let parts = split(
            bytes,
            [
                self.first.private_key_size(),
                self.second.private_key_size(),
            ],
        )?;
        Ok(Box::new(PrivateKey {
            first: self.first.private_key_from_bytes(parts[0])?,
            second: self.second.private_key_from_bytes(parts[1])?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ed25519::Ed25519, mldsa::MlDsa65};
    use super::*;
    use crate::Error;

    fn mldsa65_ed25519() -> Hybrid {
        Hybrid::new(
            "ML-DSA-65-Ed25519",
            Arc::new(MlDsa65::new()),
            Arc::new(Ed25519),
        )
    }

    #[test]
    fn scheme() {
        super::super::check_scheme(&mldsa65_ed25519());
    }

    #[test]
    fn both_halves_must_verify() {
        let rng = &mut crate::util::rng();
        let hybrid = mldsa65_ed25519();
        let sk = hybrid.generate_key(rng);
        let pk = sk.public_key();
        let sig = hybrid.sign(&*sk, b"message", rng).unwrap();

        let mut first_bad = sig.clone();
        first_bad[0] ^= 1;
        let mut second_bad = sig.clone();
        second_bad[3309] ^= 1;
        for bad in [first_bad, second_bad] {
            assert_eq!(
                hybrid.verify(&*pk, b"message", &bad).unwrap_err(),
                Error::InvalidSignature
            );
        }
    }

    #[test]
    fn halves_are_component_signatures() {
        let rng = &mut crate::util::rng();
        let hybrid = mldsa65_ed25519();
        let sk = hybrid.generate_key(rng);
        let sig = hybrid.sign(&*sk, b"message", rng).unwrap();
        let sk: &PrivateKey = downcast(&*sk).unwrap();
        Ed25519
            .verify(&*sk.second.public_key(), b"message", &sig[3309..])
            .unwrap();
        MlDsa65::new()
            .verify(&*sk.first.public_key(), b"message", &sig[..3309])
            .unwrap();
    }
}
