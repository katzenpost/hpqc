//! Runs two NIKEs side by side. Keys and shared secrets are the
//! concatenation of their halves, and a low-order point in either half is
//! an error.

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

    fn generate_key(&self, rng: &mut dyn CryptoRng) -> Box<dyn super::PrivateKey> {
        Box::new(PrivateKey {
            first: self.first.generate_key(rng),
            second: self.second.generate_key(rng),
        })
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

    fn shared_secret(
        &self,
        private_key: &dyn super::PrivateKey,
        public_key: &dyn super::PublicKey,
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        let pk: &PublicKey = downcast(public_key)?;
        let first = self.first.shared_secret(&*sk.first, &*pk.first)?;
        let second = self.second.shared_secret(&*sk.second, &*pk.second)?;
        Ok(Zeroizing::new([first.as_slice(), &second].concat()))
    }

    fn blind(
        &self,
        public_key: &dyn super::PublicKey,
        factor: &dyn super::PrivateKey,
    ) -> Result<Box<dyn super::PublicKey>> {
        let pk: &PublicKey = downcast(public_key)?;
        let factor: &PrivateKey = downcast(factor)?;
        Ok(Box::new(PublicKey {
            first: self.first.blind(&*pk.first, &*factor.first)?,
            second: self.second.blind(&*pk.second, &*factor.second)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{x448::X448, x25519::X25519};
    use super::*;
    use crate::Error;

    fn x25519_x448() -> Hybrid {
        Hybrid::new("X25519-X448", Arc::new(X25519), Arc::new(X448))
    }

    #[test]
    fn scheme() {
        super::super::check_scheme(&x25519_x448());
    }

    #[test]
    fn nested() {
        let nested = Hybrid::new("nested", Arc::new(x25519_x448()), Arc::new(X25519));
        assert_eq!(nested.public_key_size(), 32 + 56 + 32);
        super::super::check_scheme(&nested);
    }

    #[test]
    fn secret_is_concatenation() {
        let rng = &mut crate::util::rng();
        let hybrid = x25519_x448();
        let alice = hybrid.generate_key(rng);
        let bob = hybrid.generate_key(rng);
        let secret = hybrid.shared_secret(&*alice, &*bob.public_key()).unwrap();

        let alice: &PrivateKey = downcast(&*alice).unwrap();
        let bob: &PrivateKey = downcast(&*bob).unwrap();
        let first = X25519
            .shared_secret(&*alice.first, &*bob.first.public_key())
            .unwrap();
        let second = X448
            .shared_secret(&*alice.second, &*bob.second.public_key())
            .unwrap();
        assert_eq!(*secret, [first.as_slice(), &second].concat());
    }

    #[test]
    fn low_order_half_is_rejected() {
        let rng = &mut crate::util::rng();
        let hybrid = x25519_x448();
        let sk = hybrid.generate_key(rng);
        for range in [0..32, 32..88] {
            let mut bytes = hybrid.generate_key(rng).public_key().to_bytes();
            bytes[range].fill(0);
            let pk = hybrid.public_key_from_bytes(&bytes).unwrap();
            assert_eq!(
                hybrid.shared_secret(&*sk, &*pk).unwrap_err(),
                Error::LowOrderPoint
            );
        }
    }

    #[test]
    fn rejects_component_keys() {
        let hybrid = x25519_x448();
        let sk = hybrid.generate_key(&mut crate::util::rng());
        let pk = X25519.public_key_from_bytes(&[9; 32]).unwrap();
        assert_eq!(
            hybrid.shared_secret(&*sk, &*pk).unwrap_err(),
            Error::WrongKeyType
        );
        assert_eq!(
            hybrid.public_key_from_bytes(&[0; 32]).unwrap_err(),
            Error::InvalidLength {
                expected: 88,
                actual: 32
            }
        );
    }
}
