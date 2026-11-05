//! CTIDH-1024 from the highctidh-rs crate, the highctidh C library that
//! hpqc's Go `ctidh1024` package uses.

use rand_core::CryptoRng;

use crate::util::downcast;
use crate::{Error, Result, SecretBytes};

pub use highctidh::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, PrivateKey, PublicKey};

impl From<highctidh::Error> for Error {
    fn from(e: highctidh::Error) -> Self {
        match e {
            highctidh::Error::InvalidLength { expected, actual } => {
                Error::InvalidLength { expected, actual }
            }
            highctidh::Error::InvalidKey => Error::InvalidKey,
            highctidh::Error::LowOrderPoint => Error::LowOrderPoint,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Ctidh1024;

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        PublicKey::to_bytes(self)
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        PrivateKey::to_bytes(self)
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PrivateKey::public_key(self))
    }
}

impl super::Scheme for Ctidh1024 {
    fn name(&self) -> &str {
        "ctidh1024"
    }

    fn public_key_size(&self) -> usize {
        PUBLIC_KEY_SIZE
    }

    fn private_key_size(&self) -> usize {
        PRIVATE_KEY_SIZE
    }

    fn generate_key(&self, rng: &mut dyn CryptoRng) -> Box<dyn super::PrivateKey> {
        Box::new(PrivateKey::generate(rng))
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        Ok(Box::new(PublicKey::from_bytes(bytes)?))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        Ok(Box::new(PrivateKey::from_bytes(bytes)?))
    }

    fn shared_secret(
        &self,
        private_key: &dyn super::PrivateKey,
        public_key: &dyn super::PublicKey,
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        let pk: &PublicKey = downcast(public_key)?;
        Ok(sk.shared_secret(pk)?)
    }

    fn blind(
        &self,
        public_key: &dyn super::PublicKey,
        factor: &dyn super::PrivateKey,
    ) -> Result<Box<dyn super::PublicKey>> {
        let pk: &PublicKey = downcast(public_key)?;
        let factor: &PrivateKey = downcast(factor)?;
        Ok(Box::new(pk.blind(factor)?))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::*;

    #[test]
    fn scheme() {
        super::super::check_scheme(&Ctidh1024);
    }

    #[test]
    fn rejects_base_curve_and_invalid_keys() {
        assert_eq!(
            Ctidh1024.public_key_from_bytes(&[0; 128]).unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            Ctidh1024.public_key_from_bytes(&[1; 128]).unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            Ctidh1024.private_key_from_bytes(&[127; 130]).unwrap_err(),
            Error::InvalidKey
        );
    }
}
