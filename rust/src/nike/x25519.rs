//! X25519 (RFC 7748), wrapping `x25519-dalek`.

use rand_core::CryptoRng;
pub use x25519_dalek;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::util::{ct_is_zero, downcast, to_array};
use crate::{Error, Result, SecretBytes};

#[derive(Clone, Copy, Debug, Default)]
pub struct X25519;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub x25519_dalek::PublicKey);

/// Holds the unclamped scalar; clamping happens at use.
#[derive(Clone)]
pub struct PrivateKey(pub StaticSecret);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("x25519::PrivateKey").finish_non_exhaustive()
    }
}

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        Zeroizing::new(self.0.as_bytes().to_vec())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey((&self.0).into()))
    }
}

impl super::Scheme for X25519 {
    fn name(&self) -> &str {
        "x25519"
    }

    fn public_key_size(&self) -> usize {
        32
    }

    fn private_key_size(&self) -> usize {
        32
    }

    fn generate_key(&self, rng: &mut dyn CryptoRng) -> Box<dyn super::PrivateKey> {
        Box::new(PrivateKey(StaticSecret::random_from_rng(rng)))
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        Ok(Box::new(PublicKey(to_array::<32>(bytes)?.into())))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let bytes = Zeroizing::new(to_array::<32>(bytes)?);
        Ok(Box::new(PrivateKey((*bytes).into())))
    }

    fn shared_secret(
        &self,
        private_key: &dyn super::PrivateKey,
        public_key: &dyn super::PublicKey,
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        let pk: &PublicKey = downcast(public_key)?;
        Ok(Zeroizing::new(
            sk.0.diffie_hellman(&pk.0).as_bytes().to_vec(),
        ))
    }

    fn blind(
        &self,
        public_key: &dyn super::PublicKey,
        factor: &dyn super::PrivateKey,
    ) -> Result<Box<dyn super::PublicKey>> {
        let pk: &PublicKey = downcast(public_key)?;
        let factor: &PrivateKey = downcast(factor)?;
        let point = factor.0.diffie_hellman(&pk.0).to_bytes();
        if ct_is_zero(&point) {
            return Err(Error::LowOrderPoint);
        }
        Ok(Box::new(PublicKey(point.into())))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::*;

    #[test]
    fn scheme() {
        super::super::check_scheme(&X25519);
    }

    #[test]
    fn rfc7748_vector() {
        let sk = hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let pk = hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let sk = X25519.private_key_from_bytes(&sk.unwrap()).unwrap();
        let pk = X25519.public_key_from_bytes(&pk.unwrap()).unwrap();
        assert_eq!(
            hex::encode(&*X25519.shared_secret(&*sk, &*pk).unwrap()),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    #[test]
    fn low_order_point() {
        let sk = X25519.generate_key(&mut crate::util::rng());
        let zero = X25519.public_key_from_bytes(&[0; 32]).unwrap();
        assert!(ct_is_zero(&X25519.shared_secret(&*sk, &*zero).unwrap()));
        assert_eq!(
            X25519.blind(&*zero, &*sk).unwrap_err(),
            Error::LowOrderPoint
        );
    }

    #[test]
    fn foreign_key() {
        let sk = X25519.generate_key(&mut crate::util::rng());
        let pk = super::super::x448::X448
            .public_key_from_bytes(&[9; 56])
            .unwrap();
        assert_eq!(
            X25519.shared_secret(&*sk, &*pk).unwrap_err(),
            Error::WrongKeyType
        );
    }
}
