//! Ed25519 (RFC 8032), wrapping `ed25519-dalek`.
//!
//! A private key encodes as the RFC 8032 secret key followed by the public
//! key. [`derive_key`](super::Scheme::derive_key) expands its seed with
//! BLAKE2Xb before use, as hpqc's Go implementation does.

pub use ed25519_dalek;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::hash::Blake2Xb;
use crate::util::{check_len, downcast, to_array};
use crate::{Error, Result, SecretBytes};

#[derive(Clone, Copy, Debug, Default)]
pub struct Ed25519;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub VerifyingKey);

#[derive(Clone, Debug)]
pub struct PrivateKey(pub SigningKey);

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        Zeroizing::new(self.0.to_keypair_bytes().to_vec())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey(self.0.verifying_key()))
    }
}

impl super::Scheme for Ed25519 {
    fn name(&self) -> &str {
        "Ed25519"
    }

    fn public_key_size(&self) -> usize {
        32
    }

    fn private_key_size(&self) -> usize {
        64
    }

    fn signature_size(&self) -> usize {
        64
    }

    fn seed_size(&self) -> usize {
        32
    }

    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        check_len(seed, 32)?;
        let mut secret = Zeroizing::new([0; 32]);
        Blake2Xb::new(None, seed)?
            .finalize_xof()
            .read(&mut *secret)?;
        Ok(Box::new(PrivateKey(SigningKey::from_bytes(&secret))))
    }

    fn sign(
        &self,
        private_key: &dyn super::PrivateKey,
        message: &[u8],
        _rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>> {
        let sk: &PrivateKey = downcast(private_key)?;
        Ok(sk.0.sign(message).to_bytes().to_vec())
    }

    fn verify(
        &self,
        public_key: &dyn super::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let pk: &PublicKey = downcast(public_key)?;
        let signature = Signature::from_bytes(&to_array(signature)?);
        pk.0.verify(message, &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        let pk = VerifyingKey::from_bytes(&to_array(bytes)?).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(PublicKey(pk)))
    }

    /// Checks that the encoded public key matches the seed.
    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let bytes = Zeroizing::new(to_array(bytes)?);
        let sk = SigningKey::from_keypair_bytes(&bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(PrivateKey(sk)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::*;

    #[test]
    fn scheme() {
        super::super::check_scheme(&Ed25519);
    }

    #[test]
    fn rejects_mismatched_private_key() {
        let mut bytes = Ed25519.generate_key(&mut crate::util::rng()).to_bytes();
        bytes[40] ^= 1;
        assert_eq!(
            Ed25519.private_key_from_bytes(&bytes).unwrap_err(),
            Error::InvalidKey
        );
    }
}
