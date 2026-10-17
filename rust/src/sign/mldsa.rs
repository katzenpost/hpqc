//! ML-DSA (FIPS 204), wrapping the RustCrypto `ml-dsa` crate.
//!
//! Private keys encode as their 32-byte seed. Signing is hedged and uses
//! the empty context string.

use std::fmt;
use std::marker::PhantomData;

use ml_dsa::{B32, KeyInit, Keypair, MlDsaParams, Signature, SigningKey, VerifyingKey};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::util::{check_len, downcast, to_array};
use crate::{Error, Result, SecretBytes};

/// An ML-DSA parameter set.
pub trait Params: MlDsaParams + 'static {
    const NAME: &'static str;
    const PUBLIC_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;
}

impl Params for ml_dsa::MlDsa44 {
    const NAME: &'static str = "ML-DSA-44";
    const PUBLIC_KEY_SIZE: usize = 1312;
    const SIGNATURE_SIZE: usize = 2420;
}

impl Params for ml_dsa::MlDsa65 {
    const NAME: &'static str = "ML-DSA-65";
    const PUBLIC_KEY_SIZE: usize = 1952;
    const SIGNATURE_SIZE: usize = 3309;
}

impl Params for ml_dsa::MlDsa87 {
    const NAME: &'static str = "ML-DSA-87";
    const PUBLIC_KEY_SIZE: usize = 2592;
    const SIGNATURE_SIZE: usize = 4627;
}

pub struct MlDsa<P>(PhantomData<fn() -> P>);

pub type MlDsa44 = MlDsa<ml_dsa::MlDsa44>;
pub type MlDsa65 = MlDsa<ml_dsa::MlDsa65>;
pub type MlDsa87 = MlDsa<ml_dsa::MlDsa87>;

impl<P> MlDsa<P> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<P> Default for MlDsa<P> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PublicKey<P: Params>(pub VerifyingKey<P>);

pub struct PrivateKey<P: Params>(pub SigningKey<P>);

impl<P: Params> fmt::Debug for PublicKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(P::NAME).field(&self.0).finish()
    }
}

impl<P: Params> fmt::Debug for PrivateKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(P::NAME).finish_non_exhaustive()
    }
}

impl<P: Params> super::PublicKey for PublicKey<P> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
}

impl<P: Params> super::PrivateKey for PrivateKey<P> {
    fn to_bytes(&self) -> SecretBytes {
        Zeroizing::new(self.0.to_seed().to_vec())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey(self.0.verifying_key()))
    }
}

impl<P: Params> super::Scheme for MlDsa<P> {
    fn name(&self) -> &str {
        P::NAME
    }

    fn public_key_size(&self) -> usize {
        P::PUBLIC_KEY_SIZE
    }

    fn private_key_size(&self) -> usize {
        32
    }

    fn signature_size(&self) -> usize {
        P::SIGNATURE_SIZE
    }

    fn seed_size(&self) -> usize {
        32
    }

    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let seed = Zeroizing::new(B32::from(to_array::<32>(seed)?));
        Ok(Box::new(PrivateKey(SigningKey::<P>::from_seed(&seed))))
    }

    fn sign(
        &self,
        private_key: &dyn super::PrivateKey,
        message: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>> {
        let sk: &PrivateKey<P> = downcast(private_key)?;
        let sig =
            sk.0.expanded_key()
                .sign_randomized(message, &[], rng)
                .map_err(|_| Error::Unsupported("ML-DSA signing"))?;
        Ok(sig.encode().to_vec())
    }

    fn verify(
        &self,
        public_key: &dyn super::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let pk: &PublicKey<P> = downcast(public_key)?;
        check_len(signature, P::SIGNATURE_SIZE)?;
        let sig = Signature::<P>::try_from(signature).map_err(|_| Error::InvalidSignature)?;
        if pk.0.verify_with_context(message, &[], &sig) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        check_len(bytes, P::PUBLIC_KEY_SIZE)?;
        let pk = VerifyingKey::<P>::new_from_slice(bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(PublicKey(pk)))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        self.derive_key(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa44() {
        super::super::check_scheme(&MlDsa44::new());
    }

    #[test]
    fn mldsa65() {
        super::super::check_scheme(&MlDsa65::new());
    }

    #[test]
    fn mldsa87() {
        super::super::check_scheme(&MlDsa87::new());
    }
}
