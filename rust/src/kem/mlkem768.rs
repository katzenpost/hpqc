//! ML-KEM-768 (FIPS 203), wrapping the RustCrypto `ml-kem` crate.
//!
//! A private key encodes as the encapsulation key followed by the 64-byte
//! seed `d || z`.

use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit};
use ml_kem::{B32, DecapsulationKey768, EncapsulationKey768, ml_kem_768};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::util::{check_len, downcast, split, to_array};
use crate::{Error, Result, SecretBytes};

const PUBLIC_KEY_SIZE: usize = 1184;
const SEED_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Default)]
pub struct MlKem768;

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey(pub EncapsulationKey768);

#[derive(Clone)]
pub struct PrivateKey(DecapsulationKey768);

impl PrivateKey {
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        Self(DecapsulationKey768::from_seed((*seed).into()))
    }

    pub fn seed(&self) -> Zeroizing<[u8; SEED_SIZE]> {
        Zeroizing::new(self.0.to_seed().expect("always built from a seed").into())
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("mlkem768::PrivateKey")
            .finish_non_exhaustive()
    }
}

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        let ek = self.0.encapsulation_key().to_bytes();
        Zeroizing::new([ek.as_slice(), self.seed().as_slice()].concat())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey(self.0.encapsulation_key().clone()))
    }
}

impl MlKem768 {
    /// Encapsulates with the caller's randomness `m`, for test vectors.
    /// `m` must be uniformly random and never reused.
    pub fn encapsulate_deterministic(
        &self,
        public_key: &dyn super::PublicKey,
        m: &[u8; 32],
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let pk: &PublicKey = downcast(public_key)?;
        let (ct, ss) = pk.0.encapsulate_deterministic(&B32::from(*m));
        Ok((ct.to_vec(), Zeroizing::new(ss.to_vec())))
    }
}

impl super::Scheme for MlKem768 {
    fn name(&self) -> &str {
        "MLKEM768"
    }

    fn public_key_size(&self) -> usize {
        PUBLIC_KEY_SIZE
    }

    fn private_key_size(&self) -> usize {
        PUBLIC_KEY_SIZE + SEED_SIZE
    }

    fn ciphertext_size(&self) -> usize {
        1088
    }

    fn shared_secret_size(&self) -> usize {
        32
    }

    fn seed_size(&self) -> usize {
        SEED_SIZE
    }

    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let seed = Zeroizing::new(to_array(seed)?);
        Ok(Box::new(PrivateKey::from_seed(&seed)))
    }

    fn encapsulate(
        &self,
        public_key: &dyn super::PublicKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let pk: &PublicKey = downcast(public_key)?;
        let (ct, ss) = pk.0.encapsulate_with_rng(rng);
        Ok((ct.to_vec(), Zeroizing::new(ss.to_vec())))
    }

    fn decapsulate(
        &self,
        private_key: &dyn super::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        check_len(ciphertext, self.ciphertext_size())?;
        let ct = ml_kem_768::Ciphertext::try_from(ciphertext).expect("length checked");
        Ok(Zeroizing::new(sk.0.decapsulate(&ct).to_vec()))
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        check_len(bytes, PUBLIC_KEY_SIZE)?;
        let ek = EncapsulationKey768::new_from_slice(bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(PublicKey(ek)))
    }

    /// Rebuilds the key from its seed and checks that it matches the
    /// encoded encapsulation key.
    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let parts = split(bytes, [PUBLIC_KEY_SIZE, SEED_SIZE])?;
        let sk = PrivateKey::from_seed(&Zeroizing::new(to_array(parts[1])?));
        if sk.0.encapsulation_key().to_bytes().as_slice() != parts[0] {
            return Err(Error::InvalidKey);
        }
        Ok(Box::new(sk))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::*;

    #[test]
    fn scheme() {
        super::super::check_scheme(&MlKem768);
    }

    #[test]
    fn rejects_mismatched_private_key() {
        let rng = &mut crate::util::rng();
        let mut bytes = MlKem768.generate_key(rng).to_bytes();
        bytes[0] ^= 1;
        assert_eq!(
            MlKem768.private_key_from_bytes(&bytes).unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn rejects_unreduced_public_key() {
        assert_eq!(
            MlKem768
                .public_key_from_bytes(&[0xff; PUBLIC_KEY_SIZE])
                .unwrap_err(),
            Error::InvalidKey
        );
    }
}
