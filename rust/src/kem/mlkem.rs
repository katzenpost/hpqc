//! ML-KEM (FIPS 203), wrapping the RustCrypto `ml-kem` crate.
//!
//! A private key encodes as the encapsulation key followed by the 64-byte
//! seed `d || z`.
//!
//! The hedged variants restore round-3 Kyber's pre-hash: the encapsulation
//! randomness `m` is replaced by `SHA3-256(m)` before use, hedging against a
//! weak RNG. They are not FIPS 203, but share keys, ciphertexts and
//! decapsulation with the standard variants.

use std::fmt;
use std::marker::PhantomData;

use ml_kem::array::typenum::{U32, U64, Unsigned};
use ml_kem::kem::{
    Ciphertext, Decapsulate, Decapsulator, Kem, KeyExport, KeyInit, KeySizeUser, SharedKey,
    TryKeyInit,
};
use ml_kem::{B32, Seed};
use rand_core::CryptoRng;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::util::{check_len, downcast, split, to_array};
use crate::{Error, Result, SecretBytes};

const SEED_SIZE: usize = 64;

/// An ML-KEM parameter set.
pub trait Params:
    Kem<
        SharedKeySize = U32,
        EncapsulationKey: PartialEq + Send + Sync + 'static,
        DecapsulationKey: Decapsulate
                              + KeyInit
                              + KeySizeUser<KeySize = U64>
                              + KeyExport
                              + Clone
                              + Send
                              + Sync
                              + 'static,
    >
{
    const NAME: &'static str;
    const HEDGED_NAME: &'static str;

    #[doc(hidden)]
    fn encapsulate_deterministic(
        ek: &Self::EncapsulationKey,
        m: &B32,
    ) -> (Ciphertext<Self>, SharedKey<Self>);
}

macro_rules! params {
    ($kem:ty, $name:literal, $hedged:literal) => {
        impl Params for $kem {
            const NAME: &'static str = $name;
            const HEDGED_NAME: &'static str = $hedged;

            fn encapsulate_deterministic(
                ek: &Self::EncapsulationKey,
                m: &B32,
            ) -> (Ciphertext<Self>, SharedKey<Self>) {
                ek.encapsulate_deterministic(m)
            }
        }
    };
}

params!(ml_kem::MlKem512, "MLKEM512", "MLKEMHedged512");
params!(ml_kem::MlKem768, "MLKEM768", "MLKEMHedged768");
params!(ml_kem::MlKem1024, "MLKEM1024", "MLKEMHedged1024");

pub struct MlKem<P> {
    hedged: bool,
    params: PhantomData<fn() -> P>,
}

pub type MlKem512 = MlKem<ml_kem::MlKem512>;
pub type MlKem768 = MlKem<ml_kem::MlKem768>;
pub type MlKem1024 = MlKem<ml_kem::MlKem1024>;

impl<P> MlKem<P> {
    pub const fn new() -> Self {
        Self {
            hedged: false,
            params: PhantomData,
        }
    }

    pub const fn hedged() -> Self {
        Self {
            hedged: true,
            params: PhantomData,
        }
    }

    pub const fn is_hedged(&self) -> bool {
        self.hedged
    }
}

impl<P> Default for MlKem<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, PartialEq)]
pub struct PublicKey<P: Params>(pub P::EncapsulationKey);

#[derive(Clone)]
pub struct PrivateKey<P: Params>(P::DecapsulationKey);

impl<P: Params> PrivateKey<P> {
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        Self(P::DecapsulationKey::new(&Seed::from(*seed)))
    }

    pub fn seed(&self) -> Zeroizing<[u8; SEED_SIZE]> {
        Zeroizing::new(self.0.to_bytes().into())
    }
}

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
        self.0.to_bytes().to_vec()
    }
}

impl<P: Params> super::PrivateKey for PrivateKey<P> {
    fn to_bytes(&self) -> SecretBytes {
        let ek = self.0.encapsulation_key().to_bytes();
        Zeroizing::new([ek.as_slice(), self.seed().as_slice()].concat())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey::<P>(self.0.encapsulation_key().clone()))
    }
}

impl<P: Params> MlKem<P> {
    /// Encapsulates with the caller's randomness `m`, which is hashed first
    /// when the scheme is hedged. `m` must be uniformly random and never
    /// reused; this is for test vectors.
    pub fn encapsulate_deterministic(
        &self,
        public_key: &dyn super::PublicKey,
        m: &[u8; 32],
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let pk: &PublicKey<P> = downcast(public_key)?;
        let mut coins = Zeroizing::new(B32::from(*m));
        if self.hedged {
            coins.copy_from_slice(&Sha3_256::digest(m));
        }
        let (ct, ss) = P::encapsulate_deterministic(&pk.0, &coins);
        Ok((ct.to_vec(), Zeroizing::new(ss.to_vec())))
    }
}

impl<P: Params> super::Scheme for MlKem<P> {
    fn name(&self) -> &str {
        if self.hedged { P::HEDGED_NAME } else { P::NAME }
    }

    fn public_key_size(&self) -> usize {
        <P::EncapsulationKey as KeySizeUser>::KeySize::USIZE
    }

    fn private_key_size(&self) -> usize {
        self.public_key_size() + SEED_SIZE
    }

    fn ciphertext_size(&self) -> usize {
        P::CiphertextSize::USIZE
    }

    fn shared_secret_size(&self) -> usize {
        32
    }

    fn seed_size(&self) -> usize {
        SEED_SIZE
    }

    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let seed = Zeroizing::new(to_array(seed)?);
        Ok(Box::new(PrivateKey::<P>::from_seed(&seed)))
    }

    fn encapsulate(
        &self,
        public_key: &dyn super::PublicKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let mut m = Zeroizing::new([0; 32]);
        rng.fill_bytes(&mut *m);
        self.encapsulate_deterministic(public_key, &m)
    }

    fn decapsulate(
        &self,
        private_key: &dyn super::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey<P> = downcast(private_key)?;
        check_len(ciphertext, self.ciphertext_size())?;
        let ss =
            sk.0.decapsulate_slice(ciphertext)
                .map_err(|_| Error::InvalidLength {
                    expected: self.ciphertext_size(),
                    actual: ciphertext.len(),
                })?;
        Ok(Zeroizing::new(ss.to_vec()))
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        check_len(bytes, self.public_key_size())?;
        let ek = P::EncapsulationKey::new_from_slice(bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(PublicKey::<P>(ek)))
    }

    /// Rebuilds the key from its seed and checks that it matches the
    /// encoded encapsulation key.
    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let parts = split(bytes, [self.public_key_size(), SEED_SIZE])?;
        let sk = PrivateKey::<P>::from_seed(&Zeroizing::new(to_array(parts[1])?));
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

    fn all() -> Vec<Box<dyn Scheme>> {
        vec![
            Box::new(MlKem512::new()),
            Box::new(MlKem768::new()),
            Box::new(MlKem1024::new()),
            Box::new(MlKem512::hedged()),
            Box::new(MlKem768::hedged()),
            Box::new(MlKem1024::hedged()),
        ]
    }

    #[test]
    fn schemes() {
        for scheme in all() {
            super::super::check_scheme(&*scheme);
        }
    }

    #[test]
    fn sizes() {
        let sizes: Vec<_> = all()[..3]
            .iter()
            .map(|s| (s.public_key_size(), s.ciphertext_size()))
            .collect();
        assert_eq!(sizes, [(800, 768), (1184, 1088), (1568, 1568)]);
    }

    #[test]
    fn rejects_mismatched_private_key() {
        let rng = &mut crate::util::rng();
        for scheme in all() {
            let mut bytes = scheme.generate_key(rng).to_bytes();
            bytes[0] ^= 1;
            assert_eq!(
                scheme.private_key_from_bytes(&bytes).unwrap_err(),
                Error::InvalidKey
            );
        }
    }

    #[test]
    fn rejects_unreduced_public_key() {
        for scheme in all() {
            let bytes = vec![0xff; scheme.public_key_size()];
            assert_eq!(
                scheme.public_key_from_bytes(&bytes).unwrap_err(),
                Error::InvalidKey
            );
        }
    }

    fn check_hedging<P: Params>() {
        let rng = &mut crate::util::rng();
        let (standard, hedged) = (MlKem::<P>::new(), MlKem::<P>::hedged());
        let sk = standard.generate_key(rng);
        let pk = sk.public_key();
        let m = [7; 32];
        let (ct, ss) = hedged.encapsulate_deterministic(&*pk, &m).unwrap();
        let m_hash: [u8; 32] = Sha3_256::digest(m).into();
        assert_eq!(
            standard.encapsulate_deterministic(&*pk, &m_hash).unwrap(),
            (ct.clone(), ss.clone())
        );
        assert_ne!(standard.encapsulate_deterministic(&*pk, &m).unwrap().0, ct);
        assert_eq!(hedged.decapsulate(&*sk, &ct).unwrap(), ss);
    }

    #[test]
    fn hedged_hashes_the_randomness() {
        check_hedging::<ml_kem::MlKem512>();
        check_hedging::<ml_kem::MlKem768>();
        check_hedging::<ml_kem::MlKem1024>();
    }
}
