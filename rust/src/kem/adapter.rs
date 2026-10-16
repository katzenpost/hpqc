//! Turns any NIKE into a KEM by hashed ElGamal.
//!
//! The ciphertext is a fresh ephemeral public key, and the shared secret is
//! a PRF of the Diffie-Hellman output and both public keys.

use std::sync::Arc;

use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::Scheme as _;
use crate::hash::{Blake2Xb, blake2b_256};
use crate::nike;
use crate::util::{check_len, ct_is_zero, downcast};
use crate::{Error, Result, SecretBytes};

/// How the shared secret is derived from the Diffie-Hellman output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Prf {
    /// BLAKE2Xb keyed by the Diffie-Hellman output (hashed down to 32 bytes
    /// if longer), absorbing both public keys.
    #[default]
    Blake2bXof,
    /// SHA-256 over a label and the length-prefixed inputs. Only produces
    /// 32-byte secrets.
    Sha256V1,
}

impl Prf {
    fn derive(
        self,
        dh: &[u8],
        static_pk: &[u8],
        ephemeral_pk: &[u8],
        size: usize,
    ) -> Result<SecretBytes> {
        match self {
            Prf::Blake2bXof => {
                if dh.len() > size {
                    return Err(Error::Unsupported("secret longer than the XOF output"));
                }
                let hashed;
                let key = if dh.len() == 32 {
                    dh
                } else {
                    hashed = Zeroizing::new(blake2b_256(&[], dh));
                    &hashed[..]
                };
                let size = u32::try_from(size).map_err(|_| Error::Unsupported("XOF length"))?;
                let mut xof = Blake2Xb::new(Some(size), key)?;
                xof.update(static_pk).update(ephemeral_pk);
                let mut out = Zeroizing::new(vec![0; dh.len()]);
                xof.finalize_xof().read(&mut out);
                Ok(out)
            }
            Prf::Sha256V1 => {
                if size != 32 {
                    return Err(Error::Unsupported(
                        "sha256-v1 needs a 32-byte shared secret",
                    ));
                }
                let mut h = Sha256::new();
                h.update(b"kemadapter-sha256-v1");
                for part in [dh, static_pk, ephemeral_pk] {
                    h.update((part.len() as u32).to_be_bytes());
                    h.update(part);
                }
                Ok(Zeroizing::new(h.finalize().to_vec()))
            }
        }
    }
}

pub struct NikeKem {
    nike: Arc<dyn nike::Scheme>,
    prf: Prf,
}

impl NikeKem {
    pub fn new(nike: Arc<dyn nike::Scheme>) -> Self {
        Self::with_prf(nike, Prf::default())
    }

    pub fn with_prf(nike: Arc<dyn nike::Scheme>, prf: Prf) -> Self {
        Self { nike, prf }
    }

    pub fn nike(&self) -> &Arc<dyn nike::Scheme> {
        &self.nike
    }

    /// Encapsulates with a caller-chosen ephemeral key, which must be fresh.
    pub fn encapsulate_with_ephemeral(
        &self,
        public_key: &dyn super::PublicKey,
        ephemeral: &dyn nike::PrivateKey,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let pk: &PublicKey = downcast(public_key)?;
        let ct = ephemeral.public_key().to_bytes();
        let ss = self.derive(ephemeral, &*pk.0, &pk.0.to_bytes(), &ct)?;
        Ok((ct, ss))
    }

    fn derive(
        &self,
        sk: &dyn nike::PrivateKey,
        pk: &dyn nike::PublicKey,
        static_pk: &[u8],
        ephemeral_pk: &[u8],
    ) -> Result<SecretBytes> {
        let dh = self.nike.shared_secret(sk, pk)?;
        if ct_is_zero(&dh) {
            return Err(Error::LowOrderPoint);
        }
        self.prf
            .derive(&dh, static_pk, ephemeral_pk, self.shared_secret_size())
    }
}

#[derive(Debug)]
pub struct PublicKey(pub Box<dyn nike::PublicKey>);

#[derive(Debug)]
pub struct PrivateKey(pub Box<dyn nike::PrivateKey>);

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        self.0.to_bytes()
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey(self.0.public_key()))
    }
}

impl super::Scheme for NikeKem {
    fn name(&self) -> &str {
        self.nike.name()
    }

    fn public_key_size(&self) -> usize {
        self.nike.public_key_size()
    }

    fn private_key_size(&self) -> usize {
        self.nike.private_key_size()
    }

    fn ciphertext_size(&self) -> usize {
        self.nike.public_key_size()
    }

    /// The public key size, for compatibility with the Go implementation.
    fn shared_secret_size(&self) -> usize {
        self.nike.public_key_size()
    }

    fn seed_size(&self) -> usize {
        32
    }

    /// Seeds a BLAKE2Xb stream with `BLAKE2b-256(seed)` and generates the
    /// NIKE key from it.
    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        check_len(seed, 32)?;
        let mut xof = Blake2Xb::new(None, &[])?;
        xof.update(&Zeroizing::new(blake2b_256(&[], seed))[..]);
        Ok(Box::new(PrivateKey(
            self.nike.generate_key(&mut xof.finalize_xof()),
        )))
    }

    fn encapsulate(
        &self,
        public_key: &dyn super::PublicKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        self.encapsulate_with_ephemeral(public_key, &*self.nike.generate_key(rng))
    }

    fn decapsulate(
        &self,
        private_key: &dyn super::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        let ephemeral = self.nike.public_key_from_bytes(ciphertext)?;
        self.derive(
            &*sk.0,
            &*ephemeral,
            &sk.0.public_key().to_bytes(),
            ciphertext,
        )
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        Ok(Box::new(PublicKey(self.nike.public_key_from_bytes(bytes)?)))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        Ok(Box::new(PrivateKey(
            self.nike.private_key_from_bytes(bytes)?,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::*;
    use crate::nike::{hybrid::Hybrid, x448::X448, x25519::X25519};

    #[test]
    fn x25519() {
        super::super::check_scheme(&NikeKem::new(Arc::new(X25519)));
    }

    #[test]
    fn x448() {
        super::super::check_scheme(&NikeKem::new(Arc::new(X448)));
    }

    #[test]
    fn hybrid_nike() {
        let nike = Hybrid::new("X25519-X448", Arc::new(X25519), Arc::new(X448));
        super::super::check_scheme(&NikeKem::new(Arc::new(nike)));
    }

    #[test]
    fn sha256_prf() {
        super::super::check_scheme(&NikeKem::with_prf(Arc::new(X25519), Prf::Sha256V1));
        let kem = NikeKem::with_prf(Arc::new(X448), Prf::Sha256V1);
        let rng = &mut crate::util::rng();
        let pk = kem.generate_key(rng).public_key();
        assert!(matches!(
            kem.encapsulate(&*pk, rng),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn low_order_point() {
        let kem = NikeKem::new(Arc::new(X25519));
        let rng = &mut crate::util::rng();
        let sk = kem.generate_key(rng);
        assert_eq!(
            kem.decapsulate(&*sk, &[0; 32]).unwrap_err(),
            Error::LowOrderPoint
        );
        let zero = kem.public_key_from_bytes(&[0; 32]).unwrap();
        assert_eq!(
            kem.encapsulate(&*zero, rng).unwrap_err(),
            Error::LowOrderPoint
        );
    }

    #[test]
    fn foreign_key() {
        let rng = &mut crate::util::rng();
        let pk = NikeKem::new(Arc::new(X448)).generate_key(rng).public_key();
        let kem = NikeKem::new(Arc::new(X25519));
        assert_eq!(kem.encapsulate(&*pk, rng).unwrap_err(), Error::WrongKeyType);
    }
}
