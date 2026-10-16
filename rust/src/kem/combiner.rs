//! Combines any number of KEMs into one.
//!
//! Keys and ciphertexts are the concatenation of the components'. The
//! shared secret is [`split_prf`] of the component secrets and
//! ciphertexts, which stays secure while any one component is.

use std::sync::Arc;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::Scheme;
use crate::hash::blake2b_256;
use crate::util::{downcast, split};
use crate::{Error, Result, SecretBytes};

/// The split PRF over `(shared_secret, ciphertext)` pairs.
///
/// With `msg = "splitprf-v1" || u32be(n) || for each ciphertext:
/// u32be(len) || ciphertext`, the output is the XOR over all components of
/// `BLAKE2b-256` keyed by `BLAKE2b-256(shared_secret)` applied to `msg`.
///
/// # Panics
/// If `parts` is empty or contains an empty secret or ciphertext.
pub fn split_prf(parts: &[(&[u8], &[u8])]) -> [u8; 32] {
    assert!(!parts.is_empty(), "split prf needs at least one input");
    let mut msg = b"splitprf-v1".to_vec();
    msg.extend_from_slice(&(parts.len() as u32).to_be_bytes());
    for (ss, ct) in parts {
        assert!(
            !ss.is_empty() && !ct.is_empty(),
            "split prf inputs cannot be empty"
        );
        msg.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        msg.extend_from_slice(ct);
    }
    let mut out = [0; 32];
    for (ss, _) in parts {
        let key = Zeroizing::new(blake2b_256(&[], ss));
        let h = Zeroizing::new(blake2b_256(&*key, &msg));
        out.iter_mut().zip(h.iter()).for_each(|(o, h)| *o ^= h);
    }
    out
}

pub struct Combiner {
    name: String,
    schemes: Vec<Arc<dyn Scheme>>,
}

impl Combiner {
    /// # Panics
    /// If `schemes` is empty.
    pub fn new(name: impl Into<String>, schemes: Vec<Arc<dyn Scheme>>) -> Self {
        assert!(!schemes.is_empty(), "combiner needs at least one KEM");
        Self {
            name: name.into(),
            schemes,
        }
    }

    pub fn schemes(&self) -> &[Arc<dyn Scheme>] {
        &self.schemes
    }

    fn sum(&self, size: impl Fn(&dyn Scheme) -> usize) -> usize {
        self.schemes.iter().map(|s| size(&**s)).sum()
    }

    fn sizes(&self, size: impl Fn(&dyn Scheme) -> usize) -> impl Iterator<Item = usize> {
        self.schemes.iter().map(move |s| size(&**s))
    }

    fn check_arity(&self, len: usize) -> Result<()> {
        if len == self.schemes.len() {
            Ok(())
        } else {
            Err(Error::WrongKeyType)
        }
    }
}

#[derive(Debug)]
pub struct PublicKey(pub Vec<Box<dyn super::PublicKey>>);

#[derive(Debug)]
pub struct PrivateKey(pub Vec<Box<dyn super::PrivateKey>>);

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|k| k.to_bytes()).collect()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        let mut out = Zeroizing::new(Vec::new());
        for key in &self.0 {
            out.extend_from_slice(&key.to_bytes());
        }
        out
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey(self.0.iter().map(|k| k.public_key()).collect()))
    }
}

impl Scheme for Combiner {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key_size(&self) -> usize {
        self.sum(|s| s.public_key_size())
    }

    fn private_key_size(&self) -> usize {
        self.sum(|s| s.private_key_size())
    }

    fn ciphertext_size(&self) -> usize {
        self.sum(|s| s.ciphertext_size())
    }

    fn shared_secret_size(&self) -> usize {
        32
    }

    fn seed_size(&self) -> usize {
        self.sum(|s| s.seed_size())
    }

    fn derive_key(&self, seed: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let seeds = split(seed, self.sizes(|s| s.seed_size()))?;
        let keys = self
            .schemes
            .iter()
            .zip(seeds)
            .map(|(s, seed)| s.derive_key(seed));
        Ok(Box::new(PrivateKey(keys.collect::<Result<_>>()?)))
    }

    fn encapsulate(
        &self,
        public_key: &dyn super::PublicKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let pk: &PublicKey = downcast(public_key)?;
        self.check_arity(pk.0.len())?;
        let outputs = self
            .schemes
            .iter()
            .zip(&pk.0)
            .map(|(s, k)| s.encapsulate(&**k, rng))
            .collect::<Result<Vec<_>>>()?;
        let parts: Vec<_> = outputs
            .iter()
            .map(|(ct, ss)| (ss.as_slice(), ct.as_slice()))
            .collect();
        let ss = Zeroizing::new(split_prf(&parts).to_vec());
        Ok((
            outputs
                .iter()
                .flat_map(|(ct, _)| ct.iter().copied())
                .collect(),
            ss,
        ))
    }

    fn decapsulate(
        &self,
        private_key: &dyn super::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        self.check_arity(sk.0.len())?;
        let cts = split(ciphertext, self.sizes(|s| s.ciphertext_size()))?;
        let secrets = self
            .schemes
            .iter()
            .zip(&sk.0)
            .zip(&cts)
            .map(|((s, k), ct)| s.decapsulate(&**k, ct))
            .collect::<Result<Vec<_>>>()?;
        let parts: Vec<_> = secrets
            .iter()
            .zip(&cts)
            .map(|(ss, ct)| (ss.as_slice(), *ct))
            .collect();
        Ok(Zeroizing::new(split_prf(&parts).to_vec()))
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        let parts = split(bytes, self.sizes(|s| s.public_key_size()))?;
        let keys = self
            .schemes
            .iter()
            .zip(parts)
            .map(|(s, b)| s.public_key_from_bytes(b));
        Ok(Box::new(PublicKey(keys.collect::<Result<_>>()?)))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        let parts = split(bytes, self.sizes(|s| s.private_key_size()))?;
        let keys = self
            .schemes
            .iter()
            .zip(parts)
            .map(|(s, b)| s.private_key_from_bytes(b));
        Ok(Box::new(PrivateKey(keys.collect::<Result<_>>()?)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{adapter::NikeKem, mlkem768::MlKem768};
    use super::*;
    use crate::nike::{x448::X448, x25519::X25519};

    fn x25519() -> Arc<dyn Scheme> {
        Arc::new(NikeKem::new(Arc::new(X25519)))
    }

    #[test]
    fn two_kems() {
        super::super::check_scheme(&Combiner::new(
            "MLKEM768-X25519",
            vec![x25519(), Arc::new(MlKem768)],
        ));
    }

    #[test]
    fn three_kems() {
        let x448 = Arc::new(NikeKem::new(Arc::new(X448)));
        let combiner = Combiner::new("three", vec![x25519(), Arc::new(MlKem768), x448]);
        assert_eq!(combiner.ciphertext_size(), 32 + 1088 + 56);
        super::super::check_scheme(&combiner);
    }

    #[test]
    fn nested() {
        let inner: Arc<dyn Scheme> =
            Arc::new(Combiner::new("inner", vec![x25519(), Arc::new(MlKem768)]));
        super::super::check_scheme(&Combiner::new("outer", vec![inner, x25519()]));
    }

    #[test]
    fn single_kem() {
        super::super::check_scheme(&Combiner::new("one", vec![x25519()]));
    }

    #[test]
    fn rejects_keys_of_other_arity() {
        let rng = &mut crate::util::rng();
        let two = Combiner::new("two", vec![x25519(), x25519()]);
        let one = Combiner::new("one", vec![x25519()]);
        let pk = one.generate_key(rng).public_key();
        assert_eq!(two.encapsulate(&*pk, rng).unwrap_err(), Error::WrongKeyType);
    }

    #[test]
    fn split_prf_depends_on_every_input() {
        let base = split_prf(&[(b"ss1", b"ct1"), (b"ss2", b"ct2")]);
        assert_ne!(base, split_prf(&[(b"ss1", b"ct1"), (b"ss2", b"ct3")]));
        assert_ne!(base, split_prf(&[(b"ss0", b"ct1"), (b"ss2", b"ct2")]));
        assert_ne!(base, split_prf(&[(b"ss2", b"ct2"), (b"ss1", b"ct1")]));
    }
}
