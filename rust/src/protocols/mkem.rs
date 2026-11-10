//! Multi-recipient public-key encryption over any NIKE, byte compatible
//! with hpqc's Go `protocols/mkem`.
//!
//! One ephemeral key pair serves every recipient. The payload is sealed
//! under a random message key, and the message key is sealed once per
//! recipient under the BLAKE2b-256 of the NIKE shared secret with that
//! recipient. Every seal is ChaCha20-Poly1305 with a random nonce written in
//! front of its ciphertext.

use alloc::sync::Arc;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::hash::blake2b_256;
use crate::nike::{PrivateKey, PublicKey, Scheme};
use crate::prelude::*;
use crate::util::ct_is_zero;
use crate::{Error, Result};

const NONCE_SIZE: usize = 12;

/// An MKEM over one NIKE.
#[derive(Clone)]
pub struct Mkem {
    nike: Arc<dyn Scheme>,
}

/// An MKEM ciphertext: the ephemeral public key, the message key sealed to
/// each recipient, and the sealed payload. Encodes as the canonical CBOR
/// map Go's `Ciphertext.Marshal` writes.
#[derive(Debug)]
pub struct Ciphertext {
    pub ephemeral_public_key: Box<dyn PublicKey>,
    pub dek_ciphertexts: Vec<Vec<u8>>,
    pub envelope: Vec<u8>,
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        Value::Map(vec![
            (
                "EphemeralPublicKey".into(),
                Value::Bytes(self.ephemeral_public_key.to_bytes()),
            ),
            (
                "DEKCiphertexts".into(),
                Value::Array(
                    self.dek_ciphertexts
                        .iter()
                        .cloned()
                        .map(Value::Bytes)
                        .collect(),
                ),
            ),
            ("Envelope".into(), Value::Bytes(self.envelope.clone())),
        ])
        .to_bytes()
    }

    /// Decodes a ciphertext whose ephemeral key belongs to `mkem`'s NIKE.
    pub fn from_bytes(mkem: &Mkem, bytes: &[u8]) -> Result<Self> {
        let [eph, deks, envelope] = Value::from_bytes(bytes)?.into_fields([
            "EphemeralPublicKey",
            "DEKCiphertexts",
            "Envelope",
        ])?;
        let dek_ciphertexts = match deks {
            Value::Array(items) => items
                .into_iter()
                .map(Value::into_bytes)
                .collect::<Result<_>>()?,
            Value::Null => Vec::new(),
            _ => return Err(Error::InvalidInput("malformed CBOR")),
        };
        Ok(Self {
            ephemeral_public_key: mkem.nike.public_key_from_bytes(&eph.into_bytes()?)?,
            dek_ciphertexts,
            envelope: envelope.into_bytes()?,
        })
    }
}

fn seal(key: &[u8; 32], plaintext: &[u8], rng: &mut dyn CryptoRng) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    let sealed = ChaCha20Poly1305::new(key.into())
        .encrypt(&nonce.into(), plaintext)
        .expect("ChaCha20-Poly1305 seals any length that fits in memory");
    [&nonce[..], &sealed].concat()
}

fn open(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (nonce, sealed) = ciphertext
        .split_at_checked(NONCE_SIZE)
        .ok_or(Error::DecryptionFailed)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::DecryptionFailed)?;
    cipher
        .decrypt(nonce.try_into().expect("12-byte nonce"), sealed)
        .map_err(|_| Error::DecryptionFailed)
}

impl Mkem {
    pub fn new(nike: Arc<dyn Scheme>) -> Self {
        Self { nike }
    }

    fn secret(
        &self,
        private_key: &dyn PrivateKey,
        public_key: &dyn PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let raw = self.nike.shared_secret(private_key, public_key)?;
        if ct_is_zero(&raw) {
            return Err(Error::LowOrderPoint);
        }
        Ok(Zeroizing::new(blake2b_256(&[], &raw)?))
    }

    /// Seals `payload` to every key in `recipients`. Randomness is drawn
    /// from `rng` in the order Go's `EncapsulateWithEntropy` reads it, so the
    /// same random bytes give the same ciphertext. Returns the ephemeral
    /// private key with the ciphertext.
    pub fn encapsulate(
        &self,
        recipients: &[&dyn PublicKey],
        payload: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<(Box<dyn PrivateKey>, Ciphertext)> {
        let ephemeral = self.nike.generate_key(rng);
        let secrets = recipients
            .iter()
            .map(|pk| self.secret(&*ephemeral, *pk))
            .collect::<Result<Vec<_>>>()?;
        let mut msg_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *msg_key);
        let envelope = seal(&msg_key, payload, rng);
        let dek_ciphertexts = secrets.iter().map(|s| seal(s, &*msg_key, rng)).collect();
        let ciphertext = Ciphertext {
            ephemeral_public_key: ephemeral.public_key(),
            dek_ciphertexts,
            envelope,
        };
        Ok((ephemeral, ciphertext))
    }

    /// Opens `ciphertext` with one recipient's private key, trying each
    /// sealed message key in turn.
    pub fn decapsulate(
        &self,
        private_key: &dyn PrivateKey,
        ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>> {
        let secret = self.secret(private_key, &*ciphertext.ephemeral_public_key)?;
        let msg_key = ciphertext
            .dek_ciphertexts
            .iter()
            .find_map(|dek| open(&*secret, dek).ok())
            .map(Zeroizing::new)
            .ok_or(Error::DecryptionFailed)?;
        open(&msg_key, &ciphertext.envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nike::schemes::by_name;

    #[test]
    fn round_trip() {
        let rng = &mut crate::util::rng();
        let mkem = Mkem::new(by_name("x25519").unwrap());
        let keys: Vec<_> = (0..3).map(|_| mkem.nike.generate_key(rng)).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let pub_refs: Vec<&dyn PublicKey> = pubs.iter().map(|p| &**p).collect();
        let (_, ct) = mkem.encapsulate(&pub_refs, b"hello", rng).unwrap();
        let ct = Ciphertext::from_bytes(&mkem, &ct.to_bytes()).unwrap();
        for k in &keys {
            assert_eq!(mkem.decapsulate(&**k, &ct).unwrap(), b"hello");
        }
        let stranger = mkem.nike.generate_key(rng);
        assert_eq!(
            mkem.decapsulate(&*stranger, &ct).unwrap_err(),
            Error::DecryptionFailed
        );
    }
}
