//! Anonymous public-key encryption to one recipient over any NIKE, byte
//! compatible with hpqc's Go `protocols/sealedbox`.
//!
//! A box is a fresh ephemeral public key followed by the XSalsa20-Poly1305
//! secretbox of the plaintext. The key and nonce come from
//! HKDF-BLAKE2b-256 over the NIKE shared secret, with no salt and the info
//! `"hpqc-nike-sealedbox-v1" || u16be(len(name)) || name || ephemeral
//! public key || recipient public key`, where `name` is the NIKE's name.

use std::sync::Arc;

use crypto_secretbox::aead::Aead;
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::hash::hkdf_blake2b_256;
use crate::nike::{PrivateKey, PublicKey, Scheme};
use crate::util::ct_is_zero;
use crate::{Error, Result};

const KDF_LABEL: &[u8] = b"hpqc-nike-sealedbox-v1";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;

/// A sealed box over one NIKE.
#[derive(Clone)]
pub struct SealedBox {
    nike: Arc<dyn Scheme>,
}

impl SealedBox {
    pub fn new(nike: Arc<dyn Scheme>) -> Self {
        Self { nike }
    }

    /// `sealedbox-` followed by the NIKE's name.
    pub fn name(&self) -> String {
        format!("sealedbox-{}", self.nike.name())
    }

    /// How many bytes a box adds to its plaintext.
    pub fn overhead(&self) -> usize {
        self.nike.public_key_size() + TAG_SIZE
    }

    /// Seals `plaintext` to `recipient`, drawing the ephemeral key from
    /// `rng`. The same random bytes give the same box as Go's
    /// `SealWithEntropy`.
    pub fn seal(
        &self,
        recipient: &dyn PublicKey,
        plaintext: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>> {
        let ephemeral = self.nike.generate_key(rng);
        let mut out = ephemeral.public_key().to_bytes();
        let (cipher, nonce) = self.cipher(&*ephemeral, recipient, &out, &recipient.to_bytes())?;
        let sealed = cipher
            .encrypt(&nonce.into(), plaintext)
            .map_err(|_| Error::InvalidInput("plaintext too long"))?;
        out.extend(sealed);
        Ok(out)
    }

    /// Opens a box sealed to `public_key`, the public half of
    /// `private_key`. Every failure is [`Error::DecryptionFailed`].
    pub fn open(
        &self,
        private_key: &dyn PrivateKey,
        public_key: &dyn PublicKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let pk_size = self.nike.public_key_size();
        if ciphertext.len() < pk_size + TAG_SIZE {
            return Err(Error::DecryptionFailed);
        }
        let (eph_bytes, sealed) = ciphertext.split_at(pk_size);
        let open = || {
            let ephemeral = self.nike.public_key_from_bytes(eph_bytes)?;
            let (cipher, nonce) =
                self.cipher(private_key, &*ephemeral, eph_bytes, &public_key.to_bytes())?;
            cipher
                .decrypt(&nonce.into(), sealed)
                .map_err(|_| Error::DecryptionFailed)
        };
        open().map_err(|_| Error::DecryptionFailed)
    }

    fn cipher(
        &self,
        private_key: &dyn PrivateKey,
        public_key: &dyn PublicKey,
        eph_pub: &[u8],
        recipient_pub: &[u8],
    ) -> Result<(XSalsa20Poly1305, [u8; NONCE_SIZE])> {
        let secret = self.nike.shared_secret(private_key, public_key)?;
        if ct_is_zero(&secret) {
            return Err(Error::LowOrderPoint);
        }
        let name = self.nike.name().as_bytes();
        let name_len =
            u16::try_from(name.len()).map_err(|_| Error::InvalidInput("NIKE name too long"))?;
        let info = [
            KDF_LABEL,
            &name_len.to_be_bytes(),
            name,
            eph_pub,
            recipient_pub,
        ]
        .concat();
        let mut okm = Zeroizing::new([0u8; KEY_SIZE + NONCE_SIZE]);
        hkdf_blake2b_256(&secret, &[], &info, &mut *okm)?;
        let cipher = XSalsa20Poly1305::new_from_slice(&okm[..KEY_SIZE]).expect("32-byte key");
        Ok((cipher, okm[KEY_SIZE..].try_into().expect("24-byte nonce")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nike::schemes::by_name;

    #[test]
    fn round_trip() {
        let rng = &mut crate::util::rng();
        let sb = SealedBox::new(by_name("x25519").unwrap());
        let sk = sb.nike.generate_key(rng);
        for size in [0, 1, 1500] {
            let ct = sb.seal(&*sk.public_key(), &vec![7; size], rng).unwrap();
            assert_eq!(ct.len(), size + sb.overhead());
            assert_eq!(
                sb.open(&*sk, &*sk.public_key(), &ct).unwrap(),
                vec![7; size]
            );
            let mut bad = ct.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(
                sb.open(&*sk, &*sk.public_key(), &bad).unwrap_err(),
                Error::DecryptionFailed
            );
        }
        assert_eq!(sb.name(), "sealedbox-x25519");
    }
}
