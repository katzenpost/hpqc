//! Ed25519 key blinding, as hpqc's Go `sign/ed25519/blinded25519.go`.
//!
//! A factor blinds a key by multiplying it with the clamped SHA-512/256 of
//! the factor, reduced mod the group order. A key blinded by the same
//! factors verifies signatures made by the private key blinded by them, in
//! any order. Signatures are standard Ed25519 under the blinded public key.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512, Sha512_256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

fn clamped(mut bytes: [u8; 32]) -> Scalar {
    bytes[0] &= 248;
    bytes[31] &= 63;
    bytes[31] |= 64;
    let s = Scalar::from_bytes_mod_order(bytes);
    bytes.zeroize();
    s
}

fn factor_scalar(factor: &[u8]) -> Result<Scalar> {
    if factor.is_empty() {
        return Err(Error::InvalidInput("empty blinding factor"));
    }
    Ok(clamped(Sha512_256::digest(factor).into()))
}

fn wide(digest: impl Into<[u8; 64]>) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&digest.into())
}

/// The public key blinded by `factor`.
pub fn blind_verifying_key(key: &VerifyingKey, factor: &[u8]) -> Result<VerifyingKey> {
    let point = CompressedEdwardsY(key.to_bytes())
        .decompress()
        .ok_or(Error::InvalidKey)?;
    let blinded = (factor_scalar(factor)? * point).compress();
    VerifyingKey::from_bytes(&blinded.to_bytes()).map_err(|_| Error::InvalidKey)
}

/// A private key blinded by one or more factors. Its scalar is zeroed on
/// drop.
#[derive(Clone)]
pub struct BlindedSigningKey {
    scalar: Scalar,
    verifying_key: VerifyingKey,
}

impl BlindedSigningKey {
    /// `key` blinded by `factor`.
    pub fn new(key: &SigningKey, factor: &[u8]) -> Result<Self> {
        let digest = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(key.to_bytes())));
        let unblinded = Self::from_scalar(clamped(digest[..32].try_into().expect("32 bytes")));
        unblinded.blind(factor)
    }

    fn from_scalar(scalar: Scalar) -> Self {
        let point = EdwardsPoint::mul_base(&scalar).compress();
        let verifying_key =
            VerifyingKey::from_bytes(&point.to_bytes()).expect("a multiple of the base point");
        Self {
            scalar,
            verifying_key,
        }
    }

    /// This key blinded further by `factor`.
    pub fn blind(&self, factor: &[u8]) -> Result<Self> {
        Ok(Self::from_scalar(factor_scalar(factor)? * self.scalar))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Signs `message` as Go's `BlindedPrivateKey.Sign` does, with the
    /// nonce derived from SHA-512 of the blinded scalar.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let secret = Zeroizing::new(self.scalar.to_bytes());
        let salt = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(secret.as_slice())));
        let mut r = wide(
            Sha512::new()
                .chain_update(&salt[32..])
                .chain_update(message)
                .chain_update(&salt[33..])
                .finalize(),
        );
        let big_r = EdwardsPoint::mul_base(&r).compress();
        let k = wide(
            Sha512::new()
                .chain_update(big_r.as_bytes())
                .chain_update(self.verifying_key.as_bytes())
                .chain_update(message)
                .finalize(),
        );
        let s = k * self.scalar + r;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(big_r.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        r.zeroize();
        Signature::from_bytes(&sig)
    }
}

impl Drop for BlindedSigningKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl std::fmt::Debug for BlindedSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlindedSigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}
