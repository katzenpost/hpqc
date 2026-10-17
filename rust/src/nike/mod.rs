//! Non-interactive key exchange.

pub mod hybrid;
pub mod schemes;
pub mod x25519;
pub mod x448;

use std::any::Any;
use std::fmt::Debug;

use rand_core::CryptoRng;

use crate::{Result, SecretBytes};

pub trait PublicKey: Any + Debug + Send + Sync {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait PrivateKey: Any + Debug + Send + Sync {
    fn to_bytes(&self) -> SecretBytes;

    fn public_key(&self) -> Box<dyn PublicKey>;
}

pub trait Scheme: Send + Sync {
    fn name(&self) -> &str;

    fn public_key_size(&self) -> usize;

    fn private_key_size(&self) -> usize;

    fn generate_key(&self, rng: &mut dyn CryptoRng) -> Box<dyn PrivateKey>;

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn PublicKey>>;

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn PrivateKey>>;

    /// Computes the shared secret, failing with
    /// [`LowOrderPoint`](crate::Error::LowOrderPoint) when a low-order
    /// public key would make it all zeros.
    fn shared_secret(
        &self,
        private_key: &dyn PrivateKey,
        public_key: &dyn PublicKey,
    ) -> Result<SecretBytes>;

    /// Blinds `public_key` by `factor`, so that `blind(pk(a), b)` agrees
    /// with `blind(pk(b), a)` under `shared_secret`.
    fn blind(
        &self,
        public_key: &dyn PublicKey,
        factor: &dyn PrivateKey,
    ) -> Result<Box<dyn PublicKey>>;
}

#[cfg(test)]
pub(crate) fn check_scheme(scheme: &dyn Scheme) {
    let rng = &mut crate::util::rng();
    let alice = scheme.generate_key(rng);
    let bob = scheme.generate_key(rng);
    assert_eq!(
        alice.public_key().to_bytes().len(),
        scheme.public_key_size()
    );
    assert_eq!(alice.to_bytes().len(), scheme.private_key_size());

    let ab = scheme.shared_secret(&*alice, &*bob.public_key()).unwrap();
    let ba = scheme.shared_secret(&*bob, &*alice.public_key()).unwrap();
    assert_eq!(ab, ba);
    assert!(!crate::util::ct_is_zero(&ab));

    let pk = scheme
        .public_key_from_bytes(&alice.public_key().to_bytes())
        .unwrap();
    assert_eq!(pk.to_bytes(), alice.public_key().to_bytes());
    let sk = scheme.private_key_from_bytes(&alice.to_bytes()).unwrap();
    assert_eq!(sk.to_bytes(), alice.to_bytes());
    assert!(scheme.public_key_from_bytes(&[0; 3]).is_err());
    assert!(scheme.private_key_from_bytes(&[0; 3]).is_err());

    let factor = scheme.generate_key(rng);
    let blinded_alice = scheme.blind(&*alice.public_key(), &*factor).unwrap();
    let blinded_bob = scheme.blind(&*bob.public_key(), &*factor).unwrap();
    assert_eq!(
        scheme.shared_secret(&*bob, &*blinded_alice).unwrap(),
        scheme.shared_secret(&*alice, &*blinded_bob).unwrap(),
    );
}
