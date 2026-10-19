//! X448 (RFC 7748), wrapping the `x448` crate.

use rand_core::CryptoRng;
use x448::{X448_BASEPOINT_BYTES, x448_unchecked};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::util::{ct_is_zero, downcast, to_array};
use crate::{Error, Result, SecretBytes};

#[derive(Clone, Copy, Debug, Default)]
pub struct X448;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 56]);

/// Holds the unclamped scalar; clamping happens at use. (The `x448`
/// crate's `StaticSecret` clamps on load, which would change the encoding.)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub [u8; 56]);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("x448::PrivateKey").finish_non_exhaustive()
    }
}

impl super::PublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl super::PrivateKey for PrivateKey {
    fn to_bytes(&self) -> SecretBytes {
        Zeroizing::new(self.0.to_vec())
    }

    fn public_key(&self) -> Box<dyn super::PublicKey> {
        Box::new(PublicKey(x448_unchecked(self.0, X448_BASEPOINT_BYTES)))
    }
}

impl super::Scheme for X448 {
    fn name(&self) -> &str {
        "x448"
    }

    fn public_key_size(&self) -> usize {
        56
    }

    fn private_key_size(&self) -> usize {
        56
    }

    fn generate_key(&self, rng: &mut dyn CryptoRng) -> Box<dyn super::PrivateKey> {
        let mut sk = PrivateKey([0; 56]);
        rng.fill_bytes(&mut sk.0);
        Box::new(sk)
    }

    fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PublicKey>> {
        Ok(Box::new(PublicKey(to_array(bytes)?)))
    }

    fn private_key_from_bytes(&self, bytes: &[u8]) -> Result<Box<dyn super::PrivateKey>> {
        Ok(Box::new(PrivateKey(to_array(bytes)?)))
    }

    fn shared_secret(
        &self,
        private_key: &dyn super::PrivateKey,
        public_key: &dyn super::PublicKey,
    ) -> Result<SecretBytes> {
        let sk: &PrivateKey = downcast(private_key)?;
        let pk: &PublicKey = downcast(public_key)?;
        Ok(Zeroizing::new(dh(sk, pk)?.to_vec()))
    }

    fn blind(
        &self,
        public_key: &dyn super::PublicKey,
        factor: &dyn super::PrivateKey,
    ) -> Result<Box<dyn super::PublicKey>> {
        let pk: &PublicKey = downcast(public_key)?;
        let factor: &PrivateKey = downcast(factor)?;
        Ok(Box::new(PublicKey(*dh(factor, pk)?)))
    }
}

/// Checks the output rather than using `x448::x448`, whose low-order check
/// misses non-canonical encodings such as `p`.
fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<Zeroizing<[u8; 56]>> {
    let out = Zeroizing::new(x448_unchecked(sk.0, pk.0));
    if ct_is_zero(&*out) {
        Err(Error::LowOrderPoint)
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::*;

    #[test]
    fn scheme() {
        super::super::check_scheme(&X448);
    }

    #[test]
    fn rfc7748_vector() {
        let sk = hex::decode(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c\
             984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let pk = hex::decode(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031\
             ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        let sk = X448.private_key_from_bytes(&sk.unwrap()).unwrap();
        let pk = X448.public_key_from_bytes(&pk.unwrap()).unwrap();
        assert_eq!(
            hex::encode(&*X448.shared_secret(&*sk, &*pk).unwrap()),
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaad\
             eb445fc66a01b0779d98223961111e21766282f73dd96b6f"
        );
    }

    #[test]
    fn low_order_points() {
        let sk = X448.generate_key(&mut crate::util::rng());
        let mut p = [0xff; 56];
        p[28] = 0xfe;
        let mut p_minus_one = p;
        p_minus_one[0] = 0xfe;
        let mut one = [0; 56];
        one[0] = 1;
        let mut p_plus_one = [0xff; 56];
        p_plus_one[..28].fill(0);
        assert!(x448::x448([1; 56], p).is_some(), "x448 crate misses p");
        for point in [[0; 56], one, p_minus_one, p, p_plus_one] {
            let pk = X448.public_key_from_bytes(&point).unwrap();
            assert_eq!(
                X448.shared_secret(&*sk, &*pk).unwrap_err(),
                Error::LowOrderPoint
            );
            assert_eq!(X448.blind(&*pk, &*sk).unwrap_err(), Error::LowOrderPoint);
        }
    }
}
