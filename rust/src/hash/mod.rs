//! Hash constructions shared by the schemes.

mod blake2xb;

pub use blake2xb::{Blake2Xb, Blake2XbReader};

use crate::{Error, Result};

/// BLAKE2b-256, keyed when `key` is non-empty. The key is at most 64 bytes.
pub fn blake2b_256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    if key.len() > 64 {
        return Err(Error::InvalidLength {
            expected: 64,
            actual: key.len(),
        });
    }
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(key)
        .hash(data);
    Ok(hash.as_bytes().try_into().expect("32-byte digest"))
}
