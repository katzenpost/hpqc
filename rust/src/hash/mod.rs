//! Hash constructions shared by the schemes.

mod blake2xb;

pub use blake2xb::{Blake2Xb, Blake2XbReader};

/// BLAKE2b-256, keyed when `key` is non-empty.
pub fn blake2b_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(key)
        .hash(data);
    hash.as_bytes().try_into().expect("32-byte digest")
}
