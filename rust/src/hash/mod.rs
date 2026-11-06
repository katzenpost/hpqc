//! Hash constructions shared by the schemes.

mod blake2xb;

pub use blake2xb::{Blake2Xb, Blake2XbReader};

use zeroize::Zeroizing;

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

const BLAKE2B_BLOCK: usize = 128;

/// HMAC over BLAKE2b with an `N`-byte digest, as Go's
/// `hmac.New(blake2b.NewN, key)`.
fn hmac_blake2b<const N: usize>(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let hasher = || {
        let mut params = blake2b_simd::Params::new();
        params.hash_length(N);
        params.to_state()
    };
    let mut block = Zeroizing::new([0u8; BLAKE2B_BLOCK]);
    if key.len() > BLAKE2B_BLOCK {
        block[..N].copy_from_slice(hasher().update(key).finalize().as_bytes());
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| {
        let mut p = Zeroizing::new([0u8; BLAKE2B_BLOCK]);
        for (p, k) in p.iter_mut().zip(block.iter()) {
            *p = k ^ byte;
        }
        p
    };
    let mut inner = hasher();
    inner.update(&*pad(0x36));
    for part in parts {
        inner.update(part);
    }
    let mut outer = hasher();
    outer.update(&*pad(0x5c));
    outer.update(inner.finalize().as_bytes());
    Zeroizing::new(
        outer
            .finalize()
            .as_bytes()
            .try_into()
            .expect("N-byte digest"),
    )
}

fn hkdf<const N: usize>(secret: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if out.len() > 255 * N {
        return Err(Error::InvalidInput("HKDF output longer than 255 blocks"));
    }
    let zeros = [0u8; N];
    let salt: &[u8] = if salt.is_empty() { &zeros } else { salt };
    let prk = hmac_blake2b::<N>(salt, &[secret]);
    let mut t = Zeroizing::new([0u8; N]);
    for (i, chunk) in out.chunks_mut(N).enumerate() {
        let prev: &[u8] = if i == 0 { &[] } else { &t[..] };
        let next = hmac_blake2b::<N>(&prk[..], &[prev, info, &[i as u8 + 1]]);
        *t = *next;
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    Ok(())
}

/// HKDF (RFC 5869) over BLAKE2b-512, as Go's
/// `hkdf.New(blake2b.New512, secret, salt, info)`. Fills `out`, which is at
/// most 255 * 64 bytes.
pub fn hkdf_blake2b(secret: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    hkdf::<64>(secret, salt, info, out)
}

/// HKDF (RFC 5869) over BLAKE2b-256, as Go's
/// `hkdf.New(blake2b.New256, secret, salt, info)`. Fills `out`, which is at
/// most 255 * 32 bytes.
pub fn hkdf_blake2b_256(secret: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    hkdf::<32>(secret, salt, info, out)
}
