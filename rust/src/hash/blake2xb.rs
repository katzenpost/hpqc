use blake2b_simd::{Params, State};
use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

use crate::{Error, Result};

const BLOCK: usize = 64;
const UNKNOWN_LENGTH: u32 = u32::MAX;

/// BLAKE2Xb, the extendable-output form of BLAKE2b, as implemented by Go's
/// `golang.org/x/crypto/blake2b.NewXOF`.
///
/// The output length is part of the parameter block, so streams of
/// different declared lengths differ entirely.
pub struct Blake2Xb {
    state: State,
    length: u32,
}

impl Blake2Xb {
    /// Starts a XOF of `length` output bytes, or of unbounded length when
    /// `length` is `None`. The key may be empty and at most 64 bytes.
    pub fn new(length: Option<u32>, key: &[u8]) -> Result<Self> {
        let length = match length {
            None => UNKNOWN_LENGTH,
            Some(0 | UNKNOWN_LENGTH) => return Err(Error::Unsupported("BLAKE2Xb output length")),
            Some(n) => n,
        };
        if key.len() > BLOCK {
            return Err(Error::InvalidLength {
                expected: BLOCK,
                actual: key.len(),
            });
        }
        let state = Params::new()
            .hash_length(BLOCK)
            .key(key)
            .node_offset(u64::from(length) << 32)
            .to_state();
        Ok(Self { state, length })
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.state.update(data);
        self
    }

    pub fn finalize_xof(self) -> Blake2XbReader {
        let mut root = [0; BLOCK];
        root.copy_from_slice(self.state.finalize().as_bytes());
        let total = match self.length {
            UNKNOWN_LENGTH => (1 << 32) * BLOCK as u64,
            n => u64::from(n),
        };
        Blake2XbReader {
            root,
            block: [0; BLOCK],
            length: self.length,
            total,
            remaining: total,
            offset: 0,
            node: 0,
        }
    }
}

/// The output stream of a [`Blake2Xb`]. It doubles as a deterministic
/// [`rand_core::TryCryptoRng`], for deriving keys from a seed.
pub struct Blake2XbReader {
    root: [u8; BLOCK],
    block: [u8; BLOCK],
    length: u32,
    total: u64,
    remaining: u64,
    offset: usize,
    node: u32,
}

impl Blake2XbReader {
    /// Fills `out` with the next bytes of output, failing without reading
    /// if `out` reaches past the declared output length.
    pub fn read(&mut self, mut out: &mut [u8]) -> Result<()> {
        if out.len() as u64 > self.remaining {
            return Err(Error::InvalidInput("read past end of BLAKE2Xb output"));
        }
        self.remaining -= out.len() as u64;
        while !out.is_empty() {
            if self.offset == 0 {
                self.next_block();
            }
            let n = out.len().min(BLOCK - self.offset);
            let (head, tail) = std::mem::take(&mut out).split_at_mut(n);
            head.copy_from_slice(&self.block[self.offset..self.offset + n]);
            self.offset = (self.offset + n) % BLOCK;
            out = tail;
        }
        Ok(())
    }

    fn next_block(&mut self) {
        let len = (self.total - u64::from(self.node) * BLOCK as u64).min(BLOCK as u64) as usize;
        let hash = Params::new()
            .hash_length(len)
            .fanout(0)
            .max_depth(0)
            .max_leaf_length(BLOCK as u32)
            .node_offset(u64::from(self.length) << 32 | u64::from(self.node))
            .inner_hash_length(BLOCK)
            .hash(&self.root);
        self.block[..len].copy_from_slice(hash.as_bytes());
        self.node = self.node.wrapping_add(1);
    }
}

impl Drop for Blake2XbReader {
    fn drop(&mut self) {
        self.root.zeroize();
        self.block.zeroize();
    }
}

impl TryRng for Blake2XbReader {
    type Error = Error;

    fn try_next_u32(&mut self) -> Result<u32> {
        let mut b = [0; 4];
        self.read(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64> {
        let mut b = [0; 8];
        self.read(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        self.read(dst)
    }
}

impl TryCryptoRng for Blake2XbReader {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_reads_match_one_read() {
        let xof = || {
            let mut x = Blake2Xb::new(Some(200), b"key").unwrap();
            x.update(b"hello");
            x.finalize_xof()
        };
        let mut whole = [0; 200];
        xof().read(&mut whole).unwrap();

        let mut chunked = [0; 200];
        let mut reader = xof();
        let mut start = 0;
        for len in [1, 63, 64, 5, 67] {
            reader.read(&mut chunked[start..start + len]).unwrap();
            start += len;
        }
        assert_eq!(whole, chunked);
    }

    #[test]
    fn reading_past_the_end_fails() {
        let mut reader = Blake2Xb::new(Some(10), &[]).unwrap().finalize_xof();
        assert!(matches!(
            reader.read(&mut [0; 11]),
            Err(Error::InvalidInput(_))
        ));
        let mut out = [0; 10];
        reader.read(&mut out).unwrap();
        assert!(reader.read(&mut [0; 1]).is_err());
    }

    #[test]
    fn rejects_long_key() {
        assert!(Blake2Xb::new(None, &[0; 65]).is_err());
    }
}
