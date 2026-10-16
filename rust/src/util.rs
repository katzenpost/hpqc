use std::any::Any;

use subtle::ConstantTimeEq;

use crate::{Error, Result};

pub(crate) fn downcast<T: Any>(key: &dyn Any) -> Result<&T> {
    key.downcast_ref().ok_or(Error::WrongKeyType)
}

pub(crate) fn check_len(bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            expected,
            actual: bytes.len(),
        })
    }
}

pub(crate) fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    check_len(bytes, N)?;
    Ok(bytes.try_into().expect("length checked"))
}

/// Splits `bytes` into consecutive pieces of the given sizes, which must
/// add up to its length.
pub(crate) fn split(bytes: &[u8], sizes: impl IntoIterator<Item = usize>) -> Result<Vec<&[u8]>> {
    let sizes: Vec<usize> = sizes.into_iter().collect();
    check_len(bytes, sizes.iter().sum())?;
    let mut rest = bytes;
    Ok(sizes
        .into_iter()
        .map(|n| {
            let (head, tail) = rest.split_at(n);
            rest = tail;
            head
        })
        .collect())
}

pub(crate) fn ct_is_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0, |acc, b| acc | b).ct_eq(&0).into()
}

#[cfg(test)]
pub(crate) fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}
