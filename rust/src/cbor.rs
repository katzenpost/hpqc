//! The CBOR subset the voucher and MKEM messages use: byte and text
//! strings, arrays, maps and null. Encoding is canonical (RFC 7049 section
//! 3.9: shortest lengths, map keys sorted length-first then bytewise), as
//! Go's `cbor.CanonicalEncOptions` and Python's `cbor2` `canonical=True`
//! produce.

use crate::prelude::*;
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
    Null,
}

const MALFORMED: Error = Error::InvalidInput("malformed CBOR");
/// Nesting deeper than any message here is rejected.
const MAX_DEPTH: usize = 8;

fn head(out: &mut Vec<u8>, major: u8, n: usize) {
    let major = major << 5;
    let n = n as u64;
    match n {
        0..24 => out.push(major | n as u8),
        24..0x100 => out.extend([major | 24, n as u8]),
        0x100..0x1_0000 => {
            out.push(major | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..0x1_0000_0000 => {
            out.push(major | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend(n.to_be_bytes());
        }
    }
}

impl Value {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Bytes(b) => {
                head(out, 2, b.len());
                out.extend_from_slice(b);
            }
            Value::Text(t) => {
                head(out, 3, t.len());
                out.extend_from_slice(t.as_bytes());
            }
            Value::Array(items) => {
                head(out, 4, items.len());
                items.iter().for_each(|v| v.encode(out));
            }
            Value::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (Value::Text(k.clone()).to_bytes(), v.to_bytes()))
                    .collect();
                encoded.sort_by(|a, b| (a.0.len(), &a.0).cmp(&(b.0.len(), &b.0)));
                head(out, 5, encoded.len());
                for (k, v) in encoded {
                    out.extend(k);
                    out.extend(v);
                }
            }
            Value::Null => out.push(0xf6),
        }
    }

    /// Decodes one item that must span all of `bytes`.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut rest = bytes;
        let value = decode(&mut rest, 0)?;
        if !rest.is_empty() {
            return Err(MALFORMED);
        }
        Ok(value)
    }

    /// A byte string; null reads as empty, as Go decodes it into a nil slice.
    pub(crate) fn into_bytes(self) -> Result<Vec<u8>> {
        match self {
            Value::Bytes(b) => Ok(b),
            Value::Null => Ok(Vec::new()),
            _ => Err(MALFORMED),
        }
    }

    pub(crate) fn into_text(self) -> Result<String> {
        match self {
            Value::Text(t) => Ok(t),
            _ => Err(MALFORMED),
        }
    }

    /// An array of exactly `N` items.
    #[cfg(feature = "voucher")]
    pub(crate) fn into_array<const N: usize>(self) -> Result<[Value; N]> {
        match self {
            Value::Array(items) => items.try_into().map_err(|_| MALFORMED),
            _ => Err(MALFORMED),
        }
    }

    /// The values of a map's `keys`, in that order. Other keys are ignored,
    /// as Go ignores unknown struct fields.
    pub(crate) fn into_fields<const N: usize>(self, keys: [&str; N]) -> Result<[Value; N]> {
        let Value::Map(mut entries) = self else {
            return Err(MALFORMED);
        };
        let mut take = |key: &str| {
            let i = entries
                .iter()
                .position(|(k, _)| k == key)
                .ok_or(MALFORMED)?;
            Ok(entries.swap_remove(i).1)
        };
        let values: Vec<Value> = keys.iter().map(|k| take(k)).collect::<Result<_>>()?;
        Ok(values.try_into().expect("N values"))
    }
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if rest.len() < n {
        return Err(MALFORMED);
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn decode(rest: &mut &[u8], depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(MALFORMED);
    }
    let first = take(rest, 1)?[0];
    let (major, info) = (first >> 5, first & 0x1f);
    if first == 0xf6 {
        return Ok(Value::Null);
    }
    let n = match info {
        0..24 => info as u64,
        24..28 => {
            let width = 1 << (info - 24);
            take(rest, width)?
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | b as u64)
        }
        _ => return Err(MALFORMED),
    };
    // Every item takes at least one byte, so a longer count cannot fit.
    let n = usize::try_from(n)
        .ok()
        .filter(|&n| n <= rest.len())
        .ok_or(MALFORMED)?;
    match major {
        2 => Ok(Value::Bytes(take(rest, n)?.to_vec())),
        3 => String::from_utf8(take(rest, n)?.to_vec())
            .map(Value::Text)
            .map_err(|_| MALFORMED),
        4 => (0..n)
            .map(|_| decode(rest, depth + 1))
            .collect::<Result<_>>()
            .map(Value::Array),
        5 => (0..n)
            .map(|_| {
                Ok((
                    decode(rest, depth + 1)?.into_text()?,
                    decode(rest, depth + 1)?,
                ))
            })
            .collect::<Result<_>>()
            .map(Value::Map),
        _ => Err(MALFORMED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_canonical_order() {
        let v = Value::Map(vec![
            ("Signature".into(), Value::Bytes(vec![1; 300])),
            ("PleaseAdd".into(), Value::Text("hi".into())),
            ("A".into(), Value::Array(vec![Value::Null])),
        ]);
        let bytes = v.to_bytes();
        assert_eq!(&bytes[..4], &[0xa3, 0x61, b'A', 0x81]);
        let [a, p, s] = Value::from_bytes(&bytes)
            .unwrap()
            .into_fields(["A", "PleaseAdd", "Signature"])
            .unwrap();
        assert_eq!(a, Value::Array(vec![Value::Null]));
        assert_eq!(p.into_text().unwrap(), "hi");
        assert_eq!(s.into_bytes().unwrap(), vec![1; 300]);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            &[][..],
            &[0x42, 1],
            &[0x40, 0],
            &[0x5f],
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(Value::from_bytes(bad).is_err(), "{bad:?}");
        }
    }
}
