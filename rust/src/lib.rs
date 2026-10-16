//! Hybrid post-quantum cryptography.
//!
//! [`kem`], [`nike`] and [`sign`] each define an object-safe `Scheme` trait
//! together with traits for its public and private keys. Schemes are used as
//! `Arc<dyn Scheme>`, so they compose freely at runtime: a NIKE becomes a KEM
//! through [`kem::adapter`], any number of KEMs merge through
//! [`kem::combiner`], and NIKEs and signature schemes pair up through their
//! `hybrid` modules. Each family has a registry that maps names to schemes.
//!
//! Encodings are byte compatible with the Go reference implementation,
//! `github.com/katzenpost/hpqc`.

pub mod error;
pub mod hash;
pub mod kem;
pub mod nike;
pub mod sign;
mod util;

pub use error::{Error, Result};
pub use rand_core;

/// Secret bytes, zeroed on drop.
pub type SecretBytes = zeroize::Zeroizing<Vec<u8>>;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
