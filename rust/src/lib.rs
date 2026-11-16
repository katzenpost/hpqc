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
//!
//! The crate is `no_std` with `alloc`. The default features keep the whole
//! crate; firmware takes only what it needs, e.g. `default-features = false,
//! features = ["bacap", "voucher"]`. Randomness always comes from the
//! caller's [`rand_core`] RNG.

#![no_std]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "bacap")]
pub mod bacap;
mod cbor;
pub mod error;
pub mod hash;
#[cfg(feature = "kem")]
pub mod kem;
pub mod nike;
pub mod protocols;
pub mod sign;
mod util;

/// The `alloc` names the std prelude would bring in.
mod prelude {
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::String;
    pub(crate) use alloc::vec::Vec;
    pub(crate) use alloc::{format, vec};
}
#[cfg(feature = "voucher")]
pub mod voucher;

pub use error::{Error, Result};
pub use rand_core;

/// Secret bytes, zeroed on drop.
pub type SecretBytes = zeroize::Zeroizing<alloc::vec::Vec<u8>>;

#[cfg(all(doctest, feature = "kem", feature = "bacap"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
