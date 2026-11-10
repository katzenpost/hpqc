use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key was passed to a scheme it does not belong to.
    WrongKeyType,
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    InvalidKey,
    /// A Diffie-Hellman operation produced the all-zero output.
    LowOrderPoint,
    InvalidSignature,
    /// AEAD authentication failed.
    DecryptionFailed,
    /// A BACAP index is not on the capability's stream.
    IndexNotInStream,
    /// A BACAP index is further ahead of the capability's own index than
    /// the on-stream check walks.
    IndexTooFar,
    /// An all-zero BACAP box ID.
    EmptyBox,
    /// A BACAP box is not the one the capability and index derive.
    BoxMismatch,
    /// A voucher payload does not hash to the voucher.
    VoucherMismatch,
    InvalidInput(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongKeyType => f.write_str("key belongs to a different scheme"),
            Error::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected} bytes, got {actual}")
            }
            Error::InvalidKey => f.write_str("invalid key"),
            Error::LowOrderPoint => f.write_str("low order point"),
            Error::InvalidSignature => f.write_str("invalid signature"),
            Error::DecryptionFailed => f.write_str("decryption failed"),
            Error::IndexNotInStream => f.write_str("index is not on this capability's stream"),
            Error::IndexTooFar => f.write_str("index is too far ahead to check"),
            Error::EmptyBox => f.write_str("empty box, no message received"),
            Error::BoxMismatch => f.write_str("box is not the one the capability and index derive"),
            Error::VoucherMismatch => f.write_str("payload does not hash to the voucher"),
            Error::InvalidInput(what) => write!(f, "invalid input: {what}"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
