use std::fmt;

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
            Error::InvalidInput(what) => write!(f, "invalid input: {what}"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
