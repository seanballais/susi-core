use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;
use std::sync::Arc;

use aead;
use argon2;

#[derive(Debug, Clone)]
pub enum Error {
    EmptyFileError,
    InvalidPasswordLengthError,
    Argon2Error(argon2::Error),
    IOError(Arc<io::Error>),
    AEADError(aead::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

impl error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        match self {
            Self::EmptyFileError => write!(f, "File is empty"),
            Self::InvalidPasswordLengthError => {
                write!(f, "Password must be more than 12 characters")
            }
            Self::Argon2Error(e) => write!(f, "Error while using Argon2 functions: {}", e),
            Self::IOError(e) => write!(f, "Error performing I/O operations: {}", e),
            Self::AEADError(e) => write!(f, "Error while using AEAD functions: {}", e),
        }
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Self::Argon2Error(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IOError(Arc::new(e))
    }
}

impl From<aead::Error> for Error {
    fn from(e: aead::Error) -> Self {
        Self::AEADError(e)
    }
}
