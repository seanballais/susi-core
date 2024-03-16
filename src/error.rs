use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;
use std::path::PathBuf;
use std::string;
use std::sync::Arc;

use aead;
use argon2;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidNonceLengthError,
    InvalidPasswordLengthError,
    InvalidSSEFFile,
    InvalidSSEFFileIdentifierError,
    InvalidDirectoryError(String),
    LoggingError(String),
    TaskTerminatedError,
    UnsupportedSSEFFormatVersionError,
    AEADError(aead::Error),
    Argon2Error(argon2::Error),
    FromUTF8Error(string::FromUtf8Error),
    IOError(PathBuf, Arc<io::Error>),
}

pub type Result<T> = core::result::Result<T, Error>;

impl error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        match self {
            Self::InvalidNonceLengthError => {
                write!(f, "Nonce length is either too short or too long")
            }
            Self::InvalidPasswordLengthError => {
                write!(f, "Password must be more than 12 characters")
            }
            Self::InvalidSSEFFile => write!(f, "Invalid SSEF file"),
            Self::InvalidSSEFFileIdentifierError => write!(f, "Wrong file identifier"),
            Self::TaskTerminatedError => write!(f, "Task was stopped midway"),
            Self::InvalidDirectoryError(s) => write!(f, "{}", s),
            Self::LoggingError(s) => write!(f, "{}", s),
            Self::UnsupportedSSEFFormatVersionError => write!(f, "Format version is not supported"),
            Self::AEADError(e) => write!(f, "Error while using AEAD functions: {}", e),
            Self::Argon2Error(e) => write!(f, "Error while using Argon2 functions: {}", e),
            Self::FromUTF8Error(e) => write!(f, "Error while create string from bytes: {}", e),
            Self::IOError(p, e) => write!(
                f,
                "Error performing I/O operations on {}: {}",
                p.display(),
                e
            ),
        }
    }
}

impl From<aead::Error> for Error {
    fn from(e: aead::Error) -> Self {
        Self::AEADError(e)
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Self::Argon2Error(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Self {
        Self::FromUTF8Error(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IOError(PathBuf::new(), Arc::new(e))
    }
}
