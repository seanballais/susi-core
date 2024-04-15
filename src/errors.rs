use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};
use std::string;
use std::sync::Arc;

use aead;
use argon2;

#[derive(Debug, Clone)]
pub struct Copy {
    src_file_path: PathBuf,
    dest_file_path: PathBuf,
    message: String
}

impl Copy {
    pub fn new<P: AsRef<Path>, S: AsRef<str>>(src_file_path: P, dest_file_path: P, message: S) -> Self {
        Self {
            src_file_path: PathBuf::from(src_file_path.as_ref()),
            dest_file_path: PathBuf::from(dest_file_path.as_ref()),
            message: String::from(message.as_ref())
        }
    }
}

#[derive(Debug, Clone)]
pub struct IO {
    path: PathBuf,
    error: Arc<io::Error>
}

impl IO {
    pub fn new<P: AsRef<Path>>(path: P, e: Arc<io::Error>) -> Self {
        Self {
            path: PathBuf::from(path.as_ref()),
            error: e
        }
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    None, // Only use this as a default value.
    Copy(Copy),
    InvalidNonceLength,
    InvalidPasswordLength,
    InvalidSSEFFile,
    InvalidSSEFFileIdentifier,
    InvalidDirectory(String),
    Logging(String),
    TaskTerminated,
    UnsupportedSSEFFormatVersion,
    AEAD(aead::Error),
    Argon2(argon2::Error),
    FromUTF8(string::FromUtf8Error),
    IO(IO),
}

pub type Result<T> = core::result::Result<T, Error>;

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            // NOTE: aead::Error does not implement std::error::Error.
            Self::Argon2(e) => Some(e),
            Self::FromUTF8(e) => Some(e),
            Self::IO(e) => Some(e.error.as_ref()),
            _ => None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        match self {
            Self::None => write!(f, "No error"),
            Self::Copy(e) => {
                write!(
                    f,
                    "Error while copying contents of {} to {}: {}",
                    e.src_file_path.to_string_lossy(),
                    e.dest_file_path.to_string_lossy(),
                    e.message
                )
            },
            Self::InvalidNonceLength => {
                write!(f, "Nonce length is either too short or too long")
            }
            Self::InvalidPasswordLength => {
                write!(f, "Password must be more than 12 characters")
            }
            Self::InvalidSSEFFile => write!(f, "Invalid SSEF file"),
            Self::InvalidSSEFFileIdentifier => write!(f, "Wrong file identifier"),
            Self::TaskTerminated => write!(f, "Task was stopped midway"),
            Self::InvalidDirectory(s) => write!(f, "{}", s),
            Self::Logging(s) => write!(f, "{}", s),
            Self::UnsupportedSSEFFormatVersion => write!(f, "Format version is not supported"),
            Self::AEAD(e) => write!(f, "Error while using AEAD functions: {}", e),
            Self::Argon2(e) => write!(f, "Error while using Argon2 functions: {}", e),
            Self::FromUTF8(e) => write!(f, "Error while create string from bytes: {}", e),
            Self::IO(e) => write!(
                f,
                "Error performing I/O operations on {}: {}",
                e.path.to_string_lossy(),
                e.error.to_string()
            ),
        }
    }
}

impl From<Copy> for Error {
    fn from(e: Copy) -> Self { Self::Copy(e) }
}

impl From<IO> for Error {
    fn from(e: IO) -> Self { Self::IO(e) }
}

impl From<aead::Error> for Error {
    fn from(e: aead::Error) -> Self { Self::AEAD(e) }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self { Self::Argon2(e) }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Self { Self::FromUTF8(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IO(IO::new(PathBuf::new(), Arc::new(e)))
    }
}
