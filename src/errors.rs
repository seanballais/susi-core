// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};
use std::string;
use std::sync::Arc;

use crate::path::OptionPathBufExt;
use aead;
use argon2;
use crate::crypto::common::{MINIMUM_PASSWORD_LENGTH, MINIMUM_SALT_LENGTH};

#[derive(Debug, Clone)]
pub struct Copy {
    src_file_path: Option<PathBuf>,
    dest_file_path: Option<PathBuf>,
    message: String,
}

impl Copy {
    pub fn new<P: AsRef<Path>, S: AsRef<str>>(
        src_file_path: Option<P>,
        dest_file_path: Option<P>,
        message: S,
    ) -> Self {
        let src_file_path = src_file_path.map(|path| PathBuf::from(path.as_ref()));
        let dest_file_path = dest_file_path.map(|path| PathBuf::from(path.as_ref()));

        Self {
            src_file_path,
            dest_file_path,
            message: String::from(message.as_ref()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IO {
    message: String,
    path: Option<PathBuf>,
    error: Arc<io::Error>,
}

impl IO {
    pub fn new<S: AsRef<str>, P: AsRef<Path>>(
        message: S,
        path: Option<P>,
        error: Arc<io::Error>,
    ) -> Self {
        let path = path.map(|path| PathBuf::from(path.as_ref()));
        let message = String::from(message.as_ref());
        Self {
            message,
            path,
            error,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    None, // Only use this as a default value.
    Copy(Copy),
    FileExists(PathBuf),
    IncorrectPassword,
    InvalidPasswordLength,
    InvalidSaltLength,
    InvalidSSEFFile,
    InvalidSSEFFileIdentifier,
    InvalidDirectory(String),
    Logging(String),
    MACNotObtained(Arc<dyn error::Error + Send + Sync>),
    NonceNotObtained(Arc<dyn error::Error + Send + Sync>),
    PasswordKeyGeneration(Arc<dyn error::Error + Send + Sync>),
    PasswordVerification(Arc<dyn error::Error + Send + Sync>),
    TaskTerminated,
    UnsupportedSSEFFormatVersion,
    AEAD(aead::Error),
    Argon2(argon2::Error),
    FromUTF8(string::FromUtf8Error),
    IO(IO)
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
            Self::IncorrectPassword => write!(f, "Incorrect password"),
            Self::InvalidPasswordLength => {
                write!(f, "Password must be more than {} bytes", MINIMUM_PASSWORD_LENGTH)
            },
            Self::InvalidSaltLength => {
                write!(f, "Salt must be more than {} bytes", MINIMUM_SALT_LENGTH)
            },
            Self::InvalidSSEFFile => write!(f, "Invalid SSEF file"),
            Self::InvalidSSEFFileIdentifier => write!(f, "Wrong file identifier"),
            Self::TaskTerminated => write!(f, "Task was stopped midway"),
            Self::InvalidDirectory(s) => write!(f, "{}", s),
            Self::Logging(s) => write!(f, "{}", s),
            Self::FileExists(p) => {
                write!(f, "{} already exists", p.display())
            },
            Self::MACNotObtained(e) => {
                write!(f, "Unable to obtain the MAC: {}", e.to_string())
            },
            Self::NonceNotObtained(e) => {
                write!(f, "Unable to obtain the nonce: {}", e.to_string())
            }
            Self::PasswordKeyGeneration(e) => write!(
                f, "Password key generation failed: {}", e.to_string()
            ),
            Self::PasswordVerification(e) => write!(
                f, "Failed to verify provided password: {}", e.to_string()
            ),
            Self::UnsupportedSSEFFormatVersion => write!(f, "Format version is not supported"),
            Self::AEAD(e) => write!(f, "Error while using AEAD functions: {}", e.to_string()),
            Self::Argon2(e) => write!(f, "Error while using Argon2 functions: {}", e.to_string()),
            Self::FromUTF8(e) => write!(f, "Error while create string from bytes: {}", e.to_string()),
            Self::IO(e) => write!(
                f,
                "{} ({}): {}",
                e.message,
                e.path.to_string_lossy(),
                e.error.to_string()
            )
        }
    }
}

impl From<Copy> for Error {
    fn from(e: Copy) -> Self {
        Self::Copy(e)
    }
}

impl From<IO> for Error {
    fn from(e: IO) -> Self {
        Self::IO(e)
    }
}

impl From<aead::Error> for Error {
    fn from(e: aead::Error) -> Self {
        Self::AEAD(e)
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Self::Argon2(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Self {
        Self::FromUTF8(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IO(IO::new(
            String::from("Unable to perform I/O operations on file"),
            None::<&str>,
            Arc::new(e),
        ))
    }
}
