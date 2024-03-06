use std::error::Error;
use std::fmt::Formatter;

use argon2;

#[derive(Debug, Clone)]
pub enum SusiError {
    InvalidPasswordLengthError,
    Argon2Error(argon2::Error),
}

impl Error for SusiError {}

impl std::fmt::Display for SusiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::InvalidPasswordLengthError => {
                write!(f, "Password must be more than 12 characters")
            }
            Self::Argon2Error(e) => write!(f, "Error while using Argon2 functions: {}", e),
        }
    }
}

impl From<argon2::Error> for SusiError {
    fn from(e: argon2::Error) -> Self {
        Self::Argon2Error(e)
    }
}
