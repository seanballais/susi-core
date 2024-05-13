use std::sync::Arc;
use argon2::Algorithm::Argon2id;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::common::{MINIMUM_PASSWORD_LENGTH, MINIMUM_SALT_LENGTH};
use crate::errors;
use crate::errors::Result;

const KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = KEY_SIZE;

pub type FileKey = [u8; KEY_SIZE];
pub type MAC = [u8; MAC_SIZE];

#[derive(Debug, Copy, Clone)]
pub struct SusiKey {
    pub key: FileKey,
    pub mac: MAC
}

impl SusiKey {
    pub fn new(password: &[u8], salt: &[u8]) -> Result<Self> {
        if password.len() < MINIMUM_PASSWORD_LENGTH {
            return Err(errors::Error::InvalidPasswordLength);
        }

        if salt.len() < MINIMUM_SALT_LENGTH {
            return Err(errors::Error::InvalidSaltLength);
        }

        const GENERATED_KEY_SIZE: usize = 64;

        let argon2_params = argon2::ParamsBuilder::new().output_len(64).build()?;
        let argon2 = argon2::Argon2::new(Argon2id, argon2::Version::default(), argon2_params);
        let mut generated_key = [0u8; GENERATED_KEY_SIZE];
        argon2.hash_password_into(password, salt, &mut generated_key)?;

        // NOTE: I don't know how to test the following functions yet.
        // - Sean Ballais (May 11, 2024 3:50 AM)
        let k0: [u8; 32] = (&generated_key[0..GENERATED_KEY_SIZE / 2])
            .try_into()
            .map_err(|e| {
                tracing::error!("Failed to create a Susi Key: {}", e);
                errors::Error::PasswordKeyGeneration(Arc::new(e))
            }
        )?;
        let k1: [u8; 32] = (&generated_key[GENERATED_KEY_SIZE / 2..GENERATED_KEY_SIZE])
            .try_into()
            .map_err(|e| {
                tracing::error!("Failed to create a Susi Key: {}", e);
                errors::Error::PasswordKeyGeneration(Arc::new(e))
            }
        )?;

        let mut hmac = Hmac::<Sha256>::new_from_slice(&k1)
            .map_err(|e| {
                errors::Error::PasswordKeyGeneration(Arc::new(e))
            }
        )?;
        hmac.update(&k0);

        // Note: Seems like the MAC has the same size as its input key.
        // - Sean Ballais (May 11, 2024, 1:13 AM)
        let mac = (&hmac.finalize().into_bytes()[..32])
            .try_into()
            .map_err(|e| {
                errors::Error::PasswordKeyGeneration(Arc::new(e))
            })?;

        Ok(Self {
            key: k0,
            mac
        })
    }
}

pub fn is_password_correct(password: &[u8], salt: &[u8], mac: &MAC) -> Result<bool> {
    let susi_key = SusiKey::new(password, salt).map_err(|e| {
        tracing::error!("Failed to create a Susi Key: {}", e);
        errors::Error::PasswordVerification(Arc::new(e))
    })?;

    if susi_key.mac.eq(mac) {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keys::{is_password_correct, SusiKey};
    use crate::errors;
    use crate::errors::Error;

    const PASSWORD: &[u8] = b"balang araw masusulat ko kaya";
    const SALT: &[u8] = b"ang kanta na bibili ng bahay sa sta. rosa";
    const EXPECTED_KEY: [u8; 32] = [
        149, 154,  49,  95,  91, 248,  94, 163,
        166,  29, 184,  66,  87, 101,   8, 142,
        254, 123, 219, 234,  44, 118,  22, 195,
        205,  19, 198, 220, 113,  75, 126, 190
    ];
    const EXPECTED_MAC: [u8; 32] = [
        218, 125, 229,  84,  36,  15,  11, 178,
        250, 112,  66, 195,  94, 167, 185, 132,
        130, 246, 172,  31,  56,  34, 232,  47,
        18, 150, 163, 101,  21,  86, 106, 128
    ];

    #[test]
    fn test_susi_key_creation_succeeds() {
        let res = SusiKey::new(PASSWORD, SALT);
        assert!(res.is_ok());

        let key = res.unwrap();
        assert_eq!(EXPECTED_KEY, key.key);
        assert_eq!(EXPECTED_MAC, key.mac);
    }

    #[test]
    fn test_susi_key_creation_with_short_password_fails() {
        let res = SusiKey::new(b"brokenheart", b"small-salt");
        assert!(res.is_err());

        assert!(matches!(res.unwrap_err(), errors::Error::InvalidPasswordLength));
    }

    #[test]
    fn test_susi_key_creation_with_short_salt_fails() {
        let res = SusiKey::new(PASSWORD, b"small-salt");
        assert!(res.is_err());

        assert!(matches!(res.unwrap_err(), errors::Error::InvalidSaltLength));
    }

    #[test]
    fn test_password_verification_with_correct_password_succeeds() {
        let key = SusiKey::new(PASSWORD, SALT).unwrap();
        let res = is_password_correct(PASSWORD, SALT, &key.mac);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_password_verification_with_short_password_fails() {
        let key = SusiKey::new(PASSWORD, SALT).unwrap();
        let res = is_password_correct(b"iincorrectus", SALT, &key.mac);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), false);
    }

    #[test]
    fn test_password_verification_with_wrong_password_fails() {
        let key = SusiKey::new(PASSWORD, SALT).unwrap();
        let res = is_password_correct(b"shortus", SALT, &key.mac);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), Error::PasswordVerification(_)));
    }
}
