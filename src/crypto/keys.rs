use std::sync::Arc;
use argon2::Algorithm::Argon2id;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::common::MINIMUM_PASSWORD_LENGTH;
use crate::errors::Error;

pub struct SusiKey {
    pub key: [u8; 32],
    pub mac: [u8; 32]
}

impl SusiKey {
    pub fn new(password: &[u8], salt: &[u8]) -> crate::errors::Result<Self> {
        tracing::info!("Creating key from password and salt");

        if password.len() < MINIMUM_PASSWORD_LENGTH {
            return Err(Error::InvalidPasswordLength);
        }

        const GENERATED_KEY_SIZE: usize = 64;

        let argon2_params = argon2::ParamsBuilder::new().output_len(64).build()?;
        let argon2 = argon2::Argon2::new(Argon2id, argon2::Version::default(), argon2_params);
        let mut generated_key = [0u8; GENERATED_KEY_SIZE];
        argon2.hash_password_into(password, salt, &mut generated_key)?;

        let k0: [u8; 32] = (&generated_key[0..GENERATED_KEY_SIZE / 2])
            .try_into()
            .map_err(|e| {
                Error::PasswordKeyGeneration(Arc::new(e))
            }
            )?;
        let k1: [u8; 32] = (&generated_key[GENERATED_KEY_SIZE / 2..GENERATED_KEY_SIZE])
            .try_into()
            .map_err(|e| {
                Error::PasswordKeyGeneration(Arc::new(e))
            }
            )?;

        let mut hmac = Hmac::<Sha256>::new_from_slice(&k1).expect("Unable to create HMAC function");
        hmac.update(&k0);

        // Note: Seems like the MAC has the same size as its input key.
        // - Sean Ballais (May 11, 2024, 1:13 AM)
        let mac = (&hmac.finalize().into_bytes()[..32])
            .try_into()
            .map_err(|e| {
                Error::PasswordKeyGeneration(Arc::new(e))
            })?;

        Ok(Self {
            key: k0,
            mac
        })
    }
}