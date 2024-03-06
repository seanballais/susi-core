use argon2::{Algorithm::Argon2id, Argon2};

use crate::error::SusiError;

pub fn create_key_from_password(password: &[u8], salt: &[u8]) -> Result<[u8; 32], SusiError> {
    if password.len() < 12 {
        return Err(SusiError::InvalidPasswordLengthError);
    }

    let argon2_params = argon2::ParamsBuilder::new().output_len(32).build()?;
    let argon2 = Argon2::new(Argon2id, argon2::Version::default(), argon2_params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut key)?;

    Ok(key)
}

pub fn encrypt_data(data: &[u8], key: [u8; 32]) -> Vec<u8> {
    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creating_32_byte_key_from_password_succeeds() {
        let key = create_key_from_password(b"this-is-a-password-supposedly", b"saltsaltsaltsalt")
            .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_creating_32_byte_key_from_password_with_too_short_password_fails() {
        let res = create_key_from_password(b"pass", b"asin");
        assert!(res.is_err());
    }

    #[test]
    fn test_creating_32_byte_key_from_password_with_too_short_salt_fails() {
        let res = create_key_from_password(b"this-is-a-password-supposedly", b"asin");
        assert!(res.is_err());
    }
}
