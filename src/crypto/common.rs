pub const SALT_LENGTH: usize = 32;
pub const MINIMUM_PASSWORD_LENGTH: usize = 12;

// Remember that each metadata value only has a max length of 65,535 bytes, since we assign
// two bytes in the metadata key to track the size of the value.
const MAX_METADATA_VALUE_SIZE: usize = 65_535;

// We actually need 12 bytes, but 5 bytes are used as a 32-bit big endian counter, and 1 byte as
// a "last block" flag.
//
// See: https://docs.rs/aead/latest/aead/stream/struct.StreamBE32.html
const AES_256_GCM_NONCE_LENGTH: usize = 7;
pub type AES256GCMNonce = [u8; AES_256_GCM_NONCE_LENGTH];

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, Write};
    use rand::{rngs::OsRng, RngCore};
    use tempfile::tempfile;
    use crate::crypto::decryption::{decrypt_file, decrypt_from_ssef_file};
    use crate::crypto::encryption::{encrypt_file, encrypt_to_ssef_file};

    use crate::crypto::keys::SusiKey;
    use crate::errors::Error;
    use crate::fs::{File};

    use super::*;

    #[test]
    fn test_encrypting_and_decrypting_ssef_file_succeeds() {
        let mut src_file = File::from(tempfile().unwrap());
        let mut encrypted_file = File::from(tempfile().unwrap());
        let mut decrypted_file = File::from(tempfile().unwrap());

        let contents = concat!(
        "I can see what's happening\n",
        "What?\n",
        "Our trio's down to two!\n",
        "(lyrics)\n",
        "_CAN_ YOU FEEL THE LOVE TONIGHT?!\n",
        "The world for once, in perfect harmony\n",
        "With all its living things\n",
        "So many things to tell youuu\n",
        "She'd turn away from meee"
        );
        writeln!(src_file.get_file_mut(), "{}", contents).unwrap();

        // We need to wind back the file pointer in src_file since we wrote contents to it.
        src_file.rewind().unwrap();

        let password = b"tale-as-old-as-time";
        let salt = b"song-as-old-as-rhyme";
        let mut nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut nonce);

        const BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.

        let encryption_result = encrypt_to_ssef_file(
            &mut src_file,
            &mut encrypted_file,
            password,
            salt,
            &nonce,
            &BUFFER_LEN,
            None,
            None,
            None,
            None,
        );
        assert!(encryption_result.is_ok());

        // We need to wind back the file pointer in encrypted_file since we wrote contents to it.
        encrypted_file.rewind().unwrap();

        let decryption_result = decrypt_from_ssef_file(
            &mut encrypted_file,
            &mut decrypted_file,
            password,
            &BUFFER_LEN,
            None,
            None,
            None,
            None,
        );
        assert!(decryption_result.is_ok());

        // We need to wind back the file pointer in the files below since we used them before.
        src_file.rewind().unwrap();
        decrypted_file.rewind().unwrap();

        let mut original_contents = String::new();
        let mut decrypted_contents = String::new();
        src_file.read_to_string(&mut original_contents).unwrap();
        decrypted_file
            .read_to_string(&mut decrypted_contents)
            .unwrap();

        assert_eq!(original_contents.trim(), decrypted_contents.trim());
    }

    #[test]
    fn test_creating_key_from_password_succeeds() {
        let key = SusiKey::new(b"this-is-a-password-supposedly", b"saltsaltsaltsalt")
            .unwrap();
        assert_eq!(key.key.len(), 32);
    }

    #[test]
    fn test_creating_key_from_password_with_too_short_password_fails() {
        let res = SusiKey::new(b"pass", b"asin");
        assert!(res.is_err());
    }

    #[test]
    fn test_creating_key_from_password_with_too_short_salt_fails() {
        let res = SusiKey::new(b"this-is-a-password-supposedly", b"asin");
        assert!(res.is_err());
    }

    #[test]
    fn test_encrypting_and_decrypting_data_succeeds() {
        let mut src_file = File::from(tempfile().unwrap());
        let mut encrypted_file = File::from(tempfile().unwrap());
        let mut decrypted_file = File::from(tempfile().unwrap());
        let contents = concat!(
        "I can see what's happening\n",
        "What?\n",
        "Our trio's down to two!\n",
        "(lyrics)\n",
        "_CAN_ YOU FEEL THE LOVE TONIGHT?!\n",
        "The world for once, in perfect harmony\n",
        "With all its living things\n",
        "So many things to tell youuu\n",
        "She'd turn away from meee"
        );
        writeln!(src_file.get_file_mut(), "{}", contents).unwrap();

        // We need to wind back the file pointer in src_file since we wrote contents to it.
        src_file.rewind().unwrap();

        let key = SusiKey::new(b"tale-as-old-as-time", b"song-as-old-as-rhyme").unwrap();
        let mut aes_nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut aes_nonce);

        const BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.

        let encryption_result = encrypt_file(
            &mut src_file,
            &mut encrypted_file,
            &key,
            &aes_nonce,
            &BUFFER_LEN,
            None,
            None,
            None,
            None,
        );
        assert!(encryption_result.is_ok());

        // We need to wind back the file pointer in encrypted_file since we wrote contents to it.
        encrypted_file.rewind().unwrap();

        let decryption_result = decrypt_file(
            &mut encrypted_file,
            &mut decrypted_file,
            &key,
            &aes_nonce,
            &BUFFER_LEN,
            None,
            None,
            None,
            None,
        );
        assert!(decryption_result.is_ok());

        // We need to wind back the file pointer in the files below since we used them before.
        src_file.rewind().unwrap();
        decrypted_file.rewind().unwrap();

        let mut original_contents = String::new();
        let mut decrypted_contents = String::new();
        src_file.read_to_string(&mut original_contents).unwrap();
        decrypted_file
            .read_to_string(&mut decrypted_contents)
            .unwrap();

        assert_eq!(original_contents.trim(), decrypted_contents.trim());
    }

    #[test]
    fn test_encrypting_an_empty_file_succeeds() {
        let key = SusiKey::new(b"why-do-birds", b"suddenly-appear").unwrap();
        let mut aes_nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut aes_nonce);

        const BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.

        let mut empty_file = File::from(tempfile().unwrap());
        let mut dest_file = File::from(tempfile().unwrap());
        let result = encrypt_file(
            &mut empty_file,
            &mut dest_file,
            &key,
            &aes_nonce,
            &BUFFER_LEN,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypting_an_empty_file_fails() {
        let key = SusiKey::new(b"isn't she lovelyyyy", b"isn't-she-wonderfulll").unwrap();
        let mut aes_nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut aes_nonce);

        const BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.

        let mut empty_file = File::from(tempfile().unwrap());
        let mut dest_file = File::from(tempfile().unwrap());
        let result = decrypt_file(
            &mut empty_file,
            &mut dest_file,
            &key,
            &aes_nonce,
            &BUFFER_LEN,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidSSEFFile)));
    }
}