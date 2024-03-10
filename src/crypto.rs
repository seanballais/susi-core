use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic;

use aead;
use aead::KeyInit;
use aes_gcm;
use argon2;
use argon2::Algorithm::Argon2id;

use crate::error::Error;
use crate::error::Result;

type SusiKey = [u8; 32];

// We actually need 12 bytes, but 5 bytes are used as a 32-bit big endian counter, and 1 byte as
// a "last block" flag.
//
// See: https://docs.rs/aead/latest/aead/stream/struct.StreamBE32.html
type AES256GCMNonce = [u8; 7];

pub fn create_key_from_password(password: &[u8], salt: &[u8]) -> Result<SusiKey> {
    if password.len() < 12 {
        return Err(Error::InvalidPasswordLengthError);
    }

    let argon2_params = argon2::ParamsBuilder::new().output_len(32).build()?;
    let argon2 = argon2::Argon2::new(Argon2id, argon2::Version::default(), argon2_params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut key)?;

    Ok(key)
}

pub fn encrypt_file(
    src_file: &mut File,
    dest_file: &mut File,
    key: &SusiKey,
    nonce: &AES256GCMNonce,
    buffer_len: &usize,
    num_read_bytes: Option<&mut atomic::AtomicUsize>,
    num_written_bytes: Option<&mut atomic::AtomicUsize>
) -> Result<()> {
    let aead = aes_gcm::Aes256Gcm::new(key.as_ref().into());
    let mut stream_encryptor = aead::stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = vec![0u8; *buffer_len];

    loop {
        let read_count = src_file.read(&mut buffer)?;

        if let Some(ref num_bytes) = num_read_bytes {
            num_bytes.fetch_add(read_count, atomic::Ordering::Relaxed);
        }

        if read_count == 0 {
            return Err(Error::EmptyFileError);
        } else if read_count == *buffer_len {
            let encrypted = stream_encryptor.encrypt_next(buffer.as_slice())?;
            let write_count = dest_file.write(&encrypted)?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, atomic::Ordering::Relaxed);
            }
        } else {
            let encrypted = stream_encryptor.encrypt_last(&buffer[..read_count])?;
            let write_count = dest_file.write(&encrypted)?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, atomic::Ordering::Relaxed);
            }

            break;
        }
    }

    Ok(())
}

pub fn decrypt_file(
    src_file: &mut File,
    dest_file: &mut File,
    key: &SusiKey,
    nonce: &AES256GCMNonce,
    buffer_len: &usize,
    num_read_bytes: Option<&mut atomic::AtomicUsize>,
    num_written_bytes: Option<&mut atomic::AtomicUsize>
) -> Result<()> {
    let aead = aes_gcm::Aes256Gcm::new(key.as_ref().into());
    let mut stream_decryptor = aead::stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = vec![0u8; *buffer_len];

    loop {
        let read_count = src_file.read(&mut buffer)?;

        if let Some(ref num_bytes) = num_read_bytes {
            num_bytes.fetch_add(read_count, atomic::Ordering::Relaxed);
        }

        if read_count == 0 {
            return Err(Error::EmptyFileError);
        } else if read_count == *buffer_len {
            let decrypted = stream_decryptor.decrypt_next(buffer.as_slice())?;
            let write_count = dest_file.write(&decrypted)?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, atomic::Ordering::Relaxed);
            }
        } else {
            let decrypted = stream_decryptor.decrypt_last(&buffer[..read_count])?;
            let write_count = dest_file.write(&decrypted)?;

            if let Some(num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, atomic::Ordering::Relaxed);
            }

            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Seek;
    use rand::{rngs::OsRng, RngCore};
    use tempfile::tempfile;

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

    #[test]
    fn test_encrypting_and_decrypting_data_succeeds() {
        let mut src_file = tempfile().unwrap();
        let mut encrypted_file = tempfile().unwrap();
        let mut decrypted_file = tempfile().unwrap();
        let contents = concat!(
            "I can see what's happening\n",
            "What?\n",
            "Our trio's down to two!\n",
            "(lyrics)\n",
            "_CAN_ YOU FEEL THE LOVE TONIGHT?!\n",
            "The world for once, in perfect harmony\n",
            "With all its living things\n",
            "So many things to tell youuu\n",
            "She'd turn away from meee");
        writeln!(src_file, "{}", contents).unwrap();

        // We need to wind back the file pointer in src_file since we wrote contents to it.
        src_file.rewind().unwrap();

        let key = create_key_from_password(b"tale-as-old-as-time", b"song-as-old-as-rhyme").unwrap();
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
            None);
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
            None);
        assert!(decryption_result.is_ok());

        // We need to wind back the file pointer in the files below since we used them before.
        src_file.rewind().unwrap();
        decrypted_file.rewind().unwrap();

        let mut original_contents = String::new();
        let mut decrypted_contents = String::new();
        src_file.read_to_string(&mut original_contents).unwrap();
        decrypted_file.read_to_string(&mut decrypted_contents).unwrap();

        assert_eq!(original_contents.trim(), decrypted_contents.trim());
    }

    #[test]
    fn test_encrypting_an_empty_file_fails() {
        let key = create_key_from_password(b"why-do-birds", b"suddenly-appear").unwrap();
        let mut aes_nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut aes_nonce);

        const BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.

        let mut empty_file = tempfile().unwrap();
        let mut dest_file = tempfile().unwrap();
        let result = encrypt_file(
            &mut empty_file,
            &mut dest_file,
            &key,
            &aes_nonce,
            &BUFFER_LEN,
            None,
            None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypting_an_empty_file_fails() {
        let key = create_key_from_password(b"isn't she lovelyyyy", b"isn't-she-wonderfulll").unwrap();
        let mut aes_nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut aes_nonce);

        const BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.

        let mut empty_file = tempfile().unwrap();
        let mut dest_file = tempfile().unwrap();
        let result = decrypt_file(
            &mut empty_file,
            &mut dest_file,
            &key,
            &aes_nonce,
            &BUFFER_LEN,
            None,
            None);
        assert!(result.is_err());
    }
}
