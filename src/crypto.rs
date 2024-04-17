use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use aead;
use aead::stream::{DecryptorBE32, EncryptorBE32};
use aead::KeyInit;
use aes_gcm;
use aes_gcm::Aes256Gcm;
use argon2;
use argon2::Algorithm::Argon2id;

use crate::errors;
use crate::errors::{Error, Result};
use crate::fs::File;

pub const SALT_LENGTH: usize = 32;

pub const IO_BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.
pub const MINIMUM_PASSWORD_LENGTH: usize = 12;

// Remember that each metadata value only has a max length of 65,535 bytes, since we assign
// two bytes in the metadata key to track the size of the value.
const MAX_METADATA_VALUE_SIZE: usize = 65_535;

pub type SusiKey = [u8; 32];

// We actually need 12 bytes, but 5 bytes are used as a 32-bit big endian counter, and 1 byte as
// a "last block" flag.
//
// See: https://docs.rs/aead/latest/aead/stream/struct.StreamBE32.html
const AES_256_GCM_NONCE_LENGTH: usize = 7;
pub type AES256GCMNonce = [u8; AES_256_GCM_NONCE_LENGTH];

pub struct SSEFMetadata {
    filename: String,
    salt: Vec<u8>,
    nonce: AES256GCMNonce,
}

pub fn encrypt_to_ssef_file(
    src_file: &mut File,
    dest_file: &mut File,
    password: &[u8],
    salt: &[u8],
    nonce: &AES256GCMNonce,
    buffer_len: &usize,
    num_read_bytes: Option<Arc<AtomicUsize>>,
    num_written_bytes: Option<Arc<AtomicUsize>>,
    should_stop: Option<Arc<AtomicBool>>,
) -> Result<()> {
    tracing::info!(
        "Encrypting file, {}, to {}",
        src_file.path_or_empty().display(),
        dest_file.path_or_empty().display()
    );

    // Let's just rewind the files back to make sure.
    src_file
        .rewind()
        .map_err(|e| errors::IO::new(src_file.path().clone(), Arc::from(e)))?;
    dest_file
        .rewind()
        .map_err(|e| errors::IO::new(dest_file.path().clone(), Arc::new(e)))?;

    let key = create_key_from_password(password, salt)?;
    let header = create_metadata_section_for_encrypted_file(src_file, salt, nonce)?;

    dest_file
        .write_all(header.as_slice())
        .map_err(|e| errors::IO::new(dest_file.path().clone(), Arc::from(e)))?;

    encrypt_file(
        src_file,
        dest_file,
        &key,
        &nonce,
        &buffer_len,
        num_read_bytes,
        num_written_bytes,
        should_stop,
    )?;

    Ok(())
}

pub fn decrypt_from_ssef_file(
    src_file: &mut File,
    dest_file: &mut File,
    password: &[u8],
    buffer_len: &usize,
    num_read_bytes: Option<Arc<AtomicUsize>>,
    num_written_bytes: Option<Arc<AtomicUsize>>,
    should_stop: Option<Arc<AtomicBool>>,
) -> Result<()> {
    tracing::info!(
        "Decrypting file, {}, to {}",
        src_file.path_or_empty().display(),
        dest_file.path_or_empty().display()
    );

    // Let's just rewind the files back to make sure.
    src_file
        .rewind()
        .map_err(|e| errors::IO::new(src_file.path().clone(), Arc::from(e)))?;
    dest_file
        .rewind()
        .map_err(|e| errors::IO::new(dest_file.path().clone(), Arc::new(e)))?;

    validate_ssef_file_identifier(src_file)?;
    validate_ssef_file_format_version(src_file)?;

    let metadata = get_metadata_section_from_ssef_file(src_file)?;

    let key = create_key_from_password(password, metadata.salt.as_slice())?;
    let nonce: AES256GCMNonce = metadata.nonce.into();

    decrypt_file(
        src_file,
        dest_file,
        &key,
        &nonce,
        buffer_len,
        num_read_bytes,
        num_written_bytes,
        should_stop,
    )?;

    Ok(())
}

pub fn create_key_from_password(password: &[u8], salt: &[u8]) -> Result<SusiKey> {
    tracing::info!("Creating key from password and salt");

    if password.len() < MINIMUM_PASSWORD_LENGTH {
        return Err(Error::InvalidPasswordLength);
    }

    let argon2_params = argon2::ParamsBuilder::new().output_len(32).build()?;
    let argon2 = argon2::Argon2::new(Argon2id, argon2::Version::default(), argon2_params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut key)?;

    Ok(key)
}

fn encrypt_file(
    src_file: &mut File,
    dest_file: &mut File,
    key: &SusiKey,
    nonce: &AES256GCMNonce,
    buffer_len: &usize,
    num_read_bytes: Option<Arc<AtomicUsize>>,
    num_written_bytes: Option<Arc<AtomicUsize>>,
    should_stop: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let aead = Aes256Gcm::new(key.as_ref().into());
    let mut stream_encryptor = EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = vec![0u8; *buffer_len];

    tracing::info!(
        "Encrypting data from {} to {}",
        src_file.path_or_empty().display(),
        dest_file.path_or_empty().display()
    );

    loop {
        if let Some(ref should_stop) = should_stop {
            if should_stop.load(Ordering::Relaxed) {
                return Err(Error::TaskTerminated);
            }
        }

        let read_count = src_file
            .read(&mut buffer)
            .map_err(|e| errors::IO::new(src_file.path().clone(), Arc::from(e)))?;

        if let Some(ref num_bytes) = num_read_bytes {
            num_bytes.fetch_add(read_count, Ordering::Relaxed);
        }

        if read_count == 0 {
            // Huh. This must be empty. No matter. Let's just finish the operation.
            break;
        } else if read_count == *buffer_len {
            let encrypted = stream_encryptor.encrypt_next(buffer.as_slice())?;
            let write_count = dest_file
                .write(&encrypted)
                .map_err(|e| errors::IO::new(dest_file.path().clone(), Arc::from(e)))?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, Ordering::Relaxed);
            }
        } else {
            let encrypted = stream_encryptor.encrypt_last(&buffer[..read_count])?;
            let write_count = dest_file
                .write(&encrypted)
                .map_err(|e| errors::IO::new(dest_file.path().clone(), Arc::from(e)))?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, Ordering::Relaxed);
            }

            break;
        }
    }

    Ok(())
}

fn decrypt_file(
    src_file: &mut File,
    dest_file: &mut File,
    key: &SusiKey,
    nonce: &AES256GCMNonce,
    buffer_len: &usize,
    num_read_bytes: Option<Arc<AtomicUsize>>,
    num_written_bytes: Option<Arc<AtomicUsize>>,
    should_stop: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let aead = Aes256Gcm::new(key.as_ref().into());
    let mut stream_decryptor = DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = vec![0u8; *buffer_len];

    tracing::info!(
        "Decrypting data from {} to {}",
        src_file.path_or_empty().display(),
        dest_file.path_or_empty().display()
    );

    loop {
        if let Some(ref should_stop) = should_stop {
            if should_stop.load(Ordering::Relaxed) {
                return Err(Error::TaskTerminated);
            }
        }

        let read_count = src_file
            .read(&mut buffer)
            .map_err(|e| errors::IO::new(src_file.path().clone(), Arc::from(e)))?;

        if let Some(ref num_bytes) = num_read_bytes {
            num_bytes.fetch_add(read_count, Ordering::Relaxed);
        }

        if read_count == 0 {
            return Err(Error::InvalidSSEFFile);
        } else if read_count == *buffer_len {
            let decrypted = stream_decryptor.decrypt_next(buffer.as_slice())?;
            let write_count = dest_file
                .write(&decrypted)
                .map_err(|e| errors::IO::new(dest_file.path().clone(), Arc::from(e)))?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, Ordering::Relaxed);
            }
        } else {
            let decrypted = stream_decryptor.decrypt_last(&buffer[..read_count])?;
            let write_count = dest_file
                .write(&decrypted)
                .map_err(|e| errors::IO::new(dest_file.path().clone(), Arc::from(e)))?;

            if let Some(num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, Ordering::Relaxed);
            }

            break;
        }
    }

    Ok(())
}

fn create_metadata_section_for_encrypted_file(
    src_file: &File,
    salt: &[u8],
    nonce: &AES256GCMNonce,
) -> Result<Vec<u8>> {
    // File identifier = first two bytes (big-endian)
    // Format version = last two bytes (little-endian)
    let header: Vec<u8> = vec![0x55, 0x3F, 0x01, 0x00];

    let filename_metadata = create_filename_metadata_item(src_file)?;
    let salt_metadata = create_salt_metadata_item(salt);
    let nonce_metadata = create_nonce_metadata_item(nonce);
    let metadata_length = filename_metadata.len() + salt_metadata.len() + nonce_metadata.len();

    // Plus six to include header and metadata length
    let mut metadata_section: Vec<u8> = Vec::with_capacity(metadata_length + 6);
    metadata_section.extend(header.iter());
    metadata_section.push((metadata_length & 0xFF) as u8);
    metadata_section.push((metadata_length >> 8 & 0xFF) as u8);
    metadata_section.extend(filename_metadata.iter());
    metadata_section.extend(salt_metadata.iter());
    metadata_section.extend(nonce_metadata.iter());

    Ok(metadata_section)
}

fn create_filename_metadata_item(src_file: &File) -> Result<Vec<u8>> {
    // Note: No needed to check if the file name is too long, since the chances of it happening is
    //       low, and we will get an error outside the app if the file name is too long.
    let src_file_name = src_file
        .path_or_empty()
        .file_name()
        .unwrap_or_else(|| OsStr::new(""));

    let filename_length = src_file_name.len();
    let mut metadata_filename: Vec<u8> = Vec::with_capacity(4 + filename_length);
    metadata_filename.push(0x00);
    metadata_filename.push(0x01);

    // Get the first byte of the length.
    metadata_filename.push((filename_length & 0xFF) as u8);

    // Get the second byte of the length.
    metadata_filename.push((filename_length >> 8 & 0xFF) as u8);

    metadata_filename.extend_from_slice(src_file_name.to_string_lossy().as_bytes());

    Ok(metadata_filename)
}

fn create_salt_metadata_item(salt: &[u8]) -> Vec<u8> {
    let mut salt_metadata: Vec<u8> = Vec::with_capacity(4 + salt.len());
    salt_metadata.push(0xA5);
    salt_metadata.push(0x19);

    // Get the first byte of the length.
    salt_metadata.push((salt.len() & 0xFF) as u8);

    // Get the second byte of the length.
    salt_metadata.push((salt.len() >> 8 & 0xFF) as u8);

    salt_metadata.extend_from_slice(salt);

    salt_metadata
}

fn create_nonce_metadata_item(nonce: &AES256GCMNonce) -> Vec<u8> {
    let mut nonce_metadata: Vec<u8> = Vec::with_capacity(4 + nonce.len());
    nonce_metadata.push(0x90);
    nonce_metadata.push(0x9C);

    // Get the first byte of the length.
    nonce_metadata.push((nonce.len() & 0xFF) as u8);

    // Get the second byte of the length.
    nonce_metadata.push((nonce.len() >> 8 & 0xFF) as u8);

    nonce_metadata.extend_from_slice(nonce.as_slice());

    nonce_metadata
}

fn validate_ssef_file_identifier(src_file: &mut File) -> Result<()> {
    let mut file_identifier_buffer = [0u8; 2];
    src_file.read(&mut file_identifier_buffer)?;
    if file_identifier_buffer != [0x55, 0x3F] {
        return Err(Error::InvalidSSEFFileIdentifier);
    }

    Ok(())
}

fn validate_ssef_file_format_version(src_file: &mut File) -> Result<()> {
    let mut file_format_version_buffer = [0u8; 2];
    src_file.seek(SeekFrom::Start(2))?;
    src_file.read(&mut file_format_version_buffer)?;
    let file_format_version =
        file_format_version_buffer[0] as u16 | (file_format_version_buffer[1] as u16) << 8;
    if file_format_version != 1 {
        return Err(Error::UnsupportedSSEFFormatVersion);
    }

    Ok(())
}

/// Gets the metadata section of an SSEF file into a struct. Note that this file moves the
/// pointer of a file.
pub fn get_metadata_section_from_ssef_file(src_file: &mut File) -> Result<SSEFMetadata> {
    // Make sure we are start looking after the file identifier and file format version bytes.
    src_file.seek(SeekFrom::Start(4))?;

    let mut metadata_length_buffer = [0u8; 2];
    src_file.read(&mut metadata_length_buffer)?;

    let metadata_length =
        metadata_length_buffer[0] as u16 | (metadata_length_buffer[1] as u16) << 8;

    // Entire metadata, as per specs, can fit comfortably within memory. We can safely load it in.
    let mut metadata = vec![0u8; metadata_length as usize];
    src_file.read(&mut metadata)?;

    let mut metadata_index = 0;
    let mut filename = String::new();
    let mut salt: Vec<u8> = vec![];
    let mut nonce = AES256GCMNonce::default();
    while metadata_index < metadata.len() {
        let id = [metadata[metadata_index], metadata[metadata_index + 1]];

        let length_bytes = [metadata[metadata_index + 2], metadata[metadata_index + 3]];
        let length = (length_bytes[0] as u16 | (length_bytes[1] as u16) << 8) as usize;

        let value = metadata[(metadata_index + 4)..(metadata_index + length + 4)].to_vec();

        match id {
            [0x00, 0x01] => {
                filename = String::from_utf8(value)?;
            }
            [0xA5, 0x19] => {
                salt = Vec::from(value);
            }
            [0x90, 0x9C] => {
                nonce = value.try_into().map_err(|_| Error::InvalidNonceLength)?;
            }
            _ => {}
        }

        metadata_index += length + 4;
    }

    Ok(SSEFMetadata {
        filename,
        salt,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Seek;

    use rand::{rngs::OsRng, RngCore};
    use tempfile::{tempdir, tempfile};

    use crate::fs::{File, FileAccessOptions};

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
        writeln!(src_file, "{}", contents).unwrap();

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
        writeln!(src_file, "{}", contents).unwrap();

        // We need to wind back the file pointer in src_file since we wrote contents to it.
        src_file.rewind().unwrap();

        let key =
            create_key_from_password(b"tale-as-old-as-time", b"song-as-old-as-rhyme").unwrap();
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
        let key = create_key_from_password(b"why-do-birds", b"suddenly-appear").unwrap();
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
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypting_an_empty_file_fails() {
        let key =
            create_key_from_password(b"isn't she lovelyyyy", b"isn't-she-wonderfulll").unwrap();
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
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidSSEFFile)));
    }

    #[test]
    fn test_creating_metadata_section_encrypted_file_succeeds() {
        const SRC_FILENAME: &str = "test-source-file.txt";
        let dir = tempdir().unwrap();

        let src_file_path = dir.path().join(SRC_FILENAME);
        let src_file = File::open(src_file_path, FileAccessOptions::ReadWriteCreate).unwrap();

        let salt = b"you-cant-hurry-love";

        let mut nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut nonce);

        let res = create_metadata_section_for_encrypted_file(&src_file, salt, &nonce);
        assert!(res.is_ok());

        let section = res.unwrap();

        let file_header_start = 0;
        let file_header_end = file_header_start + 4;
        let file_header_indices = file_header_start..file_header_end;

        let metadata_len_start = file_header_end;
        let metadata_len_end = metadata_len_start + 2;
        let metadata_len_indices = metadata_len_start..metadata_len_end;

        // Four bytes used for file identifier and format version. Another two bytes for the bytes
        // specifying the metadata section length.
        let metadata_length = section.len() - 6;
        let metadata_length_bytes = [metadata_length as u8, (metadata_length >> 8 & 0xFF) as u8];

        let filename_key_start = metadata_len_end;
        let filename_key_end = filename_key_start + 2;
        let filename_key_indices = filename_key_start..filename_key_end;

        let filename_len_start = filename_key_end;
        let filename_len_end = filename_len_start + 2;
        let filename_len_indices = filename_len_start..filename_len_end;

        let filename_len_bytes = [
            SRC_FILENAME.len() as u8,
            (SRC_FILENAME.len() >> 8 & 0xFF) as u8,
        ];

        let filename_val_start = filename_len_end;
        let filename_val_end = filename_val_start + SRC_FILENAME.len();
        let filename_val_indices = filename_val_start..filename_val_end;

        let salt_key_start = filename_val_end;
        let salt_key_end = salt_key_start + 2;
        let salt_key_indices = salt_key_start..salt_key_end;

        let salt_len_start = salt_key_end;
        let salt_len_end = salt_len_start + 2;
        let salt_len_indices = salt_len_start..salt_len_end;

        let salt_len_bytes = [salt.len() as u8, (salt.len() >> 8 & 0xFF) as u8];

        let salt_val_start = salt_len_end;
        let salt_val_end = salt_val_start + salt.len();
        let salt_val_indices = salt_val_start..salt_val_end;

        let nonce_key_start = salt_val_end;
        let nonce_key_end = nonce_key_start + 2;
        let nonce_key_indices = nonce_key_start..nonce_key_end;

        let nonce_len_start = nonce_key_end;
        let nonce_len_end = nonce_len_start + 2;
        let nonce_len_indices = nonce_len_start..nonce_len_end;

        let nonce_len_bytes = [nonce.len() as u8, (nonce.len() >> 8 & 0xFF) as u8];

        let nonce_val_start = nonce_len_end;
        let nonce_val_end = nonce_val_start + nonce.len();
        let nonce_val_indices = nonce_val_start..nonce_val_end;

        assert_eq!(section[file_header_indices], [0x55, 0x3F, 0x01, 0x00]);

        assert_eq!(section[metadata_len_indices], metadata_length_bytes[0..2]);

        assert_eq!(section[filename_key_indices], [0x00, 0x01]);
        assert_eq!(section[filename_len_indices], filename_len_bytes[0..2]);
        assert_eq!(
            section[filename_val_indices],
            SRC_FILENAME.as_bytes()[0..SRC_FILENAME.len()]
        );

        assert_eq!(section[salt_key_indices], [0xA5, 0x19]);
        assert_eq!(section[salt_len_indices], salt_len_bytes[0..2]);
        assert_eq!(section[salt_val_indices], salt[0..salt.len()]);

        assert_eq!(section[nonce_key_indices], [0x90, 0x9C]);
        assert_eq!(section[nonce_len_indices], nonce_len_bytes[0..2]);
        assert_eq!(section[nonce_val_indices], nonce[0..nonce.len()]);
    }

    #[test]
    fn test_creating_filename_metadata_item_creates_correct_metadata() {
        const FILENAME: &str = "test-source-file.txt";
        let dir = tempdir().unwrap();
        let file_path = dir.path().join(FILENAME);
        let file = File::open(file_path, FileAccessOptions::ReadWriteCreate).unwrap();

        let res = create_filename_metadata_item(&file);
        assert!(res.is_ok());

        let metadata = res.unwrap();
        let len_bytes = [FILENAME.len() as u8, (FILENAME.len() >> 8 & 0xFF) as u8];

        assert_eq!(metadata[0..2], [0x00, 0x01]);
        assert_eq!(metadata[2..4], len_bytes[0..len_bytes.len()]);
        assert_eq!(
            metadata[4..FILENAME.len() + 4],
            FILENAME.as_bytes()[0..FILENAME.len()]
        );
    }

    #[test]
    fn test_creating_salt_metadata_item_succeeds() {
        let salt = b"you-cant-hurry-love";
        let metadata = create_salt_metadata_item(salt);
        let len_bytes = [salt.len() as u8, (salt.len() >> 8 & 0xFF) as u8];
        assert_eq!(metadata[0..2], [0xA5, 0x19]);
        assert_eq!(metadata[2..4], len_bytes);
        assert_eq!(metadata[4..salt.len() + 4], salt[0..salt.len()]);
    }

    #[test]
    fn test_creating_nonce_metadata_item_succeeds() {
        let mut nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut nonce);

        let metadata = create_nonce_metadata_item(&nonce);
        let len_bytes = [nonce.len() as u8, (nonce.len() >> 8 & 0xFF) as u8];

        assert_eq!(metadata[0..2], [0x90, 0x9C]);
        assert_eq!(metadata[2..4], len_bytes);
        assert_eq!(metadata[4..nonce.len() + 4], nonce);
    }

    #[test]
    fn test_validating_ssef_file_identifier_succeeds() {
        let mut file = File::from(tempfile().unwrap());
        file.write_all(&[0x55, 0x3F, 0x01, 0x00]).unwrap();
        file.rewind().unwrap();

        let res = validate_ssef_file_identifier(&mut file);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validating_ssef_with_wrong_file_identifier_fails() {
        let mut file = File::from(tempfile::tempfile().unwrap());
        file.write_all(&[0x3F, 0x55, 0x01, 0x00]).unwrap();
        file.rewind().unwrap();

        let res = validate_ssef_file_identifier(&mut file);
        assert!(res.is_err());
    }

    #[test]
    fn test_validating_ssef_file_format_version_succeeds() {
        let mut file = File::from(tempfile().unwrap());
        file.write_all(&[0x55, 0x3F, 0x01, 0x00]).unwrap();
        file.rewind().unwrap();

        let res = validate_ssef_file_format_version(&mut file);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validating_ssef_with_unsupported_file_format_version_fails() {
        let mut file = File::from(tempfile().unwrap());
        file.write_all(&[0x3F, 0x55, 0x01, 0x01]).unwrap();
        file.rewind().unwrap();

        let res = validate_ssef_file_format_version(&mut file);
        assert!(res.is_err());
    }

    #[test]
    fn test_getting_metadata_section_from_ssef_file_succeeds() {
        const FILENAME: &str = "some-test-source-file.txt";
        let dir = tempdir().unwrap();
        let file_path = dir.path().join(FILENAME);
        let mut src_file = File::open(file_path, FileAccessOptions::ReadWriteCreate).unwrap();
        let contents = b"tale as old as time, true as it can be";
        src_file.write_all(contents).unwrap();

        let mut encrypted_file = File::from(tempfile().unwrap());

        // We need to wind back the file pointer in src_file since we wrote contents to it.
        src_file.rewind().unwrap();

        let password = b"barely even friends";
        let salt = b"then somebody bends";
        let mut aes_nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut aes_nonce);

        const BUFFER_LEN: usize = 1_048_576; // Equals to 1 MiB.

        let encryption_result = encrypt_to_ssef_file(
            &mut src_file,
            &mut encrypted_file,
            password,
            salt,
            &aes_nonce,
            &BUFFER_LEN,
            None,
            None,
            None,
        );
        assert!(encryption_result.is_ok());

        // We need to wind back the file pointer in encrypted_file since we wrote contents to it.
        encrypted_file.rewind().unwrap();

        let ssef_metadata = get_metadata_section_from_ssef_file(&mut encrypted_file).unwrap();
        assert_eq!(ssef_metadata.filename, FILENAME);
        assert_eq!(ssef_metadata.salt.as_slice(), &salt[0..salt.len()]);
        assert_eq!(
            ssef_metadata.nonce.as_slice(),
            &aes_nonce[0..aes_nonce.len()]
        );
    }
}
