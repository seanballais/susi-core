use std::io::{Read, Seek, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use aead::KeyInit;
use aead::stream::EncryptorBE32;
use aes_gcm::Aes256Gcm;

use crate::crypto::common::AES256GCMNonce;
use crate::crypto::keys::SusiKey;
use crate::crypto::ssef::create_metadata_section_for_encrypted_file;
use crate::errors;
use crate::errors::Error;
use crate::fs::File;

pub fn encrypt_to_ssef_file(
    src_file: &mut File,
    dest_file: &mut File,
    password: &[u8],
    salt: &[u8],
    nonce: &AES256GCMNonce,
    buffer_len: &usize,
    num_read_bytes: Option<Arc<AtomicUsize>>,
    num_written_bytes: Option<Arc<AtomicUsize>>,
    num_processed_bytes: Option<Arc<AtomicUsize>>,
    should_stop: Option<Arc<AtomicBool>>,
) -> errors::Result<()> {
    tracing::info!(
        "Encrypting file, {}, to {}",
        src_file.path_or_empty().display(),
        dest_file.path_or_empty().display()
    );

    // Let's just rewind the files back to make sure.
    src_file.rewind().map_err(|e| {
        errors::IO::new(
            "Unable to rewind original file",
            src_file.path().clone(),
            Arc::from(e),
        )
    })?;
    dest_file.rewind().map_err(|e| {
        errors::IO::new(
            "Unable to rewind file",
            dest_file.path().clone(),
            Arc::new(e),
        )
    })?;

    let key = SusiKey::new(password, salt)?;
    let header = create_metadata_section_for_encrypted_file(src_file, salt, &key.mac, nonce)?;

    dest_file.write_all(header.as_slice()).map_err(|e| {
        errors::IO::new(
            "Unable to write the header",
            dest_file.path().clone(),
            Arc::from(e),
        )
    })?;

    encrypt_file(
        src_file,
        dest_file,
        &key,
        &nonce,
        &buffer_len,
        num_read_bytes,
        num_written_bytes,
        num_processed_bytes,
        should_stop,
    )?;

    Ok(())
}

pub(super) fn encrypt_file(
    src_file: &mut File,
    dest_file: &mut File,
    key: &SusiKey,
    nonce: &AES256GCMNonce,
    buffer_len: &usize,
    num_read_bytes: Option<Arc<AtomicUsize>>,
    num_written_bytes: Option<Arc<AtomicUsize>>,
    num_processed_bytes: Option<Arc<AtomicUsize>>,
    should_stop: Option<Arc<AtomicBool>>,
) -> errors::Result<()> {
    let aead = Aes256Gcm::new(key.key.as_ref().into());
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

        let read_count = src_file.read(&mut buffer)?;

        if let Some(ref num_bytes) = num_read_bytes {
            num_bytes.fetch_add(read_count, Ordering::Relaxed);
        }

        if read_count == 0 {
            // Huh. This must be empty. No matter. Let's just finish the operation.
            break;
        } else if read_count == *buffer_len {
            let encrypted = stream_encryptor.encrypt_next(buffer.as_slice())?;
            let write_count = dest_file.write_data(&encrypted)?;
            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, Ordering::Relaxed);
            }
            if let Some(ref num_bytes) = num_processed_bytes {
                num_bytes.fetch_add(read_count, Ordering::Relaxed);
            }
        } else {
            let encrypted = stream_encryptor.encrypt_last(&buffer[..read_count])?;
            let write_count = dest_file.write(&encrypted)?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, Ordering::Relaxed);
            }
            if let Some(ref num_bytes) = num_processed_bytes {
                num_bytes.fetch_add(read_count, Ordering::Relaxed);
            }

            break;
        }
    }

    Ok(())
}
