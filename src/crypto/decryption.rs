// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
use std::io::{Read, Seek};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use aead::KeyInit;
use aead::stream::DecryptorBE32;
use aes_gcm::Aes256Gcm;
use crate::constants::AUTH_TAG_BYTES_LEN;

use crate::crypto::common::AES256GCMNonce;
use crate::crypto::keys::{is_password_correct, SusiKey};
use crate::crypto::ssef::{get_metadata_section_from_ssef_file, validate_ssef_file_format_version, validate_ssef_file_identifier};
use crate::errors;
use crate::errors::Error;
use crate::fs::File;

pub fn decrypt_from_ssef_file(
    src_file: &mut File,
    dest_file: &mut File,
    password: &[u8],
    buffer_len: &usize,
    num_read_bytes: Option<Arc<AtomicUsize>>,
    num_written_bytes: Option<Arc<AtomicUsize>>,
    num_processed_bytes: Option<Arc<AtomicUsize>>,
    should_stop: Option<Arc<AtomicBool>>,
) -> errors::Result<()> {
    tracing::info!(
        "Decrypting file, {}, to {}",
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
            "Unable to rewind original file",
            dest_file.path().clone(),
            Arc::new(e),
        )
    })?;

    validate_ssef_file_identifier(src_file)?;
    validate_ssef_file_format_version(src_file)?;

    let metadata = get_metadata_section_from_ssef_file(src_file)?;
    if !is_password_correct(password, metadata.salt.as_slice(), &metadata.mac)? {
        return Err(Error::IncorrectPassword);
    }

    let key = SusiKey::new(password, metadata.salt.as_slice())?;
    let nonce: AES256GCMNonce = metadata.nonce.into();

    decrypt_file(
        src_file,
        dest_file,
        &key,
        &nonce,
        buffer_len,
        num_read_bytes,
        num_written_bytes,
        num_processed_bytes,
        should_stop,
    )?;

    Ok(())
}

pub(super) fn decrypt_file(
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
    let decryption_buffer_len: usize = buffer_len + AUTH_TAG_BYTES_LEN;

    let aead = Aes256Gcm::new(key.key.as_ref().into());
    let mut stream_decryptor = DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = vec![0u8; decryption_buffer_len];

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

        let read_count = src_file.read(&mut buffer)?;

        if let Some(ref num_bytes) = num_read_bytes {
            num_bytes.fetch_add(read_count, Ordering::Relaxed);
        }

        if read_count == 0 {
            break;
        } else if read_count == decryption_buffer_len {
            let decrypted = stream_decryptor.decrypt_next(buffer.as_slice())?;
            let write_count = dest_file.write_data(&decrypted)?;

            if let Some(ref num_bytes) = num_written_bytes {
                num_bytes.fetch_add(write_count, Ordering::Relaxed);
            }
            if let Some(ref num_bytes) = num_processed_bytes {
                num_bytes.fetch_add(read_count, Ordering::Relaxed);
            }
        } else {
            let decrypted = stream_decryptor.decrypt_last(&buffer[..read_count])?;
            let write_count = dest_file.write_data(&decrypted)?;

            if let Some(num_bytes) = num_written_bytes {
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
