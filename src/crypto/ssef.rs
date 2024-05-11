use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::crypto::common::AES256GCMNonce;
use crate::crypto::keys::{MAC, MAC_SIZE};
use crate::errors::Error;
use crate::fs::File;

pub struct SSEFMetadata {
    pub filename: String,
    pub salt: Vec<u8>,
    pub mac: [u8; MAC_SIZE],
    pub nonce: AES256GCMNonce,
}

/// Gets the metadata section of an SSEF file into a struct. Note that this file moves the
/// pointer of a file.
pub fn get_metadata_section_from_ssef_file(src_file: &mut File) -> crate::errors::Result<SSEFMetadata> {
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
    let mut mac = MAC::default();
    let mut nonce = AES256GCMNonce::default();
    while metadata_index < metadata.len() {
        let id = [metadata[metadata_index], metadata[metadata_index + 1]];

        let length_bytes = [metadata[metadata_index + 2], metadata[metadata_index + 3]];
        let length = (length_bytes[0] as u16 | (length_bytes[1] as u16) << 8) as usize;

        let value = &metadata[(metadata_index + 4)..(metadata_index + length + 4)];

        match id {
            [0x00, 0x01] => {
                filename = String::from_utf8(value.to_vec())?;
            },
            [0xA5, 0x19] => {
                salt = value.to_vec();
            },
            [0x44, 0xAC] => {
                mac = value.try_into().map_err(|e| Error::MACNotObtained(Arc::new(e)))?;
            }
            [0x90, 0x9C] => {
                nonce = value.try_into().map_err(|e| Error::NonceNotObtained(Arc::new(e)))?;
            }
            _ => {}
        }

        metadata_index += length + 4;
    }

    Ok(SSEFMetadata {
        filename,
        salt,
        mac,
        nonce,
    })
}

pub fn create_metadata_section_for_encrypted_file(
    src_file: &File,
    salt: &[u8],
    key_mac: &MAC,
    nonce: &AES256GCMNonce,
) -> crate::errors::Result<Vec<u8>> {
    // File identifier = first two bytes (big-endian)
    // Format version = last two bytes (little-endian)
    let header: Vec<u8> = vec![0x55, 0x3F, 0x01, 0x00];

    let filename_metadata = create_filename_metadata_item(src_file)?;
    let salt_metadata = create_salt_metadata_item(salt);
    let key_mac_metadata = create_key_mac_metadata_item(key_mac);
    let nonce_metadata = create_nonce_metadata_item(nonce);
    let metadata_length = filename_metadata.len()
        + salt_metadata.len()
        + key_mac_metadata.len()
        + nonce_metadata.len();

    // Plus six to include header and metadata length
    let mut metadata_section: Vec<u8> = Vec::with_capacity(metadata_length + 6);
    metadata_section.extend(header.iter());
    metadata_section.push((metadata_length & 0xFF) as u8);
    metadata_section.push((metadata_length >> 8 & 0xFF) as u8);
    metadata_section.extend(filename_metadata.iter());
    metadata_section.extend(salt_metadata.iter());
    metadata_section.extend(key_mac_metadata.iter());
    metadata_section.extend(nonce_metadata.iter());

    Ok(metadata_section)
}

pub fn create_filename_metadata_item(src_file: &File) -> crate::errors::Result<Vec<u8>> {
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

pub fn create_salt_metadata_item(salt: &[u8]) -> Vec<u8> {
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

pub fn create_key_mac_metadata_item(mac: &[u8]) -> Vec<u8> {
    let mut metadata: Vec<u8> = Vec::with_capacity(4 + mac.len());
    metadata.push(0x44);
    metadata.push(0xAC);

    // Get the first byte of the length.
    metadata.push((mac.len() & 0xFF) as u8);

    // Get the second byte of the length.
    metadata.push((mac.len() >> 8 & 0xFF) as u8);

    metadata.extend_from_slice(mac);

    metadata
}

pub fn create_nonce_metadata_item(nonce: &AES256GCMNonce) -> Vec<u8> {
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

pub fn validate_ssef_file_identifier(src_file: &mut File) -> crate::errors::Result<()> {
    let mut file_identifier_buffer = [0u8; 2];
    src_file.read(&mut file_identifier_buffer)?;
    if file_identifier_buffer != [0x55, 0x3F] {
        return Err(Error::InvalidSSEFFileIdentifier);
    }

    Ok(())
}

pub fn validate_ssef_file_format_version(src_file: &mut File) -> crate::errors::Result<()> {
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

#[cfg(test)]
mod tests {
    use std::io::Seek;
    use rand::{rngs::OsRng, RngCore};
    use tempfile::{tempdir, tempfile};

    use crate::crypto::common::AES256GCMNonce;
    use crate::crypto::encryption::encrypt_to_ssef_file;
    use crate::crypto::keys::SusiKey;
    use crate::crypto::ssef::{
        create_filename_metadata_item,
        create_key_mac_metadata_item,
        create_metadata_section_for_encrypted_file,
        create_nonce_metadata_item,
        create_salt_metadata_item,
        get_metadata_section_from_ssef_file,
        validate_ssef_file_format_version,
        validate_ssef_file_identifier
    };
    use crate::fs::{File, FileAccessOptions};

    #[test]
    fn test_creating_metadata_section_encrypted_file_succeeds() {
        const SRC_FILENAME: &str = "test-source-file.txt";
        let dir = tempdir().unwrap();

        let src_file_path = dir.path().join(SRC_FILENAME);
        let src_file = File::open(src_file_path, FileAccessOptions::ReadWriteCreate).unwrap();

        let salt = b"i'm okay i'm fine gwenchana gwenchana teng teng neng neng neng";
        let res = SusiKey::new(b"aykaramba123", salt);
        assert!(res.is_ok());

        let key = res.unwrap();

        let mut nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut nonce);

        let res = create_metadata_section_for_encrypted_file(&src_file, salt, &key.mac, &nonce);
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

        let mac_key_start = salt_val_end;
        let mac_key_end = mac_key_start + 2;
        let mac_key_indices = mac_key_start..mac_key_end;

        let mac_len_start = mac_key_end;
        let mac_len_end = mac_len_start + 2;
        let mac_len_indices = mac_len_start..mac_len_end;

        let mac_len_bytes = [key.mac.len() as u8, (key.mac.len() >> 8 & 0xFF) as u8];

        let mac_val_start = mac_len_end;
        let mac_val_end = mac_val_start + key.mac.len();
        let mac_val_indices = mac_val_start..mac_val_end;

        let nonce_key_start = mac_val_end;
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

        assert_eq!(section[mac_key_indices], [0x44, 0xAC]);
        assert_eq!(section[mac_len_indices], mac_len_bytes[0..2]);
        assert_eq!(section[mac_val_indices], key.mac[0..key.mac.len()]);

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
    fn test_creating_mac_metadata_item_succeeds() {
        let password = b"sige na please wag nang mainis";
        let salt = b"you fill up my senses, like the night in the forest";
        let res = SusiKey::new(password, salt);
        assert!(res.is_ok());

        let key = res.unwrap();
        let metadata = create_key_mac_metadata_item(&key.mac);
        let len_bytes = [key.mac.len() as u8, (key.mac.len() >> 8 & 0xFF) as u8];
        assert_eq!(metadata[0..2], [0x44, 0xAC]);
        assert_eq!(metadata[2..4], len_bytes);
        assert_eq!(metadata[4..key.mac.len() + 4], key.mac[0..key.mac.len()]);
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
        file.write_data(&[0x55, 0x3F, 0x01, 0x00]).unwrap();
        file.rewind().unwrap();

        let res = validate_ssef_file_identifier(&mut file);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validating_ssef_with_wrong_file_identifier_fails() {
        let mut file = File::from(tempfile::tempfile().unwrap());
        file.write_data(&[0x3F, 0x55, 0x01, 0x00]).unwrap();
        file.rewind().unwrap();

        let res = validate_ssef_file_identifier(&mut file);
        assert!(res.is_err());
    }

    #[test]
    fn test_validating_ssef_file_format_version_succeeds() {
        let mut file = File::from(tempfile().unwrap());
        file.write_data(&[0x55, 0x3F, 0x01, 0x00]).unwrap();
        file.rewind().unwrap();

        let res = validate_ssef_file_format_version(&mut file);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validating_ssef_with_unsupported_file_format_version_fails() {
        let mut file = File::from(tempfile().unwrap());
        file.write_data(&[0x3F, 0x55, 0x01, 0x01]).unwrap();
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
        src_file.write_data(contents).unwrap();

        let mut encrypted_file = File::from(tempfile().unwrap());

        // We need to wind back the file pointer in src_file since we wrote contents to it.
        src_file.rewind().unwrap();

        let password = b"bakit ba siya, at bakit di nalang ako";
        let salt = b"sanay mapansin ang aking nadarama sayo hindi lang rin ako sanay";
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

