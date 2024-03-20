use std::collections::VecDeque;
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Condvar, Mutex};

use rand::{rngs::OsRng, RngCore};
use tracing;

use crate::crypto::{encrypt_to_ssef_file, AES256GCMNonce, IO_BUFFER_LEN, SALT_LENGTH, decrypt_from_ssef_file};
use crate::error::Result;

pub trait Task {
    fn run(
        &mut self,
        num_read_bytes: Option<&mut AtomicUsize>,
        num_written_bytes: Option<&mut AtomicUsize>,
        should_stop: Option<&mut AtomicBool>,
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct EncryptionTask {
    id: u32,
    src_file: File,
    dest_file: File,
    password: Vec<u8>,
    salt: Vec<u8>,
    nonce: AES256GCMNonce,
    buffer_len: usize,
}

impl EncryptionTask {
    pub fn new(id: u32, src_file: File, dest_file: File, password: Vec<u8>) -> Self {
        let mut salt: Vec<u8> = Vec::with_capacity(SALT_LENGTH);
        OsRng.fill_bytes(salt.as_mut_slice());

        let mut nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut nonce);

        Self {
            id,
            src_file,
            dest_file,
            password,
            salt,
            nonce,
            buffer_len: IO_BUFFER_LEN,
        }
    }
}

impl Task for EncryptionTask {
    fn run(
        &mut self,
        num_read_bytes: Option<&mut AtomicUsize>,
        num_written_bytes: Option<&mut AtomicUsize>,
        should_stop: Option<&mut AtomicBool>,
    ) -> Result<()> {
        encrypt_to_ssef_file(
            &mut self.src_file,
            &mut self.dest_file,
            self.password.as_slice(),
            self.salt.as_slice(),
            &self.nonce,
            &self.buffer_len,
            num_read_bytes,
            num_written_bytes,
            should_stop,
        )
    }
}

#[derive(Debug)]
pub struct DecryptionTask {
    id: u32,
    src_file: File,
    dest_file: File,
    password: Vec<u8>,
    buffer_len: usize,
}

impl DecryptionTask {
    pub fn new(id: u32, src_file: File, dest_file: File, password: Vec<u8>) -> Self {
        Self {
            id,
            src_file,
            dest_file,
            password,
            buffer_len: IO_BUFFER_LEN,
        }
    }
}

impl Task for DecryptionTask {
    fn run(
        &mut self,
        num_read_bytes: Option<&mut AtomicUsize>,
        num_written_bytes: Option<&mut AtomicUsize>,
        should_stop: Option<&mut AtomicBool>,
    ) -> Result<()> {
        decrypt_from_ssef_file(
            &mut self.src_file,
            &mut self.dest_file,
            self.password.as_slice(),
            &self.buffer_len,
            num_read_bytes,
            num_written_bytes,
            should_stop
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
