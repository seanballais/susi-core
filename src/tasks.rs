use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use once_cell::sync::Lazy;

use rand::{rngs::OsRng, RngCore};
use uuid::Uuid;

use crate::crypto::{
    decrypt_from_ssef_file, encrypt_to_ssef_file, AES256GCMNonce, IO_BUFFER_LEN, SALT_LENGTH,
};
use crate::ds::{FIFOQueue, Queue};
use crate::errors::Result;

pub type TaskObject = Box<dyn Task + Send>;
pub type TaskFIFOQueue = FIFOQueue<TaskObject>;

// We're not using OnceLock here since FIFOQueue is already thread-safe. Any further locking may
// affect performance.
pub static TASK_QUEUE: Lazy<TaskFIFOQueue> = Lazy::new(|| { FIFOQueue::new() });

#[cfg(test)]
#[derive(Debug, PartialEq)]
pub enum TestTaskType {
    Encryption,
    Decryption,
}

#[derive(Debug, Eq, Clone, Copy)]
pub struct TaskID {
    upper_id: u64,
    lower_id: u64
}

impl TaskID {
    pub fn new() -> Self {
        //Uuid::new_v4().as_u128()
        let (upper_id, lower_id) = Uuid::new_v4().as_u64_pair();
        Self { upper_id, lower_id }
    }
}

impl PartialEq for TaskID {
    fn eq(&self, other: &Self) -> bool {
        self.upper_id == other.upper_id && self.lower_id == other.lower_id
    }
}

pub trait Task {
    fn run(
        &mut self,
        num_read_bytes: Option<&mut AtomicUsize>,
        num_written_bytes: Option<&mut AtomicUsize>,
        should_stop: Option<&mut AtomicBool>,
    ) -> Result<()>;

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType;

    #[cfg(test)]
    fn get_task_id(&self) -> TaskID;
}

#[derive(Debug)]
pub struct EncryptionTask {
    id: TaskID,
    src_file: File,
    dest_file: File,
    password: Vec<u8>,
    salt: Vec<u8>,
    nonce: AES256GCMNonce,
    buffer_len: usize,
}

impl EncryptionTask {
    pub fn new(id: TaskID, src_file: File, dest_file: File, password: Vec<u8>) -> Self {
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

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType {
        TestTaskType::Encryption
    }

    #[cfg(test)]
    fn get_task_id(&self) -> TaskID { self.id }
}

#[derive(Debug)]
pub struct DecryptionTask {
    id: TaskID,
    src_file: File,
    dest_file: File,
    password: Vec<u8>,
    buffer_len: usize,
}

impl DecryptionTask {
    pub fn new(id: TaskID, src_file: File, dest_file: File, password: Vec<u8>) -> Self {
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
            should_stop,
        )
    }

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType {
        TestTaskType::Decryption
    }

    #[cfg(test)]
    fn get_task_id(&self) -> TaskID { self.id }
}

#[cfg(test)]
mod tests {
    use super::*;
}
