use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rand::{rngs::OsRng, RngCore};
use uuid::Uuid;

use crate::crypto::{
    decrypt_from_ssef_file, encrypt_to_ssef_file, AES256GCMNonce, IO_BUFFER_LEN, SALT_LENGTH,
};
use crate::ds::{FIFOQueue, Queue};
use crate::errors::{Error, Result};

pub type TaskObject = Box<dyn Task + Send>;
pub type TaskFIFOQueue = FIFOQueue<TaskObject>;

pub static TASK_MANAGER: OnceLock<Mutex<TaskManager>> = OnceLock::new();

pub fn init_task_manager() {
    TASK_MANAGER.get_or_init(|| { Mutex::new(TaskManager::new()) });
}

pub trait Task {
    fn run(
        &mut self,
        num_read_bytes: Option<Arc<AtomicUsize>>,
        num_written_bytes: Option<Arc<AtomicUsize>>,
        should_stop: Option<Arc<AtomicBool>>,
    ) -> Result<()>;

    fn get_id(&self) -> TaskID;

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType;
}

pub struct TaskManager {
    task_queue: TaskFIFOQueue,
    task_statuses: HashMap<TaskID, TaskStatus>
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            task_queue: TaskFIFOQueue::new(),
            task_statuses: HashMap::new()
        }
    }

    pub fn queue_encryption_task(&mut self, src_file: File, dest_file: File, password: Vec<u8>) -> TaskID {
        let id = TaskID::new();
        let task = EncryptionTask::new(id, src_file, dest_file, password);
        self.queue_task(Box::new(task));

        let status = TaskStatus::new();
        self.task_statuses.insert(id, status);

        id
    }

    pub fn pop_task(&mut self) -> TaskObject {
        self.task_queue.pop()
    }

    pub fn get_task_status(&mut self, id: TaskID) -> Option<&mut TaskStatus> {
        self.task_statuses.get_mut(&id)
    }

    pub fn num_tasks(&self) -> usize {
        self.task_queue.len()
    }

    fn queue_task(&mut self, task: TaskObject) -> TaskID {
        let id = task.get_id().clone();
        self.task_queue.push(task);

        id
    }
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
        num_read_bytes: Option<Arc<AtomicUsize>>,
        num_written_bytes: Option<Arc<AtomicUsize>>,
        should_stop: Option<Arc<AtomicBool>>
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

    fn get_id(&self) -> TaskID { self.id }

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType {
        TestTaskType::Encryption
    }
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
        num_read_bytes: Option<Arc<AtomicUsize>>,
        num_written_bytes: Option<Arc<AtomicUsize>>,
        should_stop: Option<Arc<AtomicBool>>
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

    fn get_id(&self) -> TaskID { self.id }

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType {
        TestTaskType::Decryption
    }
}

#[derive(Debug, Eq, Clone, Copy, Hash)]
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

impl Display for TaskID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.upper_id, self.lower_id)
    }
}

impl PartialEq for TaskID {
    fn eq(&self, other: &Self) -> bool {
        self.upper_id == other.upper_id && self.lower_id == other.lower_id
    }
}

#[derive(Debug)]
pub struct TaskStatus {
    num_read_bytes: Arc<AtomicUsize>,
    num_written_bytes: Arc<AtomicUsize>,
    should_stop: Arc<AtomicBool>,
    last_error: Mutex<Error>,
    progress: Mutex<TaskProgress>
}

impl TaskStatus {
    pub fn new() -> Self {
        Self {
            num_read_bytes: Arc::new(AtomicUsize::new(0)),
            num_written_bytes: Arc::new(AtomicUsize::new(0)),
            should_stop: Arc::new(AtomicBool::new(false)),
            last_error: Mutex::new(Error::None),
            progress: Mutex::new(TaskProgress::QUEUED)
        }
    }

    pub fn get_num_read_bytes_ref(&self) -> Arc<AtomicUsize> {
        self.num_read_bytes.clone()
    }

    pub fn get_num_written_bytes_ref(&self) -> Arc<AtomicUsize> {
        self.num_written_bytes.clone()
    }

    pub fn get_should_stop_ref(&self) -> Arc<AtomicBool> {
        self.should_stop.clone()
    }

    pub fn get_last_error(&self) -> Error {
        self.last_error.lock().unwrap().clone()
    }

    pub fn get_progress(&self) -> TaskProgress {
        self.progress.lock().unwrap().clone()
    }

    pub fn set_last_error(&mut self, error: Error) {
        let mut last_error = self.last_error.lock().unwrap();
        *last_error = error;
    }

    pub fn set_progress(&mut self, new_progress: TaskProgress) {
        let mut progress = self.progress.lock().unwrap();
        *progress = new_progress;
    }

    pub fn clear(&mut self) {
        self.num_read_bytes.store(0, Ordering::Relaxed);
        self.num_written_bytes.store(0, Ordering::Relaxed);
        self.should_stop.store(false, Ordering::Relaxed);
        self.last_error = Mutex::new(Error::None);
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TaskProgress {
    QUEUED,
    RUNNING,
    DONE
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
pub enum TestTaskType {
    Encryption,
    Decryption,
}

#[cfg(test)]
mod tests {
}
