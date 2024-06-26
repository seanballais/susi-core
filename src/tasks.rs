// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Seek;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use rand::distributions::{Alphanumeric, DistString};
use rand::{rngs::OsRng, RngCore};
use tempfile::tempfile;
use uuid::Uuid;
use crate::constants::IO_BUFFER_BYTES_LEN;
use crate::crypto::common::{AES256GCMNonce, MINIMUM_PASSWORD_LENGTH, MINIMUM_SALT_LENGTH};
use crate::crypto::decryption::decrypt_from_ssef_file;
use crate::crypto::encryption::encrypt_to_ssef_file;
use crate::crypto::keys::is_password_correct;
use crate::crypto::ssef::{get_metadata_section_from_ssef_file, validate_ssef_file_format_version, validate_ssef_file_identifier};

use crate::ds::{FIFOQueue, Queue};
use crate::errors::{Error, Result, IO};
use crate::fs::{append_file_extension_to_path, copy_file_contents, File, FileAccessOptions};

pub type TaskObject = Box<dyn Task + Send>;
pub type TaskFIFOQueue = FIFOQueue<TaskObject>;

pub static TASK_MANAGER: Lazy<TaskManager> = Lazy::new(|| TaskManager::new());

pub fn init_task_manager() {
    TASK_MANAGER.kick_start();
}

pub trait Task {
    fn run(
        &mut self,
        num_read_bytes: Option<Arc<AtomicUsize>>,
        num_written_bytes: Option<Arc<AtomicUsize>>,
        num_processed_bytes: Option<Arc<AtomicUsize>>,
        should_stop: Option<Arc<AtomicBool>>,
    ) -> Result<()>;

    fn get_id(&self) -> &TaskID;

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType;
}

pub struct TaskManager {
    task_queue: TaskFIFOQueue,
    task_statuses: Mutex<HashMap<TaskID, Arc<Mutex<TaskStatus>>>>,
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            task_queue: TaskFIFOQueue::new(),
            task_statuses: Mutex::new(HashMap::new()),
        }
    }

    // TaskManager is loaded as a lazy static, so calling function may initialize it.
    pub fn kick_start(&self) {}

    pub fn queue_encryption_task(&self, src_file: File, password: Vec<u8>) -> Result<TaskID> {
        let task = EncryptionTask::new(src_file, password)?;
        let task_id = task.id.clone();
        self.queue_task(Box::new(task));

        self.add_new_task_status(task_id.clone());

        Ok(task_id.clone())
    }

    pub fn queue_decryption_task(&self, src_file: File, password: Vec<u8>) -> Result<TaskID> {
        let task = DecryptionTask::new(src_file, password)?;
        let task_id = task.id.clone();
        self.queue_task(Box::new(task));

        self.add_new_task_status(task_id.clone());

        Ok(task_id.clone())
    }

    pub fn pop_task(&self) -> TaskObject {
        self.task_queue.pop()
    }

    pub fn get_task_status(&self, id: &TaskID) -> Option<Arc<Mutex<TaskStatus>>> {
        let mut task_statuses = self.task_statuses.lock().unwrap();
        match task_statuses.get(id) {
            Some(status) => {
                let cloned_status = status.clone();

                let status_lock = status.lock().unwrap();
                let progress = status_lock.get_progress();
                let mut should_clean = false;

                if progress == TaskProgress::Done
                    || progress == TaskProgress::Failed
                    || progress == TaskProgress::Interrupted
                {
                    // If the task is done, we should delete the task status from our storage.
                    should_clean = true;
                }

                drop(status_lock);

                // We're separating the deletion of the task status section since we want to make
                // sure that the status mutex is not locked anymore once we start deleting.
                if should_clean {
                    task_statuses.remove(id);
                }

                Some(cloned_status)
            }
            None => None,
        }
    }

    pub fn num_tasks(&self) -> usize {
        self.task_queue.len()
    }

    fn queue_task(&self, task: TaskObject) -> TaskID {
        let id = task.get_id().clone();
        self.task_queue.push(task);

        id
    }

    fn add_new_task_status(&self, id: TaskID) {
        let mut task_statuses = self.task_statuses.lock().unwrap();
        let status = TaskStatus::new();
        task_statuses.insert(id, Arc::new(Mutex::new(status)));
    }
}

unsafe impl Sync for TaskManager {}

#[derive(Debug)]
pub struct EncryptionTask {
    id: TaskID,
    src_file: File,
    password: Vec<u8>,
    salt: Vec<u8>,
    nonce: AES256GCMNonce,
    buffer_len: usize,
}

impl EncryptionTask {
    pub fn new(src_file: File, password: Vec<u8>) -> Result<Self> {
        let id = TaskID::new();

        let password_string = String::from_utf8_lossy(password.as_slice());
        if password_string.len() < MINIMUM_PASSWORD_LENGTH {
            return Err(Error::InvalidPasswordLength);
        }

        let salt = Alphanumeric
            .sample_string(&mut rand::thread_rng(), MINIMUM_SALT_LENGTH)
            .into_bytes();
        let mut nonce = AES256GCMNonce::default();
        OsRng.fill_bytes(&mut nonce);

        Ok(Self {
            id,
            src_file,
            password,
            salt,
            nonce,
            buffer_len: IO_BUFFER_BYTES_LEN,
        })
    }
}

impl Task for EncryptionTask {
    fn run(
        &mut self,
        num_read_bytes: Option<Arc<AtomicUsize>>,
        num_written_bytes: Option<Arc<AtomicUsize>>,
        num_processed_bytes: Option<Arc<AtomicUsize>>,
        should_stop: Option<Arc<AtomicBool>>,
    ) -> Result<()> {
        // Check if the final destination is not yet present.
        let dest_file_path = append_file_extension_to_path(self.src_file.path_or_empty(), "ssef");
        if dest_file_path.exists() {
            return Err(Error::FileExists(dest_file_path.clone()));
        }

        // We'll write to a temporary file first. This helps us prevent incomplete files as much as
        // possible. We'll copy the temporary file to the actual destination after the encryption
        // is complete.
        let mut temp_dest_file = File::from(tempfile()?);
        let should_stop_copy = should_stop.clone();

        encrypt_to_ssef_file(
            &mut self.src_file,
            &mut temp_dest_file,
            self.password.as_slice(),
            self.salt.as_slice(),
            &self.nonce,
            &self.buffer_len,
            num_read_bytes,
            num_written_bytes,
            num_processed_bytes,
            should_stop,
        )?;

        if let Some(stop) = should_stop_copy {
            if stop.fetch_and(true, Ordering::Relaxed) {
                return Ok(());
            }
        }

        // Then we copy to the actual destination.
        temp_dest_file.rewind()?; // We need to rewind this file since we moved the
                                  // file's cursor earlier.

        let mut dest_file = File::open(dest_file_path.clone(), FileAccessOptions::WriteCreate)?;

        tracing::info!(
            "Saving encrypted file in {} to the destination, {}",
            temp_dest_file.path_or_empty().display(),
            dest_file.path_or_empty().display()
        );

        copy_file_contents(&mut temp_dest_file, &mut dest_file)?;

        // Time to delete the source file.
        let result = fs::remove_file(self.src_file.path_or_empty());
        if result.is_err() {
            // We should remove the copied encrypted file then.
            let result = fs::remove_file(dest_file.path_or_empty());
            if result.is_err() {
                return Err(Error::IO(IO::new(
                    String::from("Unable to remove the encrypted file"),
                    dest_file.path(),
                    Arc::from(result.unwrap_err()),
                )));
            }

            return Err(Error::IO(IO::new(
                String::from("Unable to remove the original file"),
                self.src_file.path(),
                Arc::from(result.unwrap_err()),
            )));
        }

        Ok(())
    }

    fn get_id(&self) -> &TaskID {
        &self.id
    }

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType {
        TestTaskType::Encryption
    }
}

#[derive(Debug)]
pub struct DecryptionTask {
    id: TaskID,
    src_file: File,
    password: Vec<u8>,
    buffer_len: usize,
}

impl DecryptionTask {
    pub fn new(src_file: File, password: Vec<u8>) -> Result<Self> {
        let password_string = String::from_utf8_lossy(password.as_slice());
        if password_string.len() < MINIMUM_PASSWORD_LENGTH {
            return Err(Error::InvalidPasswordLength);
        }

        let id = TaskID::new();
        let mut file = src_file;

        validate_ssef_file_identifier(&mut file)?;
        validate_ssef_file_format_version(&mut file)?;

        let metadata = get_metadata_section_from_ssef_file(&mut file)?;
        if !is_password_correct(password.as_slice(), metadata.salt.as_slice(), &metadata.mac)? {
            return Err(Error::IncorrectPassword);
        }

        Ok(Self {
            id,
            src_file: file,
            password,
            buffer_len: IO_BUFFER_BYTES_LEN,
        })
    }
}

impl Task for DecryptionTask {
    fn run(
        &mut self,
        num_read_bytes: Option<Arc<AtomicUsize>>,
        num_written_bytes: Option<Arc<AtomicUsize>>,
        num_processed_bytes: Option<Arc<AtomicUsize>>,
        should_stop: Option<Arc<AtomicBool>>,
    ) -> Result<()> {
        let metadata = get_metadata_section_from_ssef_file(&mut self.src_file)?;

        // Check if the final destination is not yet present.
        let mut dest_file_path = self.src_file
            .path_or_empty()
            .parent()
            .map_or_else(|| { PathBuf::new() }, |p| { p.to_path_buf() });
        let original_filename = metadata.filename;
        dest_file_path.push(original_filename);
        if dest_file_path.exists() {
            return Err(Error::FileExists(dest_file_path.clone()));
        }

        // We'll write to a temporary file first. This helps us prevent incomplete files as much as
        // possible. We'll copy the temporary file to the actual destination after the encryption
        // is complete.
        let mut temp_dest_file = File::from(tempfile()?);
        let should_stop_copy = should_stop.clone();

        decrypt_from_ssef_file(
            &mut self.src_file,
            &mut temp_dest_file,
            self.password.as_slice(),
            &self.buffer_len,
            num_read_bytes,
            num_written_bytes,
            num_processed_bytes,
            should_stop,
        )?;

        if let Some(stop) = should_stop_copy {
            if stop.fetch_and(true, Ordering::Relaxed) {
                return Ok(());
            }
        }

        // Then we copy to the actual destination.
        // We need to rewind this file since we moved the
        // file's cursor earlier.
        temp_dest_file.rewind()?;

        let mut dest_file = File::open(dest_file_path.clone(), FileAccessOptions::WriteCreate)?;

        tracing::info!(
            "Saving decrypted file in {} to the destination, {}",
            temp_dest_file.path_or_empty().display(),
            dest_file.path_or_empty().display()
        );

        copy_file_contents(&mut temp_dest_file, &mut dest_file)?;

        // Time to delete the encrypted file.
        let result = fs::remove_file(self.src_file.path_or_empty());
        if result.is_err() {
            // We should remove the copied encrypted file then.
            let result = fs::remove_file(dest_file.path_or_empty());
            if result.is_err() {
                return Err(Error::IO(IO::new(
                    String::from("Unable to remove the decrypted file"),
                    dest_file.path(),
                    Arc::from(result.unwrap_err()),
                )));
            }

            return Err(Error::IO(IO::new(
                String::from("Unable to remove the encrypted file"),
                self.src_file.path(),
                Arc::from(result.unwrap_err()),
            )));
        }

        Ok(())
    }

    fn get_id(&self) -> &TaskID {
        &self.id
    }

    #[cfg(test)]
    fn get_task_type_for_test(&self) -> TestTaskType {
        TestTaskType::Decryption
    }
}

#[derive(Debug, Eq, Clone, Copy, Hash)]
pub struct TaskID {
    pub(crate) upper_id: u64,
    pub(crate) lower_id: u64,
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
    num_processed_bytes: Arc<AtomicUsize>,
    should_stop: Arc<AtomicBool>,
    last_error: Mutex<Error>,
    progress: Mutex<TaskProgress>,
}

impl TaskStatus {
    pub fn new() -> Self {
        Self {
            num_read_bytes: Arc::new(AtomicUsize::new(0)),
            num_written_bytes: Arc::new(AtomicUsize::new(0)),
            num_processed_bytes: Arc::new(AtomicUsize::new(0)),
            should_stop: Arc::new(AtomicBool::new(false)),
            last_error: Mutex::new(Error::None),
            progress: Mutex::new(TaskProgress::Queued),
        }
    }

    pub fn get_num_read_bytes_ref(&self) -> Arc<AtomicUsize> {
        self.num_read_bytes.clone()
    }

    pub fn get_num_written_bytes_ref(&self) -> Arc<AtomicUsize> {
        self.num_written_bytes.clone()
    }

    pub fn get_num_processed_bytes_ref(&self) -> Arc<AtomicUsize> {
        self.num_processed_bytes.clone()
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
        self.num_processed_bytes.store(0, Ordering::Relaxed);
        self.should_stop.store(false, Ordering::Relaxed);
        self.last_error = Mutex::new(Error::None);
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TaskProgress {
    Queued,
    Processing,
    Finalizing,
    Done,
    Failed,
    Interrupted,
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
pub enum TestTaskType {
    Encryption,
    Decryption,
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, Write};
    use tempfile::tempfile;

    use crate::constants::IO_BUFFER_BYTES_LEN;
    use crate::errors::Error;
    use crate::fs::{append_file_extension_to_path, File, FileAccessOptions};
    use crate::tasks::{DecryptionTask, EncryptionTask, Task, TASK_MANAGER, TaskProgress};
    use crate::testing::{create_test_file, create_test_file_path, create_test_file_with_content};
    use crate::workers::{init_worker_pool};

    #[test]
    fn test_queuing_decryption_task_with_task_manager() {
        TASK_MANAGER.kick_start();
        init_worker_pool();

        let contents = "this-is-a-test-file";
        let unencrypted_file_path = create_test_file_path("unencrypted-file.txt");
        create_test_file_with_content(unencrypted_file_path.clone(), contents);
        let unencrypted_file = File::open(
            unencrypted_file_path.clone(),
            FileAccessOptions::ReadOnly
        ).unwrap();

        let password = "adecentlysizedpassword";

        let result = TASK_MANAGER.queue_encryption_task(
            unencrypted_file,
            Vec::from(password.as_bytes())
        );
        assert!(result.is_ok());

        let encryption_task_id = result.unwrap();

        let encrypted_file_path = append_file_extension_to_path(
            unencrypted_file_path.clone(),
            ".ssef"
        );

        // Loop until encryption is done or has failed.
        loop {
            let task_status_availability = TASK_MANAGER
                .get_task_status(&encryption_task_id);
            if task_status_availability.is_none() {
                break;
            }

            let task_status = task_status_availability.unwrap();
            let status = task_status.lock().unwrap();
            let progress = status.get_progress();
            if progress == TaskProgress::Done {
                break;
            } else if progress == TaskProgress::Failed || progress == TaskProgress::Interrupted {
                panic!("Encryption for {:?} failed", unencrypted_file_path.clone());
            }

            // Release the guard to make sure the worker threads can continue processing.
            drop(status);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let encrypted_file_path = append_file_extension_to_path(
            unencrypted_file_path.clone(),
            ".ssef"
        );
        let encrypted_file = File::open(
            encrypted_file_path.clone(),
            FileAccessOptions::ReadOnly
        ).unwrap();

        let result = TASK_MANAGER.queue_decryption_task(
            encrypted_file,
            Vec::from(password.as_bytes())
        );
        assert!(result.is_ok());

        let decryption_task_id = result.unwrap();

        // Loop until decryption is done or has failed.
        loop {
            let task_status_availability = TASK_MANAGER
                .get_task_status(&decryption_task_id);
            if task_status_availability.is_none() {
                break;
            }

            let task_status = task_status_availability.unwrap();
            let status = task_status.lock().unwrap();
            let progress = status.get_progress();
            if progress == TaskProgress::Done {
                break;
            } else if progress == TaskProgress::Failed || progress == TaskProgress::Interrupted {
                panic!("Decryption for {:?} failed", encrypted_file_path.clone());
            }

            // Release the guard to make sure the worker threads can continue processing.
            drop(status);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let mut decrypted_file = File::open(
            unencrypted_file_path.clone(),
            FileAccessOptions::ReadOnly
        ).unwrap();
        let mut decrypted_contents = String::from("");
        let result = decrypted_file.read_to_string(&mut decrypted_contents);
        assert!(result.is_ok());

        assert_eq!(contents.trim(), decrypted_contents);
    }

    #[test]
    fn test_creating_new_encryption_task_properly_works_successfully() {
        const SRC_FILENAME: &str = "test-source-file.txt";

        let dir = tempfile::tempdir().unwrap();
        let src_file_path = dir.path().join(SRC_FILENAME);
        let mut src_file =
            File::open(src_file_path.clone(), FileAccessOptions::ReadWriteCreate).unwrap();

        const SRC_CONTENTS: &str = "I'm a Barbie girl in a Barbie world.";
        let res = src_file.write_all(SRC_CONTENTS.as_bytes());
        assert!(res.is_ok());

        let rewind_res = src_file.rewind();
        assert!(rewind_res.is_ok());

        let password = String::from("Shake shake shake, Signora! Shake your body line.");

        let res = EncryptionTask::new(src_file, password.into_bytes());
        assert!(res.is_ok());

        let mut task = res.unwrap();

        let mut task_src_file_contents: String = String::from("");
        let res = task.src_file.read_to_string(&mut task_src_file_contents);
        assert!(res.is_ok());

        assert_eq!(SRC_CONTENTS, task_src_file_contents.trim());
        assert!(!task.password.is_empty());
        assert!(!task.salt.is_empty());
        assert!(!task.nonce.is_empty());
        assert_eq!(task.buffer_len, IO_BUFFER_BYTES_LEN);
    }

    #[test]
    fn test_creating_new_encryption_task_with_short_password_fails() {
        let src_file = File::from(tempfile().unwrap());
        let password = String::from("short");

        let res = EncryptionTask::new(src_file, password.into_bytes());
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), Error::InvalidPasswordLength));
    }

    #[test]
    fn test_creating_new_encryption_task_with_preexisting_dest_file_fails() {
        let src_file_path = create_test_file_path("encrypted-file.txt");
        let dest_file_path = append_file_extension_to_path(src_file_path.clone(), ".ssef");
        create_test_file_with_content(src_file_path.clone(), "Spooky scary skeletons");
        create_test_file(dest_file_path);

        let src_file = File::open(src_file_path, FileAccessOptions::ReadOnly).unwrap();
        let password = String::from("miss ko na siya");
        let mut task = EncryptionTask::new(src_file, password.into_bytes()).unwrap();
        let res = task.run(None, None, None, None);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), Error::FileExists(_dest_file_path)));
    }

    #[test]
    fn test_creating_new_decryption_task_properly_works_successfully() {
        let content = "You're a small town girl.";

        let src_file_path = create_test_file_path("encrypted-file.txt");
        create_test_file_with_content(src_file_path.clone(), content.clone());

        let src_file = File::open(src_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let password = String::from("we're the king and queen of hearts");
        let mut task = EncryptionTask::new(src_file, password.clone().into_bytes()).unwrap();
        let res = task.run(None, None, None, None);
        assert!(res.is_ok());

        let dest_file_path = append_file_extension_to_path(src_file_path.clone(), ".ssef");
        let dest_file = File::open(dest_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut task = DecryptionTask::new(dest_file, password.clone().into_bytes()).unwrap();
        let res = task.run(None, None, None, None);
        assert!(res.is_ok());

        let mut src_file = File::open(src_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut retrieved_contents = String::from("");
        src_file.read_to_string(&mut retrieved_contents).unwrap();

        assert_eq!(retrieved_contents, content);
    }

    #[test]
    fn test_creating_new_decryption_task_with_short_password_fails() {
        let content = "You're a small town girl.";

        let src_file_path = create_test_file_path("encrypted-file.txt");
        create_test_file_with_content(src_file_path.clone(), content.clone());

        let src_file = File::open(src_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let password = String::from("we're the king and queen of hearts");
        let mut task = EncryptionTask::new(src_file, password.into_bytes()).unwrap();
        let res = task.run(None, None, None, None);
        assert!(res.is_ok());

        let dest_file_path = append_file_extension_to_path(src_file_path.clone(), ".ssef");
        let dest_file = File::open(dest_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let password = String::from("very short");
        let res = DecryptionTask::new(dest_file, password.into_bytes());
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), Error::InvalidPasswordLength));
    }

    #[test]
    fn test_creating_new_decryption_task_with_wrong_password_fails() {
        let content = "You're a small town girl.";

        let src_file_path = create_test_file_path("encrypted-file.txt");
        create_test_file_with_content(src_file_path.clone(), content.clone());

        let src_file = File::open(src_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let password = String::from("we're the king and queen of hearts");
        let mut task = EncryptionTask::new(src_file, password.into_bytes()).unwrap();
        let res = task.run(None, None, None, None);
        assert!(res.is_ok());

        let dest_file_path = append_file_extension_to_path(src_file_path.clone(), ".ssef");
        let dest_file = File::open(dest_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let password = String::from("wrongus passwordus");
        let res = DecryptionTask::new(dest_file, password.into_bytes());
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), Error::IncorrectPassword));
    }

    #[test]
    fn test_creating_new_decryption_task_with_preexisting_dest_file_fails() {
        let content = "You're a small town girl.";

        let src_file_path = create_test_file_path("encrypted-file.txt");
        create_test_file_with_content(src_file_path.clone(), content.clone());

        let src_file = File::open(src_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let password = String::from("we're the king and queen of hearts");
        let mut task = EncryptionTask::new(src_file, password.clone().into_bytes()).unwrap();
        let res = task.run(None, None, None, None);
        assert!(res.is_ok());

        create_test_file(src_file_path.clone());

        let dest_file_path = append_file_extension_to_path(src_file_path.clone(), ".ssef");
        let dest_file = File::open(dest_file_path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut task = DecryptionTask::new(dest_file, password.clone().into_bytes()).unwrap();
        let res = task.run(None, None, None, None);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), Error::FileExists(_)));
    }
}
