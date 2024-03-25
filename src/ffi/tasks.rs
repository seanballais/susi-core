use libc::c_char;
use std::ffi::CStr;
use std::fs::File;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use crate::ds::Queue;
use crate::errors::Error;
use crate::ffi::errors::update_last_error;
use crate::tasks::{EncryptionTask, TaskID, TASK_QUEUE};

/// Returns the value in a Result, or causes the function to return `ret_val`.
macro_rules! open_file_or_return_on_err {
    ($result: expr, $path: expr, $err_val: expr) => {
        match $result {
            Ok(f) => f,
            Err(e) => {
                update_last_error(Error::IOError(PathBuf::from($path.clone()), Arc::new(e)));
                return $err_val;
            }
        }
    };
}

#[no_mangle]
pub extern fn queue_encryption_task(
    src_file: *const c_char,
    dest_file: *const c_char,
    password: *const c_char,
) -> *mut TaskID {
    let src_file_c_str = unsafe {
        assert!(!src_file.is_null());

        CStr::from_ptr(src_file)
    };
    let src_file_path = src_file_c_str.to_string_lossy().into_owned();
    let dest_file_c_str = unsafe {
        assert!(!dest_file.is_null());

        CStr::from_ptr(dest_file)
    };
    let dest_file_path = dest_file_c_str.to_string_lossy().into_owned();
    let password_c_str = unsafe {
        assert!(!password.is_null());

        CStr::from_ptr(password)
    };
    let password_string = password_c_str.to_string_lossy().into_owned();

    let task_id = TaskID::new();
    let src_file = open_file_or_return_on_err!(
        File::options()
            .read(true)
            .write(true)
            .open(src_file_path.clone()),
        src_file_path.clone(),
        ptr::null_mut()
    );
    let dest_file = open_file_or_return_on_err!(
        File::options()
            .read(true)
            .write(true)
            .open(dest_file_path.clone()),
        dest_file_path.clone(),
        ptr::null_mut()
    );

    TASK_QUEUE.push(Box::new(EncryptionTask::new(
        task_id,
        src_file,
        dest_file,
        password_string.into_bytes(),
    )));

    Box::into_raw(Box::new(task_id))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use tempfile::tempdir;
    use crate::tasks::TestTaskType;

    use super::*;

    #[test]
    pub fn test_queuing_encryption_task_succeeds() {
        const SRC_FILENAME: &str = "src-file.txt";
        const DEST_FILENAME: &str = "dest-file.txt";
        let dir = tempdir().unwrap();
        let src_file_path = dir.path().join(SRC_FILENAME);
        let dest_file_path = dir.path().join(DEST_FILENAME);

        let src_file_res = File::create(src_file_path.clone());
        let dest_file_res = File::create(dest_file_path.clone());

        assert!(src_file_res.is_ok());
        assert!(dest_file_res.is_ok());

        let src_file_path_c_char = CString::new(src_file_path.to_string_lossy().as_ref())
            .unwrap()
            .into_raw();
        let dest_file_path_c_char = CString::new(dest_file_path.to_string_lossy().as_ref())
            .unwrap()
            .into_raw();
        let password_c_char = CString::new("a-very-long-password").unwrap().into_raw();
        let id =
            unsafe { *queue_encryption_task(src_file_path_c_char, dest_file_path_c_char, password_c_char) };

        assert_eq!(TASK_QUEUE.len(), 1);

        let task = TASK_QUEUE.pop();
        assert_eq!(task.get_id(), id);
        assert_eq!(task.get_task_type_for_test(), TestTaskType::Encryption);
    }
}
