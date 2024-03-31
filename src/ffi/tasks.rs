use libc::c_char;
use std::ffi::CStr;
use std::fs::File;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use crate::errors::Error;
use crate::ffi::errors::update_last_error;
use crate::logging;
use crate::tasks::{TaskID, TASK_MANAGER};

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
pub extern "C" fn queue_encryption_task(
    src_file: *const c_char,
    password: *const c_char,
) -> *mut TaskID {
    let src_file_c_str = unsafe {
        assert!(!src_file.is_null());

        CStr::from_ptr(src_file)
    };
    let src_file_path = src_file_c_str.to_string_lossy().into_owned();
    let password_c_str = unsafe {
        assert!(!password.is_null());

        CStr::from_ptr(password)
    };
    let password_string = password_c_str.to_string_lossy().into_owned();

    let src_file = open_file_or_return_on_err!(
        File::options()
            .read(true)
            .write(true)
            .open(src_file_path.clone()),
        src_file_path.clone(),
        ptr::null_mut()
    );

    match TASK_MANAGER.queue_encryption_task(src_file, password_string.into_bytes()) {
        Ok(task_id) => {
            tracing::info!("Task (ID: {}) queued", task_id.clone());
            Box::into_raw(Box::new(task_id))
        }
        Err(e) => {
            update_last_error(e);

            ptr::null_mut()
        }
    }
}
