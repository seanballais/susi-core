use libc::c_char;
use std::ffi::CStr;
use std::ptr;

use crate::ffi::errors::update_last_error;
use crate::fs::{File, FileAccessOptions};
use crate::tasks::{TaskID, TASK_MANAGER};

/// Returns the value in a Result, or causes the function to return `ret_val`.
macro_rules! open_file_or_return_on_err {
    ($result: expr, $path: expr, $err_val: expr) => {
        match $result {
            Ok(f) => f,
            Err(e) => {
                update_last_error(e);
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
        File::open(src_file_path.clone(), FileAccessOptions::ReadWrite),
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

#[no_mangle]
pub unsafe extern "C" fn drop_task_id(id: *mut TaskID) {
    if !id.is_null() {
        drop(Box::from_raw(id));
    }
}
