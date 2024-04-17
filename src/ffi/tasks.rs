use libc::c_char;
use std::ffi::CStr;
use std::ptr;
use std::sync::atomic::Ordering;

use crate::ffi::errors::update_last_error;
use crate::fs::{File, FileAccessOptions};
use crate::tasks as susi_tasks;
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

#[repr(C)]
pub enum TaskProgress {
    QUEUED,
    RUNNING,
    DONE,
    FAILED
}

pub struct TaskStatus {
    num_read_bytes: usize,
    num_written_bytes: usize,
    should_stop: bool,
    progress: TaskProgress
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
pub extern "C" fn get_task_status(ptr: *mut TaskID) -> *mut TaskStatus {
    let task_id = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };

    let status_option = TASK_MANAGER.get_task_status(task_id);
    if let Some(guard) = status_option {
        let status = guard.lock().unwrap();
        let num_read_bytes = status.get_num_read_bytes_ref().load(Ordering::Relaxed);
        let num_written_bytes = status.get_num_written_bytes_ref().load(Ordering::Relaxed);
        let should_stop = status.get_should_stop_ref().load(Ordering::Relaxed);
        let progress = match status.get_progress() {
            susi_tasks::TaskProgress::QUEUED => { TaskProgress::QUEUED }
            susi_tasks::TaskProgress::RUNNING => { TaskProgress::RUNNING }
            susi_tasks::TaskProgress::DONE => { TaskProgress::DONE }
            susi_tasks::TaskProgress::FAILED => { TaskProgress::FAILED }
        };

        let ffi_status = TaskStatus {
            num_read_bytes,
            num_written_bytes,
            should_stop,
            progress,
        };
        return Box::into_raw(Box::new(ffi_status));
    }

    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn drop_task_id(id: *mut TaskID) {
    if !id.is_null() {
        drop(Box::from_raw(id));
    }
}
