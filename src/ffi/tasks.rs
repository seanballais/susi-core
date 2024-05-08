use libc::c_char;
use std::ffi::{CStr, CString};
use std::sync::atomic::Ordering;
use std::{mem, ptr};

use crate::ffi::errors::update_last_error;
use crate::fs::{File, FileAccessOptions};
use crate::tasks as susi_tasks;
use crate::tasks::TASK_MANAGER;

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
    Queued,
    Processing,
    Finalizing,
    Done,
    Failed,
    Interrupted,
}

#[repr(C)]
pub struct TaskStatus {
    pub num_read_bytes: usize,
    pub num_written_bytes: usize,
    pub num_processed_bytes: usize,
    pub should_stop: bool,
    pub last_error: *const c_char,
    pub progress: TaskProgress,
}

#[no_mangle]
pub unsafe extern "C" fn drop_task_status(status: *mut TaskStatus) {
    if !status.is_null() {
        drop(Box::from_raw(status));
    }
}

#[repr(C)]
pub struct TaskID {
    upper_id: u64,
    lower_id: u64,
}

impl From<susi_tasks::TaskID> for TaskID {
    fn from(id: susi_tasks::TaskID) -> Self {
        let upper_id = id.upper_id;
        let lower_id = id.lower_id;
        Self { upper_id, lower_id }
    }
}

fn clone_task_id_into_susi_task_id(id: &TaskID) -> susi_tasks::TaskID {
    susi_tasks::TaskID {
        upper_id: id.upper_id,
        lower_id: id.lower_id,
    }
}

#[no_mangle]
pub extern "C" fn queue_encryption_task(
    target_file: *const c_char,
    password: *const c_char,
) -> *mut TaskID {
    let src_file_c_str = unsafe {
        assert!(!target_file.is_null());

        CStr::from_ptr(target_file)
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
            Box::into_raw(Box::new(TaskID::from(task_id)))
        }
        Err(e) => {
            update_last_error(e);

            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn get_task_status(ptr: *const TaskID) -> *mut TaskStatus {
    let ffi_task_id = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };
    let task_id = clone_task_id_into_susi_task_id(ffi_task_id);

    let status_option = TASK_MANAGER.get_task_status(&task_id);
    if let Some(guard) = status_option {
        let status = guard.lock().unwrap();
        let num_read_bytes = status.get_num_read_bytes_ref().load(Ordering::Relaxed);
        let num_written_bytes = status.get_num_written_bytes_ref().load(Ordering::Relaxed);
        let num_processed_bytes = status.get_num_processed_bytes_ref().load(Ordering::Relaxed);
        let should_stop = status.get_should_stop_ref().load(Ordering::Relaxed);

        let last_error_message = status.get_last_error().to_string();
        let last_error_c_string = CString::new(last_error_message).unwrap();
        let last_error = last_error_c_string.as_ptr();

        mem::forget(last_error_c_string);

        let progress = match status.get_progress() {
            susi_tasks::TaskProgress::Queued => TaskProgress::Queued,
            susi_tasks::TaskProgress::Processing => TaskProgress::Processing,
            susi_tasks::TaskProgress::Finalizing => TaskProgress::Finalizing,
            susi_tasks::TaskProgress::Done => TaskProgress::Done,
            susi_tasks::TaskProgress::Failed => TaskProgress::Failed,
            susi_tasks::TaskProgress::Interrupted => TaskProgress::Interrupted,
        };

        let ffi_status = TaskStatus {
            num_read_bytes,
            num_written_bytes,
            num_processed_bytes,
            should_stop,
            last_error,
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
