// Based on: https://www.michaelfbryan.com/rust-ffi-guide/errors/return_types.html
use std::cell::RefCell;
use std::error::Error;
use std::ptr;
use std::slice::from_raw_parts_mut;

use libc::{c_char, c_int};

use crate::errors;

thread_local! {
    static LAST_FFI_ERROR: RefCell<Option<errors::Error>> = RefCell::new(None);
}

/// Writes the most recent error message into a caller-provided buffer as a UTF-8 string, returning
/// the number of bytes written.
///
/// If there are no recent errors then this returns `0` (because we wrote 0 bytes). `-1` is returned
/// if there are any errors, for example, when passed a null pointer or a buffer of insufficient
/// size.
#[no_mangle]
pub unsafe extern "C" fn get_last_error_message(buffer: *mut c_char, length: c_int) -> c_int {
    if buffer.is_null() {
        tracing::warn!("Null pointer passed into get_last_error_message() as the buffer");

        return -1;
    }

    let last_error = match take_last_error() {
        Some(err) => err,
        None => return 0,
    };

    let error_message = last_error.to_string();
    let buffer = from_raw_parts_mut(buffer as *mut u8, length as usize);

    if error_message.len() >= buffer.len() {
        tracing::warn!("Buffer provided for writing the last error message is too small");
        tracing::warn!(
            "Expected at least {} bytes, but got {}",
            error_message.len() + 1,
            buffer.len()
        );

        return -1;
    }

    ptr::copy_nonoverlapping(
        error_message.as_ptr(),
        buffer.as_mut_ptr(),
        error_message.len(),
    );

    // Add a trailing null so that people using the string as a char* don't accidentally read into
    // garbage.
    buffer[error_message.len()] = 0;

    error_message.len() as c_int
}

#[no_mangle]
pub extern "C" fn get_last_error_message_length() -> c_int {
    LAST_FFI_ERROR.with(|curr| match *curr.borrow() {
        Some(ref err) => err.to_string().len() as c_int + 1,
        None => 0,
    })
}

#[no_mangle]
pub extern "C" fn has_error() -> bool {
    LAST_FFI_ERROR.with(|curr| curr.borrow().is_some())
}

pub fn update_last_error(err: errors::Error) {
    tracing::error!("Setting the last error: {}", err);

    // Log the causes of the error.
    let mut cause = err.source();
    while let Some(parent_err) = cause {
        tracing::warn!("Caused by: {}", parent_err);
        cause = parent_err.source();
    }

    LAST_FFI_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(err);
    });
}

fn take_last_error() -> Option<errors::Error> {
    LAST_FFI_ERROR.with(|prev| prev.borrow_mut().take())
}
