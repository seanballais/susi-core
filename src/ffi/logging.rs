use crate::logging;
use libc::{c_char, c_int};
use std::ffi::CString;
use std::ptr;
use std::slice::from_raw_parts_mut;
use crate::ffi::errors::update_last_error;
use crate::logging::get_logging_directory;

#[no_mangle]
pub extern "C" fn register_logging_functions(
    info: extern fn(*const c_char),
    warning: extern fn(*const c_char),
    error: extern fn(*const c_char),
) {
    let info_fn_str = translate_func_str_rust_to_c(info);
    let warning_fn_str = translate_func_str_rust_to_c(warning);
    let error_fn_str = translate_func_str_rust_to_c(error);

    logging::register_logging_functions(info_fn_str, warning_fn_str, error_fn_str);
}

#[no_mangle]
pub unsafe extern "C" fn get_log_dir(buffer: *mut c_char, length: c_int) -> c_int {
    if buffer.is_null() {
        logging::warning!("Null pointer passed into get_log_dir() as the buffer");

        return -1;
    }

    let dir = match get_logging_directory() {
        Ok(path) => String::from(path.to_string_lossy()),
        Err(e) => {
            update_last_error(e);
            return -1;
        }
    };

    let buffer = from_raw_parts_mut(buffer as *mut u8, length as usize);

    if dir.len() >= buffer.len() {
        logging::warning!("Buffer provided for writing the log directory is too small");
        logging::warning!(
            "Expected at least {} bytes, but got {}",
            dir.len() + 1,
            buffer.len()
        );

        return -1;
    }

    ptr::copy_nonoverlapping(dir.as_ptr(), buffer.as_mut_ptr(), dir.len());

    // Add a trailing null so that people using the string as a char* don't accidentally read into
    // garbage.
    buffer[dir.len()] = 0;

    dir.len() as c_int
}

#[no_mangle]
pub extern "C" fn get_log_dir_length() -> c_int {
    let res = get_logging_directory();
    match res {
        Ok(p) => {
            p.to_string_lossy().len() as c_int + 1
        },
        Err(e) => {
            update_last_error(e);
            -1
        }
    }
}

#[inline(always)]
fn translate_func_str_rust_to_c(func: extern fn(*const c_char)) -> impl Fn(&str) -> () {
    let f = func.clone();

    move |message: &str| {
        // We need to remove any null characters to prevent errors.
        let sanitized_message: String = message.chars().filter(|&c| c != '\0').collect();
        let c_str = CString::new(sanitized_message).unwrap();
        let c_world_str = c_str.as_ptr() as *const c_char;
        f(c_world_str);
    }
}
