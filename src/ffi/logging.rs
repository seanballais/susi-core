use libc::c_char;
use std::ffi::CStr;

use crate::logging;

#[no_mangle]
pub extern "C" fn init_logging() {
    logging::init_logging();
}

#[no_mangle]
pub extern "C" fn log_info(message: *const c_char) {
    assert!(!message.is_null());

    let message_c_str = unsafe { CStr::from_ptr(message) };
    let message_str = message_c_str.to_string_lossy().into_owned();

    tracing::info!("{}", message_str);
}
