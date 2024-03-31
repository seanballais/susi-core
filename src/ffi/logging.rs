use std::ptr;
use crate::ffi::errors::update_last_error;
use crate::logging;
use crate::logging::LoggingGuard;

#[no_mangle]
pub extern "C" fn init_logging() -> *mut LoggingGuard {
    match logging::init_logging() {
        Ok(guard) => Box::into_raw(Box::new(guard)),
        Err(e) => {
            update_last_error(e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
    pub extern "C" fn destroy_logging(ptr: *mut LoggingGuard) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let _ = Box::from_raw(ptr);
    }
}
