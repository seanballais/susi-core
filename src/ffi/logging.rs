use crate::logging;

#[no_mangle]
pub extern fn destroy_thread_logging_vars() {
    drop(logging::THREAD_LOGGING_VARS);
    drop(logging::THREAD_LOGGING_INIT_ERROR);
}
