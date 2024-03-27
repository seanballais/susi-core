use std::ffi::CString;
use libc::c_char;
use crate::logging;

macro_rules! translate_func_str_rust_to_c {
    ($func: expr) => {
        |message: String| {
            // We need to remove any null characters to prevent errors.
            let sanitized_message = message.chars().filter(|&c| c != '\0').collect();
            let c_str = CString::new(sanitized_message).unwrap();
            let c_world_str = c_str.as_ptr() as *const c_char;
            $func(c_world_str);
        }
    };
}

#[no_mangle]
pub extern fn register_logging_functions(
    info: fn(*const c_char),
    warning: fn(*const c_char),
    error: fn(*const c_char),
) {
    let info_fn_str = translate_func_str_rust_to_c!(info);
    let warning_fn_str = translate_func_str_rust_to_c!(warning);
    let error_fn_str = translate_func_str_rust_to_c!(error);

    logging::register_logging_functions(info_fn_str, warning_fn_str, error_fn_str);
}
