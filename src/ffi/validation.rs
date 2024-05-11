use std::ffi::CStr;
use libc::c_char;

use crate::crypto::keys::is_password_correct;
use crate::crypto::ssef::get_metadata_section_from_ssef_file;
use crate::ffi::errors::update_last_error;
use crate::ffi::files::open_file_or_return_on_err;
use crate::fs::{File, FileAccessOptions};

#[no_mangle]
pub extern "C" fn is_password_correct_for_file(
    target_file: *const c_char,
    password: *const c_char
) -> bool {
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

    let mut src_file = open_file_or_return_on_err!(
        File::open(src_file_path.clone(), FileAccessOptions::ReadWrite),
        src_file_path.clone(),
        false
    );

    let res = get_metadata_section_from_ssef_file(&mut src_file);
    if res.is_err() {
        let error = res.unwrap_err();
        update_last_error(error);

        return false;
    }

    let metadata = res.unwrap();
    let res = is_password_correct(password_string.as_bytes(), metadata.salt.as_slice(), &metadata.mac);
    if res.is_err() {
        let error = res.unwrap_err();
        update_last_error(error);

        return false;
    }

    res.unwrap()
}