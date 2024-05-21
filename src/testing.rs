// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use crate::fs::{File, FileAccessOptions};

#[inline]
pub(crate) fn create_test_file<P: AsRef<Path>>(path: P) {
    // We need to create the file first.
    let res = File::touch(path.as_ref());
    assert!(res.is_ok());
}

#[inline]
pub(crate) fn create_test_file_with_content<P: AsRef<Path>, S: AsRef<str>>(path: P, content: S) {
    let mut file = File::open(path.as_ref(), FileAccessOptions::WriteCreate).unwrap();
    let res = file.get_file_mut().write(content.as_ref().as_bytes());
    assert!(res.is_ok());
}

#[inline]
pub(crate) fn create_test_file_path<S: AsRef<str>>(file_name: S) -> PathBuf {
    let temp_dir = tempdir().unwrap().into_path();
    let mut file_path = temp_dir.clone();
    file_path.push(file_name.as_ref());

    file_path
}