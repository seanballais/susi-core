// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
use std::path::{Path, PathBuf};

pub trait PathExt {
    fn to_pathbuf_option(&self) -> Option<PathBuf>;
}

impl PathExt for Path {
    fn to_pathbuf_option(&self) -> Option<PathBuf> {
        if self.as_os_str().is_empty() {
            None
        } else {
            Some(self.to_path_buf())
        }
    }
}

pub trait OptionPathBufExt {
    fn to_string_lossy(&self) -> String;
}

impl OptionPathBufExt for Option<PathBuf> {
    fn to_string_lossy(&self) -> String {
        match self {
            Some(path) => path.to_string_lossy().to_string(),
            _ => "".to_string(),
        }
    }
}
