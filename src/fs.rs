use crate::crypto::IO_BUFFER_LEN;
use crate::errors::{Result};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use crate::errors::Error::IOError;

pub enum FileAccessOptions {
    ReadOnly,
    ReadWrite,
    ReadWriteCreate,
    ReadTruncate,
    ReadTruncateCreate,
    WriteOnly,
    WriteCreate,
    TruncateOnly,
    TruncateCreate,
    CreateOnly // Effectively same as WriteCreate, but the intent will be clearer with this.
}

// NOTE: There were prior attempts to let us use FileObj like a std::fs::File, but there was a snag
//       trying to implement the bytes() function of the Read trait. So, we're implementing this
//       one this way for now.
#[derive(Debug)]
pub struct File {
    file: fs::File,
    path: PathBuf
}

impl File {
    pub fn open<P: AsRef<Path>>(path: P, access_option: FileAccessOptions) -> Result<Self> {
        let mut options = fs::File::options();
        match access_option {
            FileAccessOptions::ReadOnly => { options.read(true); },
            FileAccessOptions::ReadWrite => { options.read(true).write(true); },
            FileAccessOptions::ReadWriteCreate => { options.read(true).write(true).create(true); },
            FileAccessOptions::ReadTruncate => { options.read(true).write(true).truncate(true); },
            FileAccessOptions::ReadTruncateCreate => {
                options.read(true).write(true).truncate(true).create(true);
            },
            FileAccessOptions::WriteOnly => { options.write(true); },
            FileAccessOptions::WriteCreate => { options.write(true).create(true); },
            FileAccessOptions::TruncateOnly => { options.write(true).truncate(true); },
            FileAccessOptions::TruncateCreate => {
                options.write(true).truncate(true).create(true);
            },
            FileAccessOptions::CreateOnly => { options.write(true).create(true); }
        }

        let file_path = PathBuf::from(path.as_ref());
        match options.open(path.as_ref()) {
            Ok(f) => Ok(Self { file: f, path: file_path }),
            Err(e) => Err(IOError(file_path, Arc::new(e)))
        }
    }

    pub fn get_file(&self) -> &fs::File { &self.file }
    pub fn get_file_mut(&mut self) -> &mut fs::File { &mut self.file }
    pub fn get_path(&self) -> &Path { self.path.as_path() }
}

pub fn append_file_extension_to_path<P: AsRef<Path>, S: AsRef<OsStr>>(file_path: P, ext: S) -> PathBuf {
    #[cfg(target_endian = "big")]
    {
        compile_error!("Big-endian systems are not yet supported (due to lack of access of a big-endian machine.");
    }
    if ext.as_ref().is_empty() {
        return PathBuf::from(file_path.as_ref());
    }

    let mut new_file_ext = OsString::from(file_path.as_ref().extension().unwrap_or_else(|| "".as_ref()));
    let mut ext = ext.as_ref();

    #[cfg(target_endian = "little")]
    {
        // `.` in Unicode is `U+002E` or `46` (0x2E) in decimals. The value should be in the
        // first byte, even with UTF-16/UCS-2, in a little-endian system.
        if ext.as_encoded_bytes()[0] != 0x2Eu8 {
            new_file_ext.push(".");
        }
    }

    new_file_ext.push(ext);

    let mut new_file_path = PathBuf::from(file_path.as_ref());
    new_file_path.set_extension(new_file_ext);

    new_file_path
}

pub fn copy_file_contents(
    src_file: &mut File,
    dest_file: &mut File
) -> Result<()> {
    // No progress notification here yet, but this should provide the foundation.
    let mut buffer = [0u8; IO_BUFFER_LEN];
    loop {
        let read_count = src_file
            .get_file_mut()
            .read(&mut buffer)
            .map_err(|e| IOError(src_file.path.clone(), Arc::from(e)))?;
        if read_count == 0 {
            break;
        } else {
            dest_file
                .get_file_mut()
                .write(&buffer[0..read_count])
                .map_err(|e| IOError(dest_file.path.clone(), Arc::from(e)))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, Write};
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use crate::fs::{append_file_extension_to_path, copy_file_contents, FileAccessOptions, File};

    #[test]
    fn test_file_open_read_only_works_successfully() {
        let path = create_test_file_path("test-file-read-only.txt");
        create_test_file(path.clone());

        let mut file = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let res = file.get_file_mut().write_all("test".as_bytes());
        assert!(res.is_err());
    }

    #[test]
    fn test_file_open_read_write_works_successfully() {
        let path = create_test_file_path("test-file-read-write.txt");
        create_test_file(path.clone());

        let content = "bling bang bang, bling bang bang, bling bang bang bom";
        let mut file = File::open(path.clone(), FileAccessOptions::ReadWrite).unwrap();
        let res = file.get_file_mut().write_all(content.as_bytes());
        assert!(res.is_ok());

        let mut read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), content);
    }

    #[test]
    fn test_file_open_read_write_create_works_successfully() {
        let path = create_test_file_path("test-file-read-write-create.txt");
        let content = "bling bang bang, bling bang bang, bling bang bang bom";
        let mut file = File::open(path.clone(), FileAccessOptions::ReadWriteCreate).unwrap();
        let res = file.get_file_mut().write_all(content.as_bytes());
        assert!(res.is_ok());

        let mut read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), content);
    }

    #[test]
    fn test_file_open_read_truncate_works_successfully() {
        let path = create_test_file_path("test-file-read-write-create.txt");
        let old_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), old_content);

        let mut file = File::open(path.clone(), FileAccessOptions::ReadTruncate).unwrap();
        let new_content = "ang sakit sa heart";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        let mut read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), new_content);
    }

    #[test]
    fn test_file_open_read_truncate_create_no_preexisting_file_works_successfully() {
        let path = create_test_file_path("test-file-read-write-create-npf.txt");

        // We should get a new file after this point.
        let mut file = File::open(path.clone(), FileAccessOptions::ReadTruncateCreate).unwrap();
        let content = "chilling vibes with SimCity 3000";
        let res = file.get_file_mut().write_all(content.as_bytes());
        assert!(res.is_ok());

        let mut read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), content);
    }

    #[test]
    fn test_file_open_read_truncate_create_preexisting_file_works_successfully() {
        let path = create_test_file_path("test-file-read-write-create-pf.txt");
        let old_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), old_content);

        let mut file = File::open(path.clone(), FileAccessOptions::ReadTruncateCreate).unwrap();
        let new_content = "i will be okay";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        let mut read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), new_content);
    }

    #[test]
    fn test_append_file_extension_to_path_ext_no_starting_period_works_successfully() {
        let test_path_str = "test/folder/some_file.png";
        let path = PathBuf::from(test_path_str);
        let new_path = append_file_extension_to_path(path, "ssef");
        assert_eq!(new_path, PathBuf::from(format!("{}.ssef", test_path_str)));
    }

    #[test]
    fn test_append_file_extension_to_path_ext_with_starting_period_works_successfully() {
        let test_path_str = "test/folder/some_file.png";
        let path = PathBuf::from(test_path_str);
        let new_path = append_file_extension_to_path(path, ".ssef");
        assert_eq!(new_path, PathBuf::from(format!("{}.ssef", test_path_str)));
    }

    #[test]
    fn test_copying_file_contents() {
        let temp_dir = tempdir().unwrap().into_path();

        let mut src_file_path = temp_dir.clone();
        src_file_path.push("src-a.txt");
        let mut src_file = File::open(src_file_path, FileAccessOptions::ReadTruncateCreate).unwrap();

        // Used to be "kimiwa", but RustRover suggested it to be "kimchi" instead. It's funnier,
        // so we'll be keeping that.
        const TEST_CONTENT: &str = "Kuno mama kimchi";
        src_file.get_file_mut().write(TEST_CONTENT.as_bytes()).unwrap();

        let mut dest_file_path = temp_dir.clone();
        dest_file_path.push("dest-a.txt");
        let mut dest_file = File::open(dest_file_path, FileAccessOptions::ReadTruncateCreate).unwrap();

        let mut contents = String::new();
        dest_file.get_file().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "");

        // We need to rewind the source file since the cursor should be at the end of the file
        // at this point, after writing to it.
        src_file.get_file_mut().rewind().unwrap();

        let res = copy_file_contents(&mut src_file, &mut dest_file);
        assert!(res.is_ok());

        let mut contents = String::new();
        dest_file.get_file_mut().rewind().unwrap();
        dest_file.get_file().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, TEST_CONTENT);
    }

    #[inline]
    fn create_test_file<P: AsRef<Path>>(path: P) {
        // We need to create the file first.
        let res = File::open(path.as_ref(), FileAccessOptions::CreateOnly);
        assert!(res.is_ok());
    }

    #[inline]
    fn create_test_file_with_content<P: AsRef<Path>, S: AsRef<str>>(path: P, content: S) {
        let mut file = File::open(path.as_ref(), FileAccessOptions::WriteCreate).unwrap();
        let res = file.get_file_mut().write(content.as_ref().as_bytes());
        assert!(res.is_ok());
    }

    #[inline]
    fn create_test_file_path<S: AsRef<str>>(file_name: S) -> PathBuf {
        let temp_dir = tempdir().unwrap().into_path();
        let mut file_path = temp_dir.clone();
        file_path.push(file_name.as_ref());

        file_path
    }
}
