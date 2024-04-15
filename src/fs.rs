use crate::crypto::IO_BUFFER_LEN;
use crate::errors::{Copy, Error, IO, Result};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Create and truncate access options only make sense when we're writing to them. So, we won't
// combine any of them with read access. Creating and truncating files should be done via
// appropriate methods.
pub enum FileAccessOptions {
    ReadOnly,
    ReadWrite,
    ReadWriteCreate,
    ReadWriteCreateOrTruncate,
    WriteOnly,
    WriteCreate,
    WriteTruncate,
    WriteCreateOrTruncate
}

// NOTE: There were prior attempts to let us use FileObj like a std::fs::File, but there was a snag
//       trying to implement the bytes() function of the Read trait. So, we're implementing this
//       one this way for now.
#[derive(Debug)]
pub struct File {
    file: fs::File,
    path: PathBuf,
    is_readable: bool,
    is_writable: bool
}

impl File {
    pub fn open<P: AsRef<Path>>(path: P, access_option: FileAccessOptions) -> Result<Self> {
        let mut readable = false;
        let mut writable = false;
        let mut options = fs::File::options();
        match access_option {
            FileAccessOptions::ReadOnly => {
                readable = true;
                options.read(true);
            },
            FileAccessOptions::ReadWrite => {
                readable = true;
                writable = true;
                options.read(true).write(true);
            },
            FileAccessOptions::ReadWriteCreate => {
                readable = true;
                writable = true;
                options.read(true).write(true).create(true);
            },
            FileAccessOptions::ReadWriteCreateOrTruncate => {
                readable = true;
                writable = true;
                options.read(true).write(true).create(true).truncate(true);
            }
            FileAccessOptions::WriteOnly => {
                writable = true;
                options.write(true);
            },
            FileAccessOptions::WriteCreate => {
                writable = true;
                options.write(true).create(true);
            },
            FileAccessOptions::WriteTruncate => {
                writable = true;
                options.write(true).truncate(true);
            },
            FileAccessOptions::WriteCreateOrTruncate => {
                writable = true;
                options.write(true).create(true).truncate(true);
            }
        }

        let file_path = PathBuf::from(path.as_ref());
        match options.open(path.as_ref()) {
            Ok(f) => Ok(Self { file: f, path: file_path, is_readable: readable, is_writable: writable }),
            Err(e) => Err(Error::from(IO::new(file_path, Arc::new(e))))
        }
    }

    pub fn touch<P: AsRef<Path>>(path: P) -> Result<()> {
        match fs::File::create(path.as_ref().clone()) {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::from(IO::new(path.as_ref(), Arc::new(e))))
        }
    }

    pub fn get_file(&self) -> &fs::File { &self.file }
    pub fn get_file_mut(&mut self) -> &mut fs::File { &mut self.file }
    pub fn get_path(&self) -> &Path { self.path.as_path() }
    pub fn is_readable(&self) -> bool { self.is_readable }
    pub fn is_writable(&self) -> bool { self.is_writable }
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
    if !src_file.is_readable() {
        return Err(
            Error::from(Copy::new(
                src_file.get_path(),
                dest_file.get_path(),
                "No read access to the source file"
            ))
        );
    } else if !dest_file.is_writable() {
        return Err(
            Error::from(Copy::new(
                src_file.get_path(),
                dest_file.get_path(),
                "No write access to the destination file"
            ))
        );
    }

    // No progress notification here yet, but this should provide the foundation.
    let mut buffer = [0u8; IO_BUFFER_LEN];
    loop {
        let read_count = src_file
            .get_file_mut()
            .read(&mut buffer)
            .map_err(|e| IO::new(src_file.path.clone(), Arc::from(e)))?;
        if read_count == 0 {
            break;
        } else {
            dest_file
                .get_file_mut()
                .write(&buffer[0..read_count])
                .map_err(|e| IO::new(dest_file.path.clone(), Arc::from(e)))?;
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
    fn test_file_open_read_only_preexisting_file_works_successfully() {
        // Create the pre-existing file.
        let path = create_test_file_path("test-file-read-only-pf.txt");
        let content = "Kay Leni tayooo 🎵 Kaya tayong ipaglaban";
        create_test_file_with_content(path.clone(), content);

        // And read from it. It should succeed.
        let mut file = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        assert!(file.is_readable());
        assert!(!file.is_writable());

        let mut read_content = String::new();
        let res = file.get_file().read_to_string(&mut read_content);
        assert!(res.is_ok());
        assert_eq!(read_content.as_str(), content);

        // Attempt to write, but we're expecting it to fail.
        let res = file.get_file_mut().write_all("Ang Pilipinas ay matatag".as_bytes());
        assert!(res.is_err());
    }

    #[test]
    fn test_file_open_read_only_no_preexisting_file_fails() {
        // Try opening a non-existent file, which should fail.
        let path = create_test_file_path("test-file-read-only-npf.txt");
        let res = File::open(path.clone(), FileAccessOptions::ReadOnly);
        assert!(res.is_err());
    }

    #[test]
    fn test_file_open_read_write_preexisting_file_works_successfully() {
        // Create the "pre-existing" file.
        let path = create_test_file_path("test-file-read-write-pf.txt");
        create_test_file(path.clone());

        // Make sure we can write to it.
        let content = "bling bang bang, bling bang bang, bling bang bang bom";
        let mut file = File::open(path.clone(), FileAccessOptions::ReadWrite).unwrap();
        assert!(file.is_readable());
        assert!(file.is_writable());
        let res = file.get_file_mut().write_all(content.as_bytes());
        assert!(res.is_ok());

        // And finally making sure we can read to it and ensuring we wrote the correct data.
        let mut read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), content);
    }

    #[test]
    fn test_file_open_read_write_no_preexisting_file_fails() {
        // Let's npt create a file, but create a path.
        let path = create_test_file_path("test-file-read-write-npf.txt");

        // And it should fail.
        let res = File::open(path.clone(), FileAccessOptions::ReadWrite);
        assert!(res.is_err());
    }

    #[test]
    fn test_file_open_read_write_create_preexisting_file_works_successfully() {
        // Create the file with some content.
        let path = create_test_file_path("test-file-read-write-create-pf.txt");
        let orig_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), orig_content.clone());

        // We should be able to open the file since it exists.
        let mut file = File::open(path.clone(), FileAccessOptions::ReadWriteCreate).unwrap();
        assert!(file.is_readable());
        assert!(file.is_writable());

        // And make sure that the original content stays the same, since we didn't truncate it.
        let mut read_content = String::new();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), orig_content);

        // And we need to make sure we can write. Note that the file cursor is at the end of the
        // file right now.
        let res = file.get_file_mut().write_all("baang".as_bytes());
        assert!(res.is_ok());

        // And we need to read it again to make sure the content is correctly written.
        read_content.clear();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();

        let expected_content = "bling bang bang, bling bang bang, bling bang bang bombaang";
        assert_eq!(read_content.as_str(), expected_content);
    }

    #[test]
    fn test_file_open_read_write_create_no_preexisting_file_works_successfully() {
        // Let's just create a path but not a file.
        let path = create_test_file_path("test-file-read-write-create-npf.txt");

        // We should be able to open the file since it gets created.
        let mut file = File::open(path.clone(), FileAccessOptions::ReadWriteCreate).unwrap();
        assert!(file.is_readable());
        assert!(file.is_writable());

        // And make sure that the content is empty, since it's new.
        let mut read_content = String::new();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), "");

        // And we need to make sure we can write to it. Note that the file cursor is at the end of
        // the file right now. Though, it wouldn't really matter since there was no data read.
        let res = file.get_file_mut().write_all("baang".as_bytes());
        assert!(res.is_ok());

        // And we need to read it again to make sure the content is correctly written.
        read_content.clear();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();

        let expected_content = "baang";
        assert_eq!(read_content.as_str(), expected_content);
    }

    #[test]
    fn test_file_open_read_write_create_or_truncate_preexisting_file_works_successfully() {
        // Create a file with some content.
        let path = create_test_file_path("test-file-read-write-create-or-truncate-pf.txt");
        let orig_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), orig_content.clone());

        // We should be able to open the file since it exists.
        let mut file = File::open(path.clone(), FileAccessOptions::ReadWriteCreateOrTruncate).unwrap();
        assert!(file.is_readable());
        assert!(file.is_writable());

        // And make sure that the content is empty, since we truncated it.
        let mut read_content = String::new();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), "");

        // And we need to make sure we can write.
        let new_content = "hey boogie woogie bang bang";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        // And we need to read it again to make sure the content is correctly written. Of course,
        // we are rewinding the file cursor.
        read_content.clear();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), new_content);
    }

    #[test]
    fn test_file_open_read_write_create_or_truncate_no_preexisting_file_works_successfully() {
        // Let's just create a path.
        let path = create_test_file_path("test-file-read-write-create-or-truncate-npf.txt");

        // We should be able to open the file, even if it didn't exist, since it gets created.
        let mut file = File::open(path.clone(), FileAccessOptions::ReadWriteCreateOrTruncate).unwrap();
        assert!(file.is_readable());
        assert!(file.is_writable());

        // And make sure that the content is empty, since it should be a new file.
        let mut read_content = String::new();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), "");

        // And we need to make sure we can write.
        let new_content = "hey boogie woogie bang bang";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        // And we need to read it again to make sure the content is correctly written. Of course,
        // we are rewinding the file cursor.
        read_content.clear();
        file.get_file_mut().rewind().unwrap();
        file.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), new_content);
    }

    #[test]
    fn test_file_open_write_only_preexisting_file_works_successfully() {
        // Create the pre-existing file.
        let path = create_test_file_path("test-file-write-only-pf.txt");
        let old_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), old_content);

        // And let's open it up again with write-only access, which should allow writing. The cursor
        // should be at the start at this point.
        let mut file = File::open(path.clone(), FileAccessOptions::WriteOnly).unwrap();
        assert!(!file.is_readable());
        assert!(file.is_writable());
        let new_content = "baang";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        // But should fail when reading is attempted.
        let mut _read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        let res = file.get_file().read_to_string(&mut _read_content);
        assert!(res.is_err());

        // We then open the file again with read access to see if we wrote the data correctly.
        let mut file_with_read = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut read_content = String::new();
        let expected_content = "baang bang bang, bling bang bang, bling bang bang bom";
        file_with_read.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), expected_content);
    }

    #[test]
    fn test_file_open_write_only_no_preexisting_file_fails() {
        // Let's just create the path, but won't create it.
        let path = create_test_file_path("test-file-write-only-npf.txt");

        // And let's open it up again with write-only access, but should fail, since it doesn't
        // exist.
        let res = File::open(path.clone(), FileAccessOptions::WriteOnly);
        assert!(res.is_err());
    }

    #[test]
    fn test_file_open_write_create_preexisting_file_works_successfully() {
        // Create the pre-existing file.
        let path = create_test_file_path("test-file-write-only-pf.txt");
        let old_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), old_content);

        // And let's open it up again with write-only access, since it exists. File cursor should
        // be at the front right now.
        let mut file = File::open(path.clone(), FileAccessOptions::WriteCreate).unwrap();
        assert!(!file.is_readable());
        assert!(file.is_writable());

        let new_content = "baang";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        // But should fail when reading is attempted.
        let mut _read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        let res = file.get_file().read_to_string(&mut _read_content);
        assert!(res.is_err());

        // We then open the file again with read access to see if we wrote the data correctly.
        let mut file_with_read = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut read_content = String::new();
        let expected_content = "baang bang bang, bling bang bang, bling bang bang bom";
        file_with_read.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), expected_content);
    }

    #[test]
    fn test_file_open_write_create_no_preexisting_file_works_successfully() {
        // Let's create the path, but without creating a file.
        let path = create_test_file_path("test-file-write-create-npf.txt");

        // And let's open it up with write-only access, which works since it gets created.
        let mut file = File::open(path.clone(), FileAccessOptions::WriteCreate).unwrap();
        assert!(!file.is_readable());
        assert!(file.is_writable());

        let content = "baang";
        let res = file.get_file_mut().write_all(content.as_bytes());
        assert!(res.is_ok());

        // But should fail when reading is attempted.
        let mut _read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        let res = file.get_file().read_to_string(&mut _read_content);
        assert!(res.is_err());

        // We then open the file again with read access to see if we wrote the data correctly.
        let mut file_with_read = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut read_content = String::new();
        file_with_read.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), content);
    }

    #[test]
    fn test_file_open_write_truncate_preexisting_file_works_successfully() {
        // Create the pre-existing file.
        let path = create_test_file_path("test-file-write-truncate-pf.txt");
        let old_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), old_content);

        // And let's open it up again with write-only access, which works since it exists. However,
        // it will be empty cause we truncated it. So, we're writing to an empty file.
        let mut file = File::open(path.clone(), FileAccessOptions::WriteTruncate).unwrap();
        assert!(!file.is_readable());
        assert!(file.is_writable());

        let new_content = "baang";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        // We should fail trying to read the contents though..
        let mut _read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        let res = file.get_file().read_to_string(&mut _read_content);
        assert!(res.is_err());

        // We then open the file again with read access to see if we wrote the data correctly.
        let mut file_with_read = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut read_content = String::new();
        file_with_read.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), new_content);
    }

    #[test]
    fn test_file_open_write_truncate_no_preexisting_file_fails() {
        // Let's create the path, but not the file.
        let path = create_test_file_path("test-file-write-truncate-npf.txt");

        // And we will fail when we try to open the file since it does not exist.
        let res = File::open(path.clone(), FileAccessOptions::WriteTruncate);
        assert!(res.is_err());
    }

    #[test]
    fn test_file_open_write_create_or_truncate_preexisting_file_works_successfully() {
        // Create the pre-existing file.
        let path = create_test_file_path("test-file-write-create-or-truncate-pf.txt");
        let old_content = "bling bang bang, bling bang bang, bling bang bang bom";
        create_test_file_with_content(path.clone(), old_content);

        // And let's open it up again with write-only access, which works since it exists. However,
        // it will be empty cause we truncated it. So, we're writing to an empty file.
        let mut file = File::open(path.clone(), FileAccessOptions::WriteCreateOrTruncate).unwrap();
        assert!(!file.is_readable());
        assert!(file.is_writable());

        let new_content = "baang";
        let res = file.get_file_mut().write_all(new_content.as_bytes());
        assert!(res.is_ok());

        // And it should fail when we try to read the file.
        let mut _read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        let res = file.get_file().read_to_string(&mut _read_content);
        assert!(res.is_err());

        // We then open the file again with read access to see if we wrote the data correctly.
        let mut file_with_read = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut read_content = String::new();
        file_with_read.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), new_content);
    }

    #[test]
    fn test_file_open_write_create_or_truncate_no_preexisting_file_works_successfully() {
        // Let's create a path, but no file.
        let path = create_test_file_path("test-file-write-create-or-truncate-npf.txt");

        // And let's open it up again with write-only access, which works since it gets created.
        // However, it will be empty cause we truncated it. So, we're writing to an empty file.
        let mut file = File::open(path.clone(), FileAccessOptions::WriteCreateOrTruncate).unwrap();
        assert!(!file.is_readable());
        assert!(file.is_writable());
        let content = "baang";
        let res = file.get_file_mut().write_all(content.as_bytes());
        assert!(res.is_ok());

        // And it should fail when we try to read the file.
        let mut _read_content = String::new();
        file.get_file_mut().rewind().unwrap();
        let res = file.get_file().read_to_string(&mut _read_content);
        assert!(res.is_err());

        // We then open the file again with read access to see if we wrote the data correctly.
        let mut file_with_read = File::open(path.clone(), FileAccessOptions::ReadOnly).unwrap();
        let mut read_content = String::new();
        file_with_read.get_file().read_to_string(&mut read_content).unwrap();
        assert_eq!(read_content.as_str(), content);
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

        // Let's create the test source file.
        let mut src_file_path = temp_dir.clone();
        src_file_path.push("src-a.txt");
        let mut src_file = File::open(src_file_path, FileAccessOptions::ReadWriteCreateOrTruncate).unwrap();

        // Used to be "kimiwa", but RustRover suggested it to be "kimchi" instead. It's funnier,
        // so we'll be keeping that.
        const TEST_CONTENT: &str = "Kuno mama kimchi";
        src_file.get_file_mut().write(TEST_CONTENT.as_bytes()).unwrap();

        // And then let's create the test destination file.
        let mut dest_file_path = temp_dir.clone();
        dest_file_path.push("dest-a.txt");
        let mut dest_file = File::open(dest_file_path, FileAccessOptions::ReadWriteCreateOrTruncate).unwrap();

        // And now we try to copy.
        //
        // We need to rewind the source file since the cursor will be at the end of the file
        // at this point, after writing to it.
        src_file.get_file_mut().rewind().unwrap();

        let res = copy_file_contents(&mut src_file, &mut dest_file);
        assert!(res.is_ok());

        // And we should get the same string held by TEST_CONTENT in the destination file.
        let mut contents = String::new();
        dest_file.get_file_mut().rewind().unwrap();
        dest_file.get_file().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, TEST_CONTENT);
    }

    #[inline]
    fn create_test_file<P: AsRef<Path>>(path: P) {
        // We need to create the file first.
        let res = File::touch(path.as_ref());
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
