use crate::errors::{Error, Result};
use std::collections::HashMap;
use std::env;
use std::fmt::format;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

pub static LOG_FUNCTIONS: OnceLock<HashMap<LogLevel, Mutex<Box<dyn Fn(&str) -> () + Send>>>> =
    OnceLock::new();

#[repr(C)]
#[derive(Eq, PartialEq, Hash)]
pub enum LogLevel {
    INFO,
    WARNING,
    ERROR,
}

macro_rules! info {
    ($($x: tt)*) => {
        crate::logging::log(format!($($x)*), crate::logging::LogLevel::INFO);
    };
}
pub(crate) use info;

macro_rules! warning {
    ($($x: tt)*) => {
        crate::logging::log(format!($($x)*), crate::logging::LogLevel::WARNING);
    };
}
pub(crate) use warning;

macro_rules! error {
    ($($x: tt)*) => {
        crate::logging::log(format!($($x)*), crate::logging::LogLevel::ERROR);
    };
}
pub(crate) use error;

pub fn register_logging_functions(
    info: impl Fn(&str) -> () + Send + 'static,
    warning: impl Fn(&str) -> () + Send + 'static,
    error: impl Fn(&str) -> () + Send + 'static,
) {
    LOG_FUNCTIONS.get_or_init(|| {
        let mut log_functions: HashMap<LogLevel, Mutex<Box<dyn Fn(&str) -> () + Send>>> =
            HashMap::new();

        log_functions.insert(LogLevel::INFO, Mutex::new(Box::new(info)));
        log_functions.insert(LogLevel::WARNING, Mutex::new(Box::new(warning)));
        log_functions.insert(LogLevel::ERROR, Mutex::new(Box::new(error)));

        log_functions
    });
}

pub fn get_logging_directory() -> Result<PathBuf> {
    #[cfg(target_family = "unix")]
    {
        compile_error!("UNIX-like operating systems (e.g. Linux and macOS) are not yet supported!");
    }

    let mut base_log_dir = PathBuf::new();
    let home_dir = env::var_os("USERPROFILE");
    if let Some(dir) = home_dir {
        base_log_dir.push(dir);
    } else {
        return Err(Error::InvalidDirectoryError(String::from(
            "No suitable directory to store logs",
        )));
    }

    const DIRS: [&str; 4] = ["AppData", "Local", "Susi", "logs"];
    for dir in DIRS {
        base_log_dir.push(dir);
    }

    Ok(base_log_dir)
}

#[inline(always)]
pub fn log<S: AsRef<str>>(message: S, level: LogLevel) {
    if let Some(functions) = LOG_FUNCTIONS.get() {
        if let Some(function) = functions.get(&level) {
            let f = function.lock().unwrap();
            f(message.as_ref());
        }
    }
}
