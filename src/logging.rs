use crate::errors::{Error, Result};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;

pub static LOG_FUNCTIONS: OnceLock<HashMap<LogLevel, fn(String)>> = OnceLock::new();

macro_rules! log_function {
    ($message: expr, $log_level: path) => {
        if let Some(functions) = LOG_FUNCTIONS.get() {
            if let Some(function) = functions.get(&$log_level) {
                function($message);
            }
        }
    };
}

#[repr(C)]
#[derive(Eq, Hash)]
pub enum LogLevel {
    INFO,
    WARNING,
    ERROR,
}

pub fn info(message: String) {
    log_function!(message, LogLevel::INFO);
}

pub fn warning(message: String) {
    log_function!(message, LogLevel::WARNING);
}

pub fn error(message: String) {
    log_function!(message, LogLevel::ERROR);
}

pub fn register_logging_functions(info: fn(String), warning: fn(String), error: fn(String)) {
    LOG_FUNCTIONS.get_or_init(|| {
        let mut log_functions: HashMap<LogLevel, fn(String)> = HashMap::new();

        log_functions.insert(LogLevel::INFO, info);
        log_functions.insert(LogLevel::WARNING, warning);
        log_functions.insert(LogLevel::ERROR, error);

        log_functions
    });
}

pub fn get_logging_directory() -> Result<PathBuf> {
    #[cfg(target_family = "unix")]
    {
        panic!("UNIX-like operating systems (e.g. Linux and macOS) are not yet supported!");
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
