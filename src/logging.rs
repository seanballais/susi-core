use crate::errors::{Error, Result};
use std::cell::RefCell;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use tracing::dispatcher::with_default;
use tracing::{Dispatch, Level};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::FmtSubscriber;

pub struct LoggingGuard {
    guard: WorkerGuard,
}

impl LoggingGuard {
    pub fn new(guard: WorkerGuard) -> Self {
        Self { guard }
    }
}

pub fn init_logging() -> Result<LoggingGuard> {
    let log_dir = match get_logging_directory() {
        Ok(dir) => dir,
        Err(e) => {
            return Err(e);
        }
    };

    let file_appender_res = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("susi")
        .filename_suffix("log")
        .build(log_dir);
    let file_appender = match file_appender_res {
        Ok(appender) => appender,
        Err(_) => {
            return Err(Error::LoggingError(String::from(
                "Unable to initialize logging file appender",
            )));
        }
    };

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let res = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_writer(non_blocking)
        .with_ansi(false)
        .try_init();
    match res {
        Ok(_) => Ok(LoggingGuard::new(guard)),
        Err(e) => {
            Err(Error::LoggingError(String::from(
                "Unable to initialize logging. Make sure logging is not being reinitialized",
            )))
        }
    }
}

fn get_logging_directory() -> Result<PathBuf> {
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
