// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
use crate::errors::{Error, Result};
use crate::ffi::errors::update_last_error;
use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

pub static LOGGING_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

pub fn init_logging() {
    let log_dir = match get_logging_directory() {
        Ok(dir) => dir,
        Err(e) => {
            println!(
                "WARNING: Unable to initialize logging. Error: {}",
                e.to_string()
            );
            update_last_error(e);
            return;
        }
    };

    let file_appender_res = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("susi")
        .filename_suffix("log")
        .build(log_dir);
    let file_appender = match file_appender_res {
        Ok(appender) => appender,
        Err(e) => {
            let msg = format!(
                "Unable to initialize log appender. Error: {}",
                e.to_string()
            );
            println!("WARNING! {}", msg);
            update_last_error(Error::Logging(msg));
            return;
        }
    };

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let res = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_writer(non_blocking)
        .with_ansi(false)
        .try_init();
    match res {
        Ok(_) => {
            LOGGING_GUARD.get_or_init(|| guard);
        }
        Err(e) => {
            let msg = format!(
                "Unable to initialize logging. Make sure logging is not being reinitialized. Error: {}",
                e.to_string()
            );
            println!("WARNING! {}", msg);
            update_last_error(Error::Logging(String::from(msg)));
            return;
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
        return Err(Error::InvalidDirectory(String::from(
            "No suitable directory to store logs",
        )));
    }

    const DIRS: [&str; 4] = ["AppData", "Local", "Susi", "logs"];
    for dir in DIRS {
        base_log_dir.push(dir);
    }

    Ok(base_log_dir)
}
