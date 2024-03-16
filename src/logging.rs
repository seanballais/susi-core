use std::path::PathBuf;
use std::{env, fs};
use tracing_appender;
use tracing_subscriber::prelude::*;

use crate::error::{Error, Result};

pub fn setup_logging() -> Result<Vec<tracing_appender::non_blocking::WorkerGuard>> {
    println!("Getting the log directory path... ");
    let log_dir = get_logging_directory()?;
    if !log_dir.exists() {
        print!("Creating log directory since it doesn't exist yet... ");
        fs::create_dir_all(&log_dir)?;
        println!("✅");
    }

    print!("Setting up loggers... ");
    let file_appender = tracing_appender::rolling::never(log_dir, "core.log");
    let (file_logger, file_logger_guard) = tracing_appender::non_blocking(file_appender);
    let file_logger_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_logger)
        .with_ansi(false);

    let (stdout_logger, stdout_logger_guard) = tracing_appender::non_blocking(std::io::stdout());
    let stdout_logger_layer = tracing_subscriber::fmt::layer().with_writer(stdout_logger);

    let subscriber = tracing_subscriber::Registry::default()
        .with(file_logger_layer)
        .with(stdout_logger_layer);
    let res = tracing::subscriber::set_global_default(subscriber);

    match res {
        Ok(()) => println!("✅"),
        Err(e) => {
            println!("❌");
            return Err(Error::LoggingError(e.to_string()));
        }
    }

    Ok(vec![file_logger_guard, stdout_logger_guard])
}

fn get_logging_directory() -> Result<PathBuf> {
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
