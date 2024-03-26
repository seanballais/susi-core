use std::path::PathBuf;
use std::sync::OnceLock;
use std::{env, fs};
use tracing_appender;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;

use crate::errors::{Error, Result};

// We need these alive throughout the lifetime of the client program so that we can keep on logging.
// We don't need to access this more than once, other than when deallocating this one.
static LOGGING_GUARDS: OnceLock<Vec<WorkerGuard>> = OnceLock::new();

pub fn setup_logging() -> Result<Vec<WorkerGuard>> {
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

pub fn init_logging() {
    if LOGGING_GUARDS.get().is_none() {
        tracing::warn!("There was an attempt to reinitialize to logging");
        return;
    }

    let log_setup_res = setup_logging();
    match log_setup_res {
        Ok(guards) => {
            // No need to worry if it fails to set the guards. It's all good.
            LOGGING_GUARDS.set(guards).ok();
        }
        Err(e) => {
            eprintln!(
                "Error occurred, but we'll still continue, but with no logging. Error: {}",
                e
            );
        }
    };

    tracing::info!("Logging initialized");
}

pub fn init_panic_hooks() {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        tracing_panic::panic_hook(panic_info);
        prev_hook(panic_info);
    }));
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
