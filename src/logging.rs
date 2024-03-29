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

thread_local! {
    static THREAD_LOGGING_VARS: RefCell<Option<(Dispatch, WorkerGuard)>> = RefCell::new(None);
    static THREAD_LOGGING_INIT_ERROR: RefCell<Option<Error>> = RefCell::new(None);
}

macro_rules! info {
    ($($x: tt)*) => {
        THREAD_LOGGING_VARS.with(|vars| {
            if let Some((dispatch, _guard)) = vars.borrow().as_ref() {
                with_default(&dispatch, || {
                    tracing::info!($($x)*);
                });
            }
        });
    };
}

pub fn init_thread_local_logging() {
    let log_dir = match get_logging_directory() {
        Ok(dir) => dir,
        Err(e) => {
            update_logging_variables(None, Some(e));
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
        Err(_) => {
            let error = Error::LoggingError(String::from("Unable to initialize logging"));
            update_logging_variables(None, Some(error));
            return;
        }
    };

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(non_blocking)
        .with_ansi(false)
        .finish();

    update_logging_variables(Some((Dispatch::new(subscriber), guard)), None);

    info!("Testing if the logging works.");
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

#[inline(always)]
fn update_logging_variables(logging_vars: Option<(Dispatch, WorkerGuard)>, error: Option<Error>) {
    THREAD_LOGGING_VARS.with_borrow_mut(|vars| {
        *vars = logging_vars;
    });
    THREAD_LOGGING_INIT_ERROR.with_borrow_mut(|error_var| {
        *error_var = error;
    });
}
