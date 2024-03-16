use tracing_appender::non_blocking::WorkerGuard;
use susi_core::logging;

fn main() {
    let log_setup_res = logging::setup_logging();
    let mut log_guards = Vec::new();
    match log_setup_res {
        Ok(guards) => {
            log_guards = guards;
        },
        Err(e) => {
            eprintln!(
                "Error occurred, but we'll still continue, but with no logging. Error: {}",
                e
            );
        }
    };

    tracing::info!("Testing logging mechanism.");
}
