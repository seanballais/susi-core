use std::io;

use interprocess::local_socket::{LocalSocketListener, LocalSocketStream, NameTypeSupport};
use tracing;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_panic;

use susi_core::logging;

fn main() {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        tracing_panic::panic_hook(panic_info);
        prev_hook(panic_info);
    }));

    let log_setup_res = logging::setup_logging();
    let mut log_guards = Vec::new();
    match log_setup_res {
        Ok(guards) => {
            log_guards = guards;
        }
        Err(e) => {
            eprintln!(
                "Error occurred, but we'll still continue, but with no logging. Error: {}",
                e
            );
        }
    };

    tracing::info!("Logging is ready");
    tracing::info!("Setting up IPC server");

    let socket_name = {
        use NameTypeSupport::{Both, OnlyNamespaced, OnlyPaths};

        const NAME: &str = "sfb-susi.sock";
        match NameTypeSupport::query() {
            OnlyPaths => format!("/tmp/{}", NAME), // For macOS support
            OnlyNamespaced | Both => format!("@{}", NAME),
        }
    };

    let binding_result = LocalSocketListener::bind(socket_name);
    if binding_result.is_err() {
        panic!("Unable to connect to socket file. Please check if the socket file is being used");
    }

    let listener = binding_result.unwrap();

    tracing::info!("Starting IPC server");
}
