use std::io;
use std::io::{BufRead, Read};

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

    const BUFFER_SIZE: usize = 1024;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut read_bytes: Vec<u8> = Vec::with_capacity(BUFFER_SIZE); // Size seems okay for now.

    for connection in listener.incoming().filter_map(handle_listener_error) {
        let mut conn = io::BufReader::new(connection);
        tracing::info!("New connection received");

        read_bytes.clear(); // Ready this one for buffering.

        loop {
            let mut read_count = 0usize;
            let read_result = conn.read(&mut buffer);
            match read_result {
                Ok(c) => { read_count = c; },
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        tracing::warn!("Reading from connection got interrupted. Retrying");
                        continue;
                    } else {
                        tracing::error!("Error occurred while reading from connection. Aborting");
                        break;
                    }
                }
            }

            read_bytes.extend_from_slice(&buffer[0..read_count]);

            // Nothing more to read.
            if read_count == 0 {
                break;
            }
        }

        if !read_bytes.is_empty() {
            println!("{}", String::from_utf8_lossy(&read_bytes));
        }
    }
}

fn handle_listener_error(connection: io::Result<LocalSocketStream>) -> Option<LocalSocketStream> {
    connection.ok()
}
