use std::sync::OnceLock;
use tracing_appender::non_blocking::WorkerGuard;

pub mod components;
pub mod crypto;
pub mod error;
pub mod logging;
pub mod metadata;
pub mod tasks;
pub mod workers;
pub mod ds;
mod supervisor;
