use crate::{init_core_systems, logging as susi_logging};
use std::fs::File;
use std::io::Write;

pub mod errors;
mod tasks;
mod workers;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    init_core_systems();

    tracing::info!("Finished initializing core systems");
}
