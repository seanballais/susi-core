use crate::{init_core_systems, logging};
use std::fs::File;
use std::io::Write;

pub mod errors;
mod tasks;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    init_core_systems();

    logging::info!("Finished initializing core systems");
}
