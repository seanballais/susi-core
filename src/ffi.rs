use crate::init_core_systems;
use std::fs::File;
use std::io::Write;

pub mod errors;
mod tasks;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    init_core_systems();

    tracing::info!("Finished initializing core systems");
}
