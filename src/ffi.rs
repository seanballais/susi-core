use crate::init_core_systems;

pub mod errors;
mod logging;
mod tasks;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    init_core_systems();

    tracing::info!("Finished initializing core systems");
}
