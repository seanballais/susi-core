use crate::init_core_systems;

mod errors;
mod tasks;

#[no_mangle]
pub extern fn init_susi_core() {
    init_core_systems();

    tracing::info!("Finished initializing core systems");
}
