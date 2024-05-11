use crate::init_core_systems;

// We need to set `errors` to public visibility since it's used in `src/logging.rs`.
pub mod errors;
mod logging;
mod tasks;
mod validation;
mod files;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    init_core_systems();

    tracing::info!("Finished initializing core systems");
}
