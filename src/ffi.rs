use crate::init_core_systems;

mod errors;
mod tasks;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    init_core_systems();
}
