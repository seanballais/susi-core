use crate::logging;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    logging::init_logging();
    logging::init_panic_hooks();
}
