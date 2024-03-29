mod crypto;
mod ds;
mod errors;
mod ffi;
pub mod logging;
mod metadata;
mod tasks;
mod workers;

pub fn init_core_systems() {
    logging::init_thread_local_logging();
    tasks::init_task_manager();
    workers::init_worker_pool();
}
