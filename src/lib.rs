mod components;
mod crypto;
mod ds;
mod errors;
mod ffi;
mod logging;
mod metadata;
mod multithreading;
mod supervisor;
mod tasks;
mod workers;

pub fn init_core_systems() {
    logging::init_logging();
    logging::init_panic_hooks();
    tasks::init_task_manager();
    workers::init_worker_pool();
}
