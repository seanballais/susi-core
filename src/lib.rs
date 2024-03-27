mod crypto;
mod ds;
mod errors;
mod ffi;
pub mod logging;
mod metadata;
mod multithreading;
mod supervisor;
mod tasks;
mod workers;

pub fn init_core_systems() {
    tasks::init_task_manager();
    workers::init_worker_pool();
}
