use std::fs::File;
use std::io::Write;
use std::panic;

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

    let orig_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_panic_hook(panic_info);
        let mut file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open("C:/Users/sean/AppData/Local/Susi/logs/panic.log")
            .unwrap();
        let backtrace = std::backtrace::Backtrace::force_capture();
        file.write_all(backtrace.to_string().as_bytes()).unwrap()
    }))
}
