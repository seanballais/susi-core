// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
mod crypto;
mod ds;
mod errors;
mod ffi;
mod fs;
pub mod logging;
mod metadata;
mod path;
mod tasks;
mod workers;
mod constants;
mod testing;

pub fn init_core_systems() {
    logging::init_logging();
    tasks::init_task_manager();
    workers::init_worker_pool();

    // TODO: Update this panic hook later on.
    // let orig_panic_hook = panic::take_hook();
    // panic::set_hook(Box::new(move |panic_info| {
    //     orig_panic_hook(panic_info);
    //     let mut file = File::options()
    //         .write(true)
    //         .create(true)
    //         .truncate(true)
    //         .open("C:/Users/sean/AppData/Local/Susi/logs/panic.log")
    //         .unwrap();
    //     let backtrace = std::backtrace::Backtrace::force_capture();
    //     file.write_all(panic_info.to_string().as_bytes()).unwrap();
    //     file.write_all(backtrace.to_string().as_bytes()).unwrap();
    // }))
}
