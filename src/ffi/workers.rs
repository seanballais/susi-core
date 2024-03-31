use crate::workers::WORKER_POOL;

#[no_mangle]
pub extern "C" fn close_worker_pool() {
    WORKER_POOL.lock().unwrap().close();
}
