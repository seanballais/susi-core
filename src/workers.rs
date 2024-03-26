use std::cell::OnceCell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, mpsc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use once_cell::sync::Lazy;
use crate::ds::{FIFOQueue, Queue};
use crate::errors::Error;

use crate::tasks::{TASK_MANAGER, TaskID, TaskObject, TaskProgress};

pub static WORKER_POOL: OnceLock<WorkerPool> = OnceLock::new();

pub fn init_worker_pool() {
    WORKER_POOL.get_or_init(|| {
        let default_num = NonZeroUsize::new(1).unwrap(); // 1 is definitely non-zero.
        let num_workers = thread::available_parallelism().unwrap_or(default_num);

        // Temporary number of workers. We'll let the number of workers be configurable later.
        WorkerPool::new(num_workers.get())
    });
}

// Based on: https://web.mit.edu/rust-lang_v1.25/arch/
//                   amd64_ubuntu1404/share/doc/rust/
//                   html/book/second-edition/
//                   ch20-03-designing-the-interface.html
#[derive(Debug)]
pub struct WorkerPool {
    workers: FIFOQueue<Worker>,
}

impl WorkerPool {
    pub fn new(num_workers: usize) -> Self {
        assert!(num_workers > 0);

        let mut workers = FIFOQueue::with_capacity(num_workers);
        for id in 0..num_workers {
            workers.push(Worker::new(id as u32));
        }

        Self {
            workers
        }
    }
}

#[derive(Debug)]
struct Worker {
    id: u32,
    thread: thread::JoinHandle<()>,
}

impl Worker {
    pub fn new(id: u32) -> Self {
        let thread = thread::spawn(move || {
            loop {
                tracing::info!("Thread {} is getting a task", id);
                let mut task_manager = TASK_MANAGER.get().unwrap().lock().unwrap();
                let mut task = task_manager.pop_task();
                let task_status = task_manager.get_task_status(task.get_id()).unwrap();

                let num_read_bytes = task_status.get_num_read_bytes_ref();
                let num_written_bytes = task_status.get_num_written_bytes_ref();
                let should_stop = task_status.get_should_stop_ref();

                task_status.set_progress(TaskProgress::RUNNING);

                drop(task_manager); // IMPORTANT. Otherwise, other workers will be locked out.

                tracing::info!("Thread {} running task {}", id, task.get_id());
                let res = task.run(Some(num_read_bytes), Some(num_written_bytes), Some(should_stop));

                // Reacquire lock because we need to update a task status.
                let mut task_manager = TASK_MANAGER.get().unwrap().lock().unwrap();
                let task_status = task_manager.get_task_status(task.get_id()).unwrap();
                task_status.set_progress(TaskProgress::DONE);
                match res {
                    Err(e) => { task_status.set_last_error(e); },
                    _ => {}
                }
            }
        });

        Self { id, thread }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;
    use crate::tasks::init_task_manager;
    use super::*;

    #[test]
    fn test_worker_pool_tackles_queued_encrypted_task_successfully() {
        init_task_manager();
        init_worker_pool();

        const SRC_FILENAME: &str = "src-file.txt";
        const DEST_FILENAME: &str = "dest-file.txt";
        let dir = tempdir().unwrap();
        let src_file_path = dir.path().join(SRC_FILENAME);
        let dest_file_path = dir.path().join(DEST_FILENAME);

        let src_file_res = File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(src_file_path.clone());
        let dest_file_res = File::create(dest_file_path.clone());

        assert!(src_file_res.is_ok());
        assert!(dest_file_res.is_ok());

        let mut src_file = src_file_res.unwrap();
        let dest_file = dest_file_res.unwrap();
        let password = Vec::from("a-very-legit-long-password".as_bytes());

        let res = src_file.write("bling-bam-bam-born".as_bytes());
        assert!(res.is_ok());

        let mut task_manager = TASK_MANAGER.get().unwrap().lock().unwrap();
        let task_id = task_manager.queue_encryption_task(src_file, dest_file, password);

        let start = Instant::now();
        const MAX_EXECUTION_TIME_SECS: u64 = 5;
        loop {
            let status = task_manager.get_task_status(task_id).unwrap();
            if status.get_progress() == TaskProgress::DONE {
                break;
            }

            println!("{:?}", start.elapsed());
            assert!(start.elapsed() < Duration::from_secs(MAX_EXECUTION_TIME_SECS));
        }
    }
}
