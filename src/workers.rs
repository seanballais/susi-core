use std::num::NonZeroUsize;
use std::sync::OnceLock;
use std::thread;
use crate::ds::{FIFOQueue, Queue};

use crate::tasks::{TASK_MANAGER, TaskProgress};

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

        let workers = FIFOQueue::with_capacity(num_workers);
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
