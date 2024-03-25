use std::cell::OnceCell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use once_cell::sync::Lazy;
use crate::ds::{FIFOQueue, Queue};
use crate::errors::Error;

use crate::tasks::{TASK_MANAGER, TaskID, TaskObject};

pub static WORKER_POOL: OnceCell<WorkerPool> = OnceCell::new();

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
        let thread = thread::spawn(|| {
            loop {
                tracing::info!("Thread {} is getting a task", id);
                let mut task_manager = TASK_MANAGER.lock().unwrap();
                let mut task = task_manager.pop_task();
                let Some(task_status) = task_manager.get_task_status(task.get_id());

                let num_read_bytes = task_status.get_num_read_bytes_mut_ref();
                let num_written_bytes = task_status.get_num_written_bytes_mut_ref();
                let should_stop = task_status.get_should_stop_mut_ref();

                tracing::info!("Thread {} running task {}", id, task.get_id());
                let res = task.run(Some(num_read_bytes), Some(num_written_bytes), Some(should_stop));
                match res {
                    Err(e) => { task_status.set_last_error(e); },
                    _ => {}
                }
            }
        });

        Self { id, thread }
    }
}
