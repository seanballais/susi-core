use std::collections::HashMap;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use crate::ds::{FIFOQueue, Queue};
use crate::errors::Error;

use crate::tasks::{TASK_QUEUE, TaskID, TaskObject};

pub type WorkerErrors = HashMap<TaskID, Error>;

// Based on: https://web.mit.edu/rust-lang_v1.25/arch/
//                   amd64_ubuntu1404/share/doc/rust/
//                   html/book/second-edition/
//                   ch20-03-designing-the-interface.html
#[derive(Debug)]
pub struct WorkerPool<'a> {
    workers: FIFOQueue<Worker>,
    task_to_worker_map: Arc<Mutex<HashMap<TaskID, &'a Worker>>>
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

    pub fn execute_task()
}

#[derive(Debug)]
struct Worker {
    id: u32,
    thread: thread::JoinHandle<()>,
    task_status: Arc<Mutex<TaskStatus>>,
    errors: Arc<WorkerErrors>
}

impl Worker {
    pub fn new(id: u32) -> Self {
        let task_status = Arc::new(TaskStatus::new());
        let errors:Arc<WorkerErrors> = Arc::new(WorkerErrors::new());
        let thread = thread::spawn(|| {
            let mut task_status = task_status.clone();
            let errors = errors.clone();
            loop {
                tracing::info!("Thread {} is getting a task", id);
                let mut task = TASK_QUEUE.pop();
                let num_read_bytes = task_status.get_num_read_bytes_mut_ref();
                let num_written_bytes = task_status.get_num_written_bytes_mut_ref();
                let should_stop = task_status.get_should_stop_mut_ref();

                tracing::info!("Thread {} running task {}", id, task.get_id());
                let res = task.run(Some(num_read_bytes), Some(num_written_bytes), Some(should_stop));
                match res {
                    Err(e) => { errors.lock().unwrap().insert(task.get_id(), e); },
                    _ => {}
                }
            }
        });

        Self { id, thread, task_status, errors }
    }
}
