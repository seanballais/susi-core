use std::fs::File;
use std::io::Write;
use crate::ds::{FIFOQueue, Queue};
use std::num::NonZeroUsize;
use std::sync::mpsc::TryRecvError;
use std::sync::{Mutex, OnceLock};
use std::thread;

use bus::{Bus, BusReader};
use once_cell::sync::Lazy;
use tracing::Level;

use crate::logging;
use crate::tasks::{TaskProgress, TASK_MANAGER};

pub static WORKER_POOL: Lazy<Mutex<WorkerPool>> = Lazy::new(|| {
    let default_num = unsafe { NonZeroUsize::new_unchecked(1) };
    let num_workers = thread::available_parallelism().unwrap_or(default_num);

    // Temporary number of workers. We'll let the number of workers be configurable later.
    Mutex::new(WorkerPool::new(num_workers.get()))
});

pub fn init_worker_pool() {
    WORKER_POOL.lock().unwrap().kick_start();
}

#[derive(Debug, Copy, Clone)]
enum WorkerMessage {
    NONE,
    TERMINATE
}

// Based on: https://web.mit.edu/rust-lang_v1.25/arch/
//                   amd64_ubuntu1404/share/doc/rust/
//                   html/book/second-edition/
//                   ch20-03-designing-the-interface.html
#[derive(Debug)]
pub struct WorkerPool {
    workers: Vec<Worker>,
    bus: Bus<WorkerMessage>
}

impl WorkerPool {
    pub fn new(num_workers: usize) -> Self {
        assert!(num_workers > 0);

        let mut bus = Bus::new(5);

        let mut workers = Vec::with_capacity(num_workers);
        for id in 0..num_workers {
            workers.push(Worker::new(id as u32, bus.add_rx()));
        }

        Self { workers, bus }
    }

    // The WorkerPool is loaded in lazily, so this function is used to initialize it.
    pub fn kick_start(&self) {}

    pub fn close(&mut self) {
        self.bus.broadcast(WorkerMessage::TERMINATE);

        while let Some(worker) = self.workers.pop() {
            worker.thread.join().unwrap();
        }
    }
}

#[derive(Debug)]
struct Worker {
    id: u32,
    thread: thread::JoinHandle<()>
}

impl Worker {
    pub fn new(id: u32, mut bus_receiver: BusReader<WorkerMessage>) -> Self {
        let thread = thread::spawn(move || {
            tracing::span!(Level::INFO, "worker_thread", worker_id = id);
            loop {
                match bus_receiver.try_recv() {
                    Ok(message) => {
                        match message {
                            WorkerMessage::TERMINATE => break,
                            WorkerMessage::NONE => {}
                        };
                    }
                    Err(_) => {}
                }

                logging::info!("Thread {} is getting a task", id);
                let mut task = match TASK_MANAGER.pop_task() {
                    Some(t) => t,
                    None => { continue; }
                };
                let task_status_ptr = TASK_MANAGER.get_task_status(task.get_id()).unwrap();
                let mut task_status = task_status_ptr.lock().unwrap();

                let num_read_bytes = task_status.get_num_read_bytes_ref();
                let num_written_bytes = task_status.get_num_written_bytes_ref();
                let should_stop = task_status.get_should_stop_ref();

                task_status.set_progress(TaskProgress::RUNNING);

                logging::info!("Thread {} running task {}", id, task.get_id());
                let res = task.run(
                    Some(num_read_bytes.clone()),
                    Some(num_written_bytes.clone()),
                    Some(should_stop.clone()),
                );

                match res {
                    Ok(()) => {
                        task_status.set_progress(TaskProgress::DONE);
                    }
                    Err(e) => {
                        task_status.set_last_error(e);
                        task_status.set_progress(TaskProgress::FAILED);
                    }
                }
            }
        });

        Self { id, thread }
    }
}
