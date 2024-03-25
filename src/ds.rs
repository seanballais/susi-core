use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

// Based on: https://untitled.dev/thread-safe-queue-rust
pub trait Queue<T> {
    fn new() -> Self;
    fn with_capacity(size: usize) -> Self;
    fn push(&self, value: T);
    fn pop(&self) -> T;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
}

pub struct FIFOQueue<T> {
    data: Mutex<VecDeque<T>>,
    cond_var: Condvar,
}

impl<T> Queue<T> for FIFOQueue<T> {
    fn new() -> Self {
        Self {
            data: Mutex::new(VecDeque::new()),
            cond_var: Condvar::new(),
        }
    }

    fn with_capacity(size: usize) -> Self {
        Self {
            data: Mutex::new(VecDeque::with_capacity(size)),
            cond_var: Condvar::new(),
        }
    }

    fn push(&self, value: T) {
        // We're unwrapping here since the world might already in a bad state when our mutex lock
        // is poisoned. Same case for our Condvar.
        let mut data = self.data.lock().unwrap();
        data.push_back(value);

        self.cond_var.notify_one();
    }

    // Popping will wait if the queue is empty.
    fn pop(&self) -> T {
        // We're unwrapping here since the world might already in a bad state when our mutex lock
        // is poisoned. Same case for our Condvar.
        let mut data = self.data.lock().unwrap();
        while data.is_empty() {
            data = self.cond_var.wait(data).unwrap();
        }

        data.pop_front().unwrap()
    }

    fn len(&self) -> usize {
        // We're unwrapping here since the world might already in a bad state when our mutex lock
        // is poisoned.
        let data = self.data.lock().unwrap();
        data.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

unsafe impl<T> Sync for FIFOQueue<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_using_fifo_queue_works_properly() {
        let queue = Arc::new(FIFOQueue::<i32>::new());

        let q1 = queue.clone();
        let t1 = std::thread::spawn(move || {
            q1.push(1);
            q1.push(2);
        });

        t1.join().unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), 1);
        assert_eq!(queue.pop(), 2);
        assert!(queue.is_empty());

        let q2 = queue.clone();
        let t2 = std::thread::spawn(move || {
            q2.push(q2.pop()); // The pop should be blocked at this point since the queue is empty.
            q2.push(3);
        });

        let q3 = queue.clone();
        let t3 = std::thread::spawn(move || {
            // After this one, t2 should be unblocked, and will then be able to push.
            q3.push(4);
        });

        t2.join().unwrap();
        t3.join().unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), 4);
        assert_eq!(queue.pop(), 3);
    }

    #[test]
    fn test_using_fifo_queue_with_set_capacity_works_properly() {
        let queue = Arc::new(FIFOQueue::<i32>::with_capacity(3));

        let q1 = queue.clone();
        let t1 = std::thread::spawn(move || {
            q1.push(1);
            q1.push(2);
        });

        t1.join().unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), 1);
        assert_eq!(queue.pop(), 2);
        assert!(queue.is_empty());

        let q2 = queue.clone();
        let t2 = std::thread::spawn(move || {
            q2.push(q2.pop()); // The pop should be blocked at this point since the queue is empty.
            q2.push(3);
        });

        let q3 = queue.clone();
        let t3 = std::thread::spawn(move || {
            // After this one, t2 should be unblocked, and will then be able to push.
            q3.push(4);
        });

        t2.join().unwrap();
        t3.join().unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), 4);
        assert_eq!(queue.pop(), 3);
    }
}
