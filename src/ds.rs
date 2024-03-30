use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

// Based on: https://untitled.dev/thread-safe-queue-rust
pub trait Queue<T> {
    fn new() -> Self;
    fn with_capacity(size: usize) -> Self;
    fn push(&self, value: T);
    fn pop(&self) -> Option<T>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
}

#[derive(Debug)]
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
    fn pop(&self) -> Option<T> {
        // We're unwrapping here since the world might already in a bad state when our mutex lock
        // is poisoned. Same case for our Condvar.
        let mut data = self.data.lock().unwrap();
        if data.is_empty() {
            None
        } else {
            Some(data.pop_front().unwrap())
        }
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
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
        assert!(queue.is_empty());
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
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
        assert!(queue.is_empty());
    }
}
