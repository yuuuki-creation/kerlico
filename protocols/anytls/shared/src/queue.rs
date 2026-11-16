//! A growable byte ring. Pushing copies once into free space; popping copies out and moves the head.

pub(crate) struct ByteQueue {
    buf: Vec<u8>,
    head: usize,
    len: usize,
}

impl ByteQueue {
    pub(crate) const fn new() -> Self {
        Self { buf: Vec::new(), head: 0, len: 0 }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.len + bytes.len() > self.buf.len() {
            self.grow(self.len + bytes.len());
        }
        let cap = self.buf.len();
        let tail = (self.head + self.len) % cap;
        let first = bytes.len().min(cap - tail);
        self.buf[tail..tail + first].copy_from_slice(&bytes[..first]);
        self.buf[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.len += bytes.len();
    }

    pub(crate) fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        if n == 0 {
            return 0;
        }
        let cap = self.buf.len();
        let first = n.min(cap - self.head);
        out[..first].copy_from_slice(&self.buf[self.head..self.head + first]);
        out[first..n].copy_from_slice(&self.buf[..n - first]);
        self.head = (self.head + n) % cap;
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
        }
        n
    }

    /// Copies the first `out.len()` bytes without removing them. `false` if there are fewer.
    pub(crate) fn peek(&self, out: &mut [u8]) -> bool {
        if out.len() > self.len {
            return false;
        }
        let cap = self.buf.len();
        let first = out.len().min(cap - self.head);
        out[..first].copy_from_slice(&self.buf[self.head..self.head + first]);
        let rest = out.len() - first;
        out[first..].copy_from_slice(&self.buf[..rest]);
        true
    }

    pub(crate) fn skip(&mut self, n: usize) {
        let n = n.min(self.len);
        if self.len == n {
            self.clear();
        } else if n > 0 {
            self.head = (self.head + n) % self.buf.len();
            self.len -= n;
        }
    }

    fn grow(&mut self, need: usize) {
        let cap = need.next_power_of_two().max(4096);
        let mut next = vec![0u8; cap];
        let n = self.pop(&mut next[..self.len]);
        self.buf = next;
        self.head = 0;
        self.len = n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_grows_without_losing_order() {
        let mut queue = ByteQueue::new();
        let mut expect = std::collections::VecDeque::new();
        let mut counter = 0u8;
        let mut out = vec![0u8; 10000];
        for round in 0..2000usize {
            let push = (round * 37) % 3001;
            let bytes: Vec<u8> = (0..push).map(|_| { counter = counter.wrapping_add(1); counter }).collect();
            queue.push(&bytes);
            expect.extend(bytes);
            let take = (round * 53) % 2999;
            let n = queue.pop(&mut out[..take]);
            assert_eq!(n, take.min(expect.len()));
            for byte in &out[..n] {
                assert_eq!(Some(*byte), expect.pop_front());
            }
            assert_eq!(queue.len(), expect.len());
        }
        let mut peek = [0u8; 3];
        if queue.len() >= 3 {
            assert!(queue.peek(&mut peek));
            assert_eq!(peek[0], expect[0]);
        }
    }
}
