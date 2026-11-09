use std::io::{self, Write};
use std::time::Duration;

use super::{invalid, retryable};

pub(super) struct Segment {
    pub(super) end: usize,
    pub(super) delay: Duration,
}

struct Pending {
    input: Vec<u8>,
    wire: Vec<u8>,
    segments: Vec<Segment>,
    segment: usize,
    written: usize,
}

pub(super) struct WireWriter {
    inner: Box<dyn Write + Send>,
    pending: Option<Pending>,
    closed: bool,
}

impl WireWriter {
    pub(super) fn new(inner: Box<dyn Write + Send>) -> Self {
        Self { inner, pending: None, closed: false }
    }

    pub(super) fn resume(&mut self, input: &[u8]) -> io::Result<Option<usize>> {
        self.check_open()?;
        let Some(pending) = &self.pending else { return Ok(None); };
        if !input.starts_with(&pending.input) {
            return Err(invalid("masked write retry changed the pending input"));
        }
        let used = pending.input.len();
        self.drain_pending()?;
        self.pending = None;
        Ok(Some(used))
    }

    pub(super) fn frame(&mut self, input: &[u8], wire: Vec<u8>, segments: Vec<Segment>) -> io::Result<usize> {
        debug_assert!(self.pending.is_none());
        debug_assert_eq!(segments.last().map(|segment| segment.end), Some(wire.len()));
        self.pending = Some(Pending {
            input: input.to_vec(),
            wire,
            segments,
            segment: 0,
            written: 0,
        });
        self.resume(input).map(|used| used.expect("pending masked frame"))
    }

    pub(super) fn direct(&mut self, input: &[u8]) -> io::Result<usize> {
        debug_assert!(self.pending.is_none());
        self.check_open()?;
        self.inner.write(input)
    }

    pub(super) fn flush(&mut self) -> io::Result<()> {
        self.check_open()?;
        self.drain_pending()?;
        self.inner.flush()
    }

    fn drain_pending(&mut self) -> io::Result<()> {
        let Some(pending) = &mut self.pending else { return Ok(()); };
        while let Some(segment) = pending.segments.get(pending.segment) {
            while pending.written < segment.end {
                let error = match self.inner.write(&pending.wire[pending.written..segment.end]) {
                    Ok(0) => io::Error::new(io::ErrorKind::WriteZero, "masked wire write stalled"),
                    Ok(len) => {
                        pending.written += len;
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => error,
                };
                if !retryable(&error) {
                    self.pending = None;
                    self.closed = true;
                }
                return Err(error);
            }
            if !segment.delay.is_zero() {
                std::thread::sleep(segment.delay);
            }
            pending.segment += 1;
        }
        Ok(())
    }

    fn check_open(&self) -> io::Result<()> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Allows exactly `at` bytes, reports backpressure once, then resumes.
    pub(in crate::finalmask) struct Pause {
        pub(in crate::finalmask) at: Option<usize>,
        pub(in crate::finalmask) kind: io::ErrorKind,
        pub(in crate::finalmask) wire: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Pause {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut wire = self.wire.lock().unwrap();
            let len = match self.at {
                Some(at) if at == wire.len() => {
                    self.at = None;
                    return Err(self.kind.into());
                }
                Some(at) => (at - wire.len()).min(bytes.len()),
                None => bytes.len(),
            };
            wire.extend_from_slice(&bytes[..len]);
            Ok(len)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
