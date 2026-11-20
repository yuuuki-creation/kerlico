use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{ready, Context, Poll};

use io_uring::{cqueue, opcode, types, IoUring};
use tokio::io::{unix::AsyncFd, Interest};

const COUNT: u16 = 128;
const SIZE: usize = 65536 + tun_rs::VIRTIO_NET_HDR_LEN;
const GROUP: u16 = 1;
const RECEIVE: u64 = 1;

struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
}

impl Mapping {
    fn new(len: usize) -> io::Result<Self> {
        // SAFETY: no address constraint, anonymous mapping, and a nonzero size.
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ptr: NonNull::new(raw.cast()).expect("mmap used the null address"),
            len,
        })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this mapping is uniquely owned and not leased to the kernel.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

struct Pool {
    metadata: Mapping,
    frames: Mapping,
    tail: u16,
}

impl Pool {
    fn new() -> io::Result<Self> {
        Ok(Self {
            metadata: Mapping::new(COUNT as usize * size_of::<types::BufRingEntry>())?,
            frames: Mapping::new(COUNT as usize * SIZE)?,
            tail: 0,
        })
    }

    fn slot(&self, id: u16) -> *mut u8 {
        assert!(id < COUNT);
        // SAFETY: id is in range and there are COUNT frame slots.
        unsafe { self.frames.ptr.as_ptr().add(id as usize * SIZE) }
    }

    fn advertise(&mut self, ids: impl IntoIterator<Item = u16>) {
        let base = self.metadata.ptr.as_ptr().cast::<types::BufRingEntry>();
        for id in ids {
            // SAFETY: the entry contains only integer fields.
            let mut entry: types::BufRingEntry = unsafe { std::mem::zeroed() };
            entry.set_addr(self.slot(id) as u64);
            entry.set_len(SIZE as u32);
            entry.set_bid(id);
            // The slot is unowned by the kernel until the next tail publication.
            // Leave the reserved word alone because slot zero shares it with tail.
            unsafe {
                ptr::copy_nonoverlapping(
                    (&entry as *const types::BufRingEntry).cast::<u8>(),
                    base.add((self.tail % COUNT) as usize).cast::<u8>(),
                    size_of::<types::BufRingEntry>() - size_of::<u16>(),
                );
            }
            self.tail = self.tail.wrapping_add(1);
        }
        // SAFETY: a page-aligned, initialized BufRingEntry array owns tail.
        let tail = unsafe { AtomicU16::from_ptr(types::BufRingEntry::tail(base).cast_mut()) };
        tail.store(self.tail, Ordering::Release);
    }
}

// Readiness borrows the ring descriptor. The registration is destroyed before
// the ring; the TUN also remains alive while its request is running.
struct RingFd(RawFd);
impl AsRawFd for RingFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

pub(super) struct Multishot {
    readiness: AsyncFd<RingFd>,
    ring: IoUring,
    pool: Option<Pool>,
    tun_fd: RawFd,
    active: bool,
}

impl Multishot {
    pub(super) fn new(tun_fd: RawFd) -> io::Result<Self> {
        let ring = IoUring::new(128)?;
        let mut probe = io_uring::Probe::new();
        ring.submitter().register_probe(&mut probe)?;
        if !probe.is_supported(opcode::ReadMulti::CODE) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        // SAFETY: this is the only reactor registration for the ring and
        // the registration field drops before the ring closes its descriptor.
        let readiness = unsafe {
            AsyncFd::register_with_interest(RingFd(ring.as_raw_fd()), Interest::READABLE)?
        };
        let mut pool = Pool::new()?;
        // SAFETY: pool outlives the registration or is retained if cancellation
        // cannot be confirmed.
        unsafe {
            ring.submitter().register_buf_ring_with_flags(
                pool.metadata.ptr.as_ptr() as u64,
                COUNT,
                GROUP,
                0,
            )?;
        }
        pool.advertise(0..COUNT);
        Ok(Self {
            readiness,
            ring,
            pool: Some(pool),
            tun_fd,
            active: false,
        })
    }

    fn arm(&mut self) -> io::Result<()> {
        let entry = opcode::ReadMulti::new(types::Fd(self.tun_fd), 0, GROUP)
            .build()
            .user_data(RECEIVE);
        // SAFETY: the drive owns the TUN until submit imports the file; all
        // offered buffers outlive the operation.
        unsafe { self.ring.submission().push(&entry) }.map_err(io::Error::other)?;
        self.active = true;
        loop {
            match self.ring.submit() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(1) => return Ok(()),
                Ok(_) => return Err(io::Error::other("multishot read was not submitted")),
                Err(error) => return Err(error),
            }
        }
    }

    fn completion_result(&mut self, entry: cqueue::Entry) -> io::Result<Option<(u16, usize)>> {
        assert_eq!(entry.user_data(), RECEIVE);
        self.active = cqueue::more(entry.flags());
        let result = entry.result();
        if result == -libc::ENOBUFS {
            // Poll again after the returned slots have been recycled.
            return Ok(None);
        }
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        if result == 0 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let id = cqueue::buffer_select(entry.flags())
            .ok_or_else(|| io::Error::other("TUN multishot completion had no buffer"))?;
        if id >= COUNT || result as usize > SIZE {
            return Err(io::Error::other("invalid TUN multishot completion buffer"));
        }
        Ok(Some((id, result as usize)))
    }

    pub(super) fn poll_packet<R>(
        &mut self,
        cx: &mut Context<'_>,
        consume: impl FnOnce(&mut [u8]) -> R,
    ) -> Poll<io::Result<R>> {
        loop {
            if !self.active {
                self.arm()?;
            }
            let entry = self.ring.completion().next();
            if let Some(entry) = entry {
                if let Some((id, len)) = self.completion_result(entry)? {
                    // SAFETY: the consumed CQE releases ownership of this validated
                    // slot. Recycle only after consume ends and the borrow expires.
                    let bytes = unsafe {
                        std::slice::from_raw_parts_mut(self.pool.as_ref().unwrap().slot(id), len)
                    };
                    let result = consume(bytes);
                    self.recycle(id);
                    return Poll::Ready(Ok(result));
                }
            } else {
                let mut ready = ready!(self.readiness.poll_read_ready(cx))?;
                // A CQE may arrive while clearing readiness. Recheck the ring
                // before returning to the executor.
                ready.clear_ready();
            }
        }
    }

    fn recycle(&mut self, id: u16) {
        self.pool.as_mut().unwrap().advertise([id]);
    }

    pub(super) fn discard(&mut self) -> io::Result<()> {
        if self.active {
            loop {
                match self
                    .ring
                    .submitter()
                    .register_sync_cancel(None, types::CancelBuilder::any())
                {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                    _ => break,
                }
            }
        }
        loop {
            let next = self.ring.completion().next();
            let Some(entry) = next else { break };
            assert_eq!(entry.user_data(), RECEIVE);
            self.active = cqueue::more(entry.flags());
            if let Some(id) = cqueue::buffer_select(entry.flags()) {
                if id >= COUNT {
                    return Err(io::Error::other("invalid cancelled TUN read buffer"));
                }
                self.recycle(id);
            }
        }
        if self.active {
            return Err(io::Error::other("TUN read termination was not observed"));
        }
        Ok(())
    }
}

impl Drop for Multishot {
    fn drop(&mut self) {
        if let Err(error) = self
            .discard()
            .and_then(|()| self.ring.submitter().unregister_buf_ring(GROUP))
        {
            eprintln!("WireGuard: TUN multishot teardown: {error}");
            // Never unmap pages which an unconfirmed kernel request could use.
            if let Some(pool) = self.pool.take() {
                std::mem::forget(pool);
            }
        }
    }
}
