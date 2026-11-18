use super::*;

impl<R> AdvancedTlsRead<R> {
    /// TLS 1.3 lends authenticated records from its receive storage. Legacy
    /// versions keep their native record implementation.
    pub fn has_buffered_records(&self) -> bool {
        self.rx.is_some() && !self.direct
    }

    pub fn buffered_records<'a>(&'a self, slices: &mut [IoSlice<'a>]) -> usize {
        let mut ranges = self.plaintext.iter().peekable();
        let mut count = 0;
        for slot in slices {
            let Some(first) = ranges.next() else { break };
            let mut end = first.end;
            while let Some(next) = ranges.next_if(|next| next.start == end) {
                end = next.end;
            }
            *slot = IoSlice::new(&self.wire[first.start..end]);
            count += 1;
        }
        count
    }

    pub fn buffered_record(&self) -> &[u8] {
        self.plaintext
            .front()
            .map_or(&[], |range| &self.wire[range.clone()])
    }

    pub fn consume_records(&mut self, mut n: usize) {
        while n != 0 {
            let front = self
                .plaintext
                .front_mut()
                .expect("consume authenticated TLS bytes");
            let used = n.min(front.len());
            front.start += used;
            n -= used;
            if front.start == front.end {
                self.plaintext.pop_front();
            }
        }
    }

    pub(super) fn copy_plaintext(&mut self, bytes: &mut [u8]) -> usize {
        let first = self.buffered_record();
        let n = first.len().min(bytes.len());
        bytes[..n].copy_from_slice(&first[..n]);
        self.consume_records(n);
        n
    }

    pub(super) fn process_messages(&mut self, messages: Vec<records::Message>) -> io::Result<()> {
        for message in messages {
            let mut core = self.core.lock().expect("TLS state");
            match message {
                records::Message::Closed => {
                    self.closed = true;
                    let state = core.get_shutdown() | ShutdownState::RECEIVED;
                    core.set_shutdown(state);
                }
                records::Message::KeyUpdate(true)
                    if !core.get_shutdown().contains(ShutdownState::SENT)
                        && !core.get_ref().terminal_write =>
                {
                    let io = core.get_mut();
                    if let Some(sender) = &mut io.sender {
                        sender.update(&mut io.output)?;
                    } else {
                        io.prepared_sender = None;
                        core.ssl_mut()
                            .request_key_update(false)
                            .map_err(io::Error::other)?;
                        flush_open_tls(&mut core).map_err(io::Error::other)?;
                    }
                    if !core.get_ref().output.is_empty() {
                        self.control.pending.store(true, Ordering::Release);
                    }
                }
                records::Message::KeyUpdate(_) => {}
                records::Message::Ticket(ticket) => {
                    // SAFETY: the live native client validates one complete,
                    // authenticated ticket. Its returned session is owned.
                    let session = unsafe {
                        boring_sys::SSL_process_tls13_new_session_ticket(
                            core.ssl_mut().as_ptr(),
                            ticket.as_ptr(),
                            ticket.len(),
                        )
                    };
                    if session.is_null() {
                        return Err(io::Error::other("TLS session ticket"));
                    }
                    let session = unsafe { boring2::ssl::SslSession::from_ptr(session) };
                    if let Some(cache) = &self.session_cache {
                        cache.cache_ticket(core.ssl(), session);
                    }
                }
            }
        }
        Ok(())
    }
}

impl<R: Read> AdvancedTlsRead<R> {
    /// Lend a bounded batch to a byte-stream consumer. Vision uses Read, which
    /// stops after each record before deciding whether to switch to DIRECT.
    pub fn prepare_buffered_records(&mut self) -> io::Result<()> {
        if !self.has_buffered_records() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.fill_tls13_records(16)
    }

    /// The transport must be nonblocking. Drain its currently ready bytes
    /// before lending the batch, bounded by sixteen maximum wire records.
    /// Once a batch is lent, preparation returns it unchanged until consumed.
    pub fn prepare_nonblocking_records(&mut self) -> io::Result<()> {
        if !self.has_buffered_records() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.fill_records(16, true)
    }

    pub(super) fn fill_tls13_records(&mut self, limit: usize) -> io::Result<()> {
        self.fill_records(limit, false)
    }

    fn fill_records(&mut self, limit: usize, drain_ready: bool) -> io::Result<()> {
        if !self.plaintext.is_empty() {
            return Ok(());
        }
        if let Some(error) = self.pending_error.take() {
            if self.needs_write() {
                let _ = self.control.flush(&self.core);
            }
            return Err(error);
        }
        while !self.closed {
            let step = match self.decode_tls13_record(drain_ready) {
                Ok(false) if drain_ready && !self.plaintext.is_empty() => self.read_ready_tail(),
                result => result,
            };
            match step {
                Ok(true)
                    if self.plaintext.len() >= limit
                        || (self.needs_write() && !self.plaintext.is_empty()) =>
                {
                    return Ok(())
                }
                Ok(true) => {}
                Ok(false) if !self.plaintext.is_empty() => return Ok(()),
                Ok(false) => self.read_wire()?,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    return if self.plaintext.is_empty() {
                        Err(error)
                    } else {
                        Ok(())
                    };
                }
                Err(error) => {
                    self.closed = true;
                    if let Some(record) = error
                        .get_ref()
                        .and_then(|e| e.downcast_ref::<records::RecordError>())
                    {
                        {
                            let mut core = self.core.lock().expect("TLS state");
                            let io = core.get_mut();
                            if let Some(sender) = &mut io.sender {
                                sender.seal(&mut io.output, 21, &[2, record.alert])?;
                            } else {
                                io.prepared_sender = None;
                                // SAFETY: the live native connection still owns this send epoch.
                                unsafe {
                                    boring_sys::SSL_send_fatal_alert(
                                        core.ssl_mut().as_ptr(),
                                        record.alert,
                                    );
                                }
                            }
                            core.get_mut().terminal_write = true;
                            self.control
                                .pending
                                .store(!core.get_ref().output.is_empty(), Ordering::Release);
                        }
                    }
                    if self.plaintext.is_empty() {
                        if self.needs_write() {
                            let _ = self.control.flush(&self.core);
                        }
                        return Err(error);
                    }
                    self.pending_error = Some(error);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn read_ready_tail(&mut self) -> io::Result<bool> {
        const MAX_BATCH_WIRE: usize = 16 * MAX_RECORD;
        if self.tail == self.wire.len() {
            if self.wire.len() == MAX_BATCH_WIRE {
                return Ok(false);
            }
            // No slice has escaped this preparation yet. Ranges survive the
            // resize, and already authenticated bytes need not be compacted.
            self.wire
                .resize((self.wire.len() * 2).clamp(4096, MAX_BATCH_WIRE), 0);
        }
        loop {
            let available = self.wire.len() - self.tail;
            match self.inner.read(&mut self.wire[self.tail..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS peer closed without close_notify",
                    ))
                }
                Ok(n) => {
                    self.tail += n;
                    self.grow_read = n == available;
                    return Ok(true);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn decode_tls13_record(&mut self, compact: bool) -> io::Result<bool> {
        if self.needs_write() {
            if !self.plaintext.is_empty() {
                return Ok(true);
            }
            self.control.flush(&self.core)?;
        }
        let needed = self.next_record_len()?;
        if self.tail - self.head < needed {
            return Ok(false);
        }
        let start = self.head;
        let end = start + needed;
        let rx = self.rx.as_mut().expect("TLS 1.3 receiver");
        let encrypted = start + 5;
        let header = self.wire[start..encrypted]
            .try_into()
            .expect("complete record header");
        let dest = if compact {
            self.plaintext.back().map_or(encrypted, |range| range.end)
        } else {
            encrypted
        };
        let (kind, len) = rx.open_within(header, &mut self.wire[dest..end], encrypted - dest)?;
        self.head = end;
        if kind == 23 {
            if len != 0 {
                self.plaintext.push_back(dest..dest + len);
            }
        } else {
            let messages = rx.control(kind, &self.wire[dest..dest + len])?;
            self.process_messages(messages)?;
        }
        Ok(true)
    }

    pub(super) fn next_record_len(&self) -> io::Result<usize> {
        let needed = if self.tail - self.head < 5 {
            5
        } else {
            5 + u16::from_be_bytes([self.wire[self.head + 3], self.wire[self.head + 4]]) as usize
        };
        if needed > MAX_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS record too large",
            ));
        }
        Ok(needed)
    }
}
