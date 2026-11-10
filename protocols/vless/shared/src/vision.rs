//! XTLS Vision padding. The block layout matches Xray `XtlsPadding` / `XtlsUnpadding`.

const CONTINUE: u8 = 0x00;
const END: u8 = 0x01;
const DIRECT: u8 = 0x02;
const MAX_CONTENT: usize = 8192 - 21;
const TLS13: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// One direction pair. `seal` pads outbound bytes. `push`/`pop` recover inbound bytes.
pub struct Vision {
    id: [u8; 16],
    packets_left: i32,
    is_tls: bool,
    is_tls12: bool,
    enable_xtls: bool,
    remaining_hello: i32,
    cipher: u16,
    uuid_left: bool,
    padding: bool,
    inbox: Vec<u8>,
    cursor: usize,
    plain: Vec<u8>,
    direct_in: bool,
    switch_read: bool,
    switch_write: bool,
    rem_cmd: i32,
    rem_content: i32,
    rem_pad: i32,
    current: i32,
}

impl Vision {
    pub fn new(id: [u8; 16]) -> Self {
        Self {
            id,
            packets_left: 8,
            is_tls: false,
            is_tls12: false,
            enable_xtls: false,
            remaining_hello: -1,
            cipher: 0,
            uuid_left: true,
            padding: true,
            inbox: Vec::new(),
            cursor: 0,
            plain: Vec::new(),
            direct_in: false,
            switch_read: false,
            switch_write: false,
            rem_cmd: -1,
            rem_content: -1,
            rem_pad: -1,
            current: 0,
        }
    }

    pub fn inbound_direct(&self) -> bool {
        self.direct_in
    }

    pub fn outbound_direct(&self) -> bool {
        !self.padding
    }

    pub fn take_read_switch(&mut self) -> bool { std::mem::take(&mut self.switch_read) }
    pub fn take_write_switch(&mut self) -> bool { std::mem::take(&mut self.switch_write) }

    pub fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        if !self.padding {
            return plain.to_vec();
        }
        if plain.is_empty() {
            let mut out = Vec::new();
            self.emit(&mut out, &[], CONTINUE);
            return out;
        }
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < plain.len() {
            let end = (offset + MAX_CONTENT).min(plain.len());
            chunks.push(&plain[offset..end]);
            offset = end;
        }
        for chunk in &chunks {
            if !self.filter(chunk) {
                break;
            }
        }
        let mut out = Vec::new();
        let whole_command = self.command(plain);
        for (index, chunk) in chunks.iter().enumerate() {
            let command = if whole_command == DIRECT {
                if index + 1 == chunks.len() { DIRECT } else { CONTINUE }
            } else { self.command(chunk) };
            self.emit(&mut out, chunk, command);
            if command != CONTINUE {
                self.padding = false;
                self.switch_write = command == DIRECT;
                for rest in chunks.iter().skip(index + 1) {
                    out.extend_from_slice(rest);
                }
                break;
            }
        }
        out
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.inbox.extend_from_slice(bytes);
        self.pump();
    }

    pub fn pop(&mut self, buf: &mut [u8]) -> usize {
        let n = self.plain.len().min(buf.len());
        buf[..n].copy_from_slice(&self.plain[..n]);
        self.plain.drain(..n);
        n
    }

    fn command(&self, chunk: &[u8]) -> u8 {
        let app = chunk.len() >= 6 && chunk.starts_with(&[0x17, 0x03, 0x03]) && complete_record(chunk);
        if self.is_tls && app {
            if self.enable_xtls { DIRECT } else { END }
        } else if !self.is_tls12 && self.packets_left <= 1 {
            END
        } else {
            CONTINUE
        }
    }

    fn emit(&mut self, out: &mut Vec<u8>, content: &[u8], command: u8) {
        if self.uuid_left {
            out.extend_from_slice(&self.id);
            self.uuid_left = false;
        }
        let pad = padding_len(content.len(), self.is_tls);
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(pad as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + pad, 0);
    }

    fn filter(&mut self, buf: &[u8]) -> bool {
        if self.packets_left <= 0 {
            return false;
        }
        self.packets_left -= 1;
        if buf.len() >= 6 {
            if buf.starts_with(&[0x16, 0x03, 0x03]) && buf[5] == 0x02 {
                let record = u16::from_be_bytes([buf[3], buf[4]]) as i32 + 5;
                self.remaining_hello = record;
                self.is_tls12 = true;
                self.is_tls = true;
                if buf.len() >= 79 && record >= 79 {
                    let at = 43 + buf[43] as usize + 1;
                    if at + 2 <= buf.len() {
                        self.cipher = u16::from_be_bytes([buf[at], buf[at + 1]]);
                    }
                }
            } else if buf.starts_with(&[0x16, 0x03]) && buf[5] == 0x01 {
                self.is_tls = true;
            }
        }
        if self.remaining_hello > 0 {
            let end = (self.remaining_hello as usize).min(buf.len());
            self.remaining_hello -= buf.len() as i32;
            if buf[..end].windows(TLS13.len()).any(|window| window == TLS13) {
                if matches!(self.cipher, 0x1301..=0x1304) {
                    self.enable_xtls = true;
                }
                self.packets_left = 0;
                return false;
            }
            if self.remaining_hello <= 0 {
                self.packets_left = 0;
                return false;
            }
        }
        true
    }

    fn pump(&mut self) {
        if self.direct_in {
            let rest = self.rest().to_vec();
            self.consume_all();
            self.plain.extend_from_slice(&rest);
            return;
        }
        loop {
            if self.rem_cmd < 0 && self.rem_content < 0 && self.rem_pad < 0 {
                if self.rest().len() < 21 {
                    return;
                }
                if self.rest()[..16] == self.id {
                    self.advance(16);
                    self.rem_cmd = 5;
                } else {
                    let rest = self.rest().to_vec();
                    self.consume_all();
                    self.plain.extend_from_slice(&rest);
                    return;
                }
            }
            if self.rem_cmd > 0 {
                if self.rest().is_empty() {
                    return;
                }
                let byte = self.rest()[0];
                self.advance(1);
                match self.rem_cmd {
                    5 => self.current = byte as i32,
                    4 => self.rem_content = (byte as i32) << 8,
                    3 => self.rem_content |= byte as i32,
                    2 => self.rem_pad = (byte as i32) << 8,
                    1 => self.rem_pad |= byte as i32,
                    _ => {}
                }
                self.rem_cmd -= 1;
                continue;
            }
            if self.rem_content > 0 {
                let n = self.rest().len().min(self.rem_content as usize);
                if n == 0 {
                    return;
                }
                let bytes = self.rest()[..n].to_vec();
                self.advance(n);
                self.filter(&bytes);
                self.plain.extend_from_slice(&bytes);
                self.rem_content -= n as i32;
                continue;
            }
            if self.rem_pad > 0 {
                let n = self.rest().len().min(self.rem_pad as usize);
                if n == 0 {
                    return;
                }
                self.advance(n);
                self.rem_pad -= n as i32;
                continue;
            }
            if self.current == 0 {
                self.rem_cmd = 5;
                continue;
            }
            self.rem_cmd = -1;
            self.rem_content = -1;
            self.rem_pad = -1;
            self.direct_in = true;
            self.switch_read = self.current == DIRECT as i32;
            let rest = self.rest().to_vec();
            self.consume_all();
            self.plain.extend_from_slice(&rest);
            return;
        }
    }

    fn rest(&self) -> &[u8] {
        &self.inbox[self.cursor..]
    }

    fn advance(&mut self, n: usize) {
        self.cursor += n;
        if self.cursor >= 8192 {
            self.inbox.drain(..self.cursor);
            self.cursor = 0;
        }
    }

    fn consume_all(&mut self) {
        self.inbox.clear();
        self.cursor = 0;
    }
}

pub trait VisionTransport: std::io::Read + std::io::Write {
    fn read_direct(&mut self) -> std::io::Result<()>;
    fn write_direct(&mut self) -> std::io::Result<()>;
}

pub struct VisionIo<T> {
    inner: T,
    state: std::sync::Arc<std::sync::Mutex<Vision>>,
    unsent: Vec<u8>,
    accepted: Option<usize>,
    switch: bool,
}

pub fn vision_pair<T: VisionTransport>(read: T, write: T, id: [u8; 16], prefix: &[u8]) -> std::io::Result<(VisionIo<T>, VisionIo<T>)> {
    let mut state = Vision::new(id);
    state.push(prefix);
    let mut read = read;
    if state.take_read_switch() { read.read_direct()?; }
    let state = std::sync::Arc::new(std::sync::Mutex::new(state));
    Ok((
        VisionIo { inner: read, state: state.clone(), unsent: Vec::new(), accepted: None, switch: false },
        VisionIo { inner: write, state, unsent: Vec::new(), accepted: None, switch: false },
    ))
}

impl<T> VisionIo<T> {
    pub fn inner_mut(&mut self) -> &mut T { &mut self.inner }
}

impl<T: VisionTransport> std::io::Read for VisionIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            let (n, finished) = {
                let mut state = self.state.lock().expect("vision");
                (state.pop(buf), state.inbound_direct())
            };
            if n > 0 { return Ok(n); }
            if finished { return self.inner.read(buf); }
            let mut bytes = [0; 8192];
            let n = self.inner.read(&mut bytes)?;
            if n == 0 { return Ok(0); }
            let switch = {
                let mut state = self.state.lock().expect("vision");
                state.push(&bytes[..n]);
                state.take_read_switch()
            };
            if switch { self.inner.read_direct()?; }
        }
    }
}

impl<T: VisionTransport> std::io::Write for VisionIo<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.accepted.is_none() {
            let mut state = self.state.lock().expect("vision");
            if state.outbound_direct() { drop(state); return self.inner.write(buf); }
            let size = buf.len().min(1024 * 1024);
            self.unsent = state.seal(&buf[..size]);
            self.switch = state.take_write_switch();
            self.accepted = Some(size);
        }
        self.flush()?;
        Ok(self.accepted.take().unwrap_or(0))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        while !self.unsent.is_empty() {
            let n = self.inner.write(&self.unsent)?;
            if n == 0 { return Err(std::io::ErrorKind::WriteZero.into()); }
            self.unsent.drain(..n);
        }
        self.inner.flush()?;
        if self.switch {
            self.inner.write_direct()?;
            self.switch = false;
        }
        Ok(())
    }
}

fn padding_len(content: usize, long: bool) -> usize {
    let raw = if content < 900 && long {
        random_below(500) + 900 - content
    } else {
        random_below(256)
    };
    let room = MAX_CONTENT.saturating_sub(content);
    raw.min(room)
}

fn random_below(max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    let mut bytes = [0u8; 4];
    let _ = getrandom::getrandom(&mut bytes);
    u32::from_le_bytes(bytes) as usize % max
}

fn complete_record(bytes: &[u8]) -> bool {
    let mut header = 5;
    let mut record = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        if header > 0 {
            let data = bytes[index];
            index += 1;
            match header {
                5 if data != 0x17 => return false,
                4 | 3 if data != 0x03 => return false,
                2 => record = (data as usize) << 8,
                1 => record |= data as usize,
                _ => {}
            }
            header -= 1;
        } else if record > 0 {
            if bytes.len() - index < record {
                return false;
            }
            index += record;
            record = 0;
            header = 5;
        } else {
            return false;
        }
    }
    header == 5 && record == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pull(vision: &mut Vision) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = vision.pop(&mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[test]
    fn padding_roundtrip_then_direct() {
        let id = [0xab; 16];
        let mut writer = Vision::new(id);
        let mut reader = Vision::new(id);
        for index in 0..8u8 {
            let plain = vec![index; 20];
            let sealed = writer.seal(&plain);
            if index == 0 {
                assert_eq!(&sealed[..16], &id);
            }
            for byte in &sealed {
                reader.push(&[*byte]);
            }
            assert_eq!(pull(&mut reader), plain);
        }
        let tail = writer.seal(b"raw-tail");
        assert_eq!(tail, b"raw-tail");
        reader.push(&tail);
        assert_eq!(pull(&mut reader), b"raw-tail");
    }

    #[test]
    fn tls13_application_data_switches_to_direct() {
        let id = [0x11; 16];
        let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x4a, 0x02];
        hello.resize(79, 0);
        hello[43] = 0;
        hello[44] = 0x13;
        hello[45] = 0x01;
        hello[60..66].copy_from_slice(&TLS13);
        let mut writer = Vision::new(id);
        let mut reader = Vision::new(id);
        reader.push(&writer.seal(&hello));
        assert_eq!(pull(&mut reader), hello);
        let mut app = vec![0x17, 0x03, 0x03, 0x00, 0x03, 1, 2, 3];
        assert!(complete_record(&app));
        let sealed = writer.seal(&app);
        assert_eq!(sealed[0], DIRECT);
        reader.push(&sealed);
        assert_eq!(pull(&mut reader), app);
        let after = writer.seal(b"spliced");
        assert_eq!(after, b"spliced");
        reader.push(&after);
        assert_eq!(pull(&mut reader), b"spliced");
        app.clear();
    }

    #[test]
    fn large_tls_record_switches_only_after_the_last_padded_block() {
        let id = [0x31; 16];
        let mut writer = Vision::new(id);
        let mut reader = Vision::new(id);
        let mut hello = vec![0x16, 3, 3, 0, 74, 2];
        hello.resize(79, 0);
        hello[44..46].copy_from_slice(&[0x13, 1]);
        hello[60..66].copy_from_slice(&TLS13);
        reader.push(&writer.seal(&hello));
        assert_eq!(pull(&mut reader), hello);
        let mut record = vec![0x17, 3, 3, 0x40, 0];
        record.resize(16389, 42);
        let padded = writer.seal(&record);
        let mut cursor = 0;
        let mut commands = Vec::new();
        while cursor < padded.len() {
            commands.push(padded[cursor]);
            let content = u16::from_be_bytes([padded[cursor + 1], padded[cursor + 2]]) as usize;
            let padding = u16::from_be_bytes([padded[cursor + 3], padded[cursor + 4]]) as usize;
            cursor += 5 + content + padding;
        }
        assert!(commands.len() > 1);
        assert!(commands[..commands.len() - 1].iter().all(|command| *command == CONTINUE));
        assert_eq!(commands.last(), Some(&DIRECT));
        assert!(writer.take_write_switch());
        reader.push(&padded);
        assert!(reader.take_read_switch());
        assert_eq!(pull(&mut reader), record);
    }
}
