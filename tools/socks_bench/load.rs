use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

mod udp;

const STREAMS: usize = 8;
// Split each paced tick over all streams, retaining remainder bytes.
fn block_size(index: usize) -> usize {
    let mbps: usize = env::var("KERLICO_BENCH_MBPS")
        .map_or(500, |s| s.parse().expect("integer Mbps"));
    assert!((1..=10_000).contains(&mbps));
    let hz = tick_hz() as usize;
    assert_eq!(mbps * 125_000 % hz, 0, "benchmark rate must give an integral number of bytes per tick");
    let per_tick = mbps * 125_000 / hz;
    assert!(per_tick / STREAMS >= 16, "block must fit its sequence and timestamp");
    per_tick / STREAMS + usize::from(index < per_tick % STREAMS)
}

fn tick_hz() -> u64 {
    let hz = env::var("KERLICO_BENCH_TICK_HZ")
        .map_or(100, |v| v.parse().expect("integer TCP ticks per second"));
    assert!(hz > 0 && hz <= 1000 && 1_000_000_000 % hz == 0);
    hz
}

#[repr(C)]
struct Timespec {
    sec: i64,
    nanos: i64,
}

extern "C" {
    fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
}

fn now() -> u64 {
    let mut time = Timespec { sec: 0, nanos: 0 };
    assert_eq!(unsafe { clock_gettime(1, &mut time) }, 0);
    (time.sec as u64) * 1_000_000_000 + (time.nanos as u64)
}

fn pattern(index: usize) -> Vec<u8> {
    let mut state = index as u32 + 1;
    (0..block_size(index))
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn io_timeout() -> Duration {
    let millis = env::var("KERLICO_BENCH_IO_TIMEOUT_MS")
        .map_or(2000, |v| v.parse().expect("positive socket timeout in milliseconds"));
    assert!(millis > 0);
    Duration::from_millis(millis)
}

fn listen(address: &str) -> io::Result<Vec<(TcpStream, Vec<u8>)>> {
    let listener = TcpListener::bind(address)?;
    println!("listening");
    let mut streams = Vec::with_capacity(STREAMS);
    for _ in 0..STREAMS {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(io_timeout()))?;
        stream.set_write_timeout(Some(io_timeout()))?;
        stream.set_nodelay(true)?;
        let mut id = [0];
        stream.read_exact(&mut id)?;
        let index = usize::from(id[0]);
        if index >= STREAMS || streams.iter().any(|(known, _)| *known == index) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TCP flow id",
            ));
        }
        streams.push((index, stream));
    }
    streams.sort_unstable_by_key(|(index, _)| *index);
    Ok(streams
        .into_iter()
        .map(|(index, stream)| (stream, pattern(index)))
        .collect())
}

fn proxy(address: &str, target: &str) -> io::Result<Vec<(TcpStream, Vec<u8>)>> {
    let mut streams = Vec::with_capacity(STREAMS);
    for index in 0..STREAMS {
        let mut stream = TcpStream::connect(address)?;
        let target: std::net::SocketAddrV4 = target.parse().unwrap();
        let mut method = [0; 2];
        stream.write_all(&[5, 1, 0])?;
        stream.read_exact(&mut method)?;
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1];
        request.extend(target.ip().octets());
        request.extend(target.port().to_be_bytes());
        stream.write_all(&request)?;
        let mut header = [0; 4];
        stream.read_exact(&mut header)?;
        assert_eq!(&header[..3], &[5, 0, 0]);
        let address_len = match header[3] {
            1 => 4,
            4 => 16,
            kind => panic!("unexpected reply address type {kind}"),
        };
        stream.read_exact(&mut [0; 18][..address_len + 2])?;
        stream.set_read_timeout(Some(io_timeout()))?;
        stream.set_write_timeout(Some(io_timeout()))?;
        stream.set_nodelay(true)?;
        // A SOCKS server can acknowledge the request before the origin
        // accepts it. Identify the flows explicitly before measuring.
        stream.write_all(&[index as u8])?;
        streams.push((stream, pattern(index)));
    }
    Ok(streams)
}

fn wait_until(deadline: u64) {
    loop {
        let remaining = deadline.saturating_sub(now());
        if remaining == 0 {
            return;
        }
        thread::sleep(Duration::from_nanos(remaining));
    }
}

fn latency_enabled() -> bool {
    env::var_os("KERLICO_BENCH_TIMESTAMPS").is_some()
}

fn latency_report(samples: &mut [u64]) {
    if samples.is_empty() {
        return;
    }
    samples.sort_unstable();
    let quantile = |percentage: usize| samples[(samples.len() - 1) * percentage / 100] / 1_000;
    println!("latency_us {} {} {} {} {}", samples.len(), quantile(50), quantile(95), quantile(99), quantile(100));
}

fn send(mut streams: Vec<(TcpStream, Vec<u8>)>, rounds: u64) -> io::Result<()> {
    let start = now() + 500_000_000;
    println!("start {start}");
    let timestamps = latency_enabled();
    let bytes_per_tick: usize = streams.iter().map(|(_, block)| block.len()).sum();
    let interval = 1_000_000_000 / tick_hz();
    let stagger = env::var_os("KERLICO_BENCH_STAGGER_TCP_WRITES").is_some();
    // A blocked socket must not withhold scheduled writes from unrelated flows.
    let maximum = thread::scope(|scope| -> io::Result<u64> {
        let mut writers = Vec::with_capacity(streams.len());
        for (index, (stream, block)) in streams.iter_mut().enumerate() {
            let offset = if stagger {
                interval * index as u64 / STREAMS as u64
            } else {
                0
            };
            writers.push(scope.spawn(move || -> io::Result<u64> {
                let mut late = 0;
                for tick in 0..rounds {
                    let deadline = start + tick * interval + offset;
                    wait_until(deadline);
                    block[..8].copy_from_slice(&tick.to_be_bytes());
                    if timestamps {
                        block[8..16].copy_from_slice(&now().to_be_bytes());
                    }
                    stream.write_all(block)?;
                    late = late.max(now().saturating_sub(deadline));
                }
                Ok(late)
            }));
        }
        let mut maximum = 0;
        for writer in writers {
            maximum = maximum.max(writer.join().expect("TCP flow writer")?);
        }
        Ok(maximum)
    })?;
    println!("sent {} {maximum}", rounds * bytes_per_tick as u64);
    // A successful write can leave bytes in either proxy. Keep every stream
    // open until the receiver has verified the entire run.
    for (stream, _) in &mut streams {
        let mut receipt = [0; 8];
        stream.read_exact(&mut receipt)?;
        if u64::from_be_bytes(receipt) != rounds {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid delivery receipt"));
        }
    }
    Ok(())
}

fn receive(mut streams: Vec<(TcpStream, Vec<u8>)>, warmup: u64, rounds: u64) -> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    let bytes_per_tick: usize = streams.iter().map(|(_, block)| block.len()).sum();
    let timestamps = latency_enabled();
    let warmed = AtomicUsize::new(0);
    let progress = env::var_os("KERLICO_BENCH_PROGRESS")
        .map(std::fs::File::create)
        .transpose()?
        .map(|file| Mutex::new(io::BufWriter::new(file)));
    // Loss on one proxied TCP stream must not stop the application reading
    // the other seven. All readers inherit the receiver's CPU affinity.
    let (finished, mut delays) = thread::scope(|scope| -> io::Result<_> {
        let mut readers = Vec::new();
        for (stream, expected) in &mut streams {
            let progress = &progress;
            let warmed = &warmed;
            readers.push(scope.spawn(move || -> io::Result<_> {
                let mut buffer = vec![0; expected.len()];
                let mut delays = Vec::new();
                for tick in 0..rounds {
                    stream.read_exact(&mut buffer)?;
                    expected[..8].copy_from_slice(&tick.to_be_bytes());
                    if timestamps {
                        let sent_at = u64::from_be_bytes(buffer[8..16].try_into().unwrap());
                        let delay = now().checked_sub(sent_at)
                            .ok_or_else(|| io::Error::other("invalid send clock"))?;
                        expected[8..16].copy_from_slice(&sent_at.to_be_bytes());
                        if tick >= warmup { delays.push(delay); }
                    }
                    if buffer != *expected {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "payload mismatch"));
                    }
                    if let Some(log) = progress {
                        let mut log = log.lock().expect("delivery progress");
                        log.write_all(&now().to_le_bytes())?;
                        log.write_all(&(expected.len() as u64).to_le_bytes())?;
                        log.flush()?;
                    }
                    if tick + 1 == warmup && warmed.fetch_add(1, Ordering::Relaxed) + 1 == STREAMS {
                        println!("warmed {}", now());
                    }
                }
                let finished = now();
                stream.write_all(&rounds.to_be_bytes())?;
                Ok((finished, delays))
            }));
        }
        let mut finish = 0;
        let mut delays = Vec::new();
        for reader in readers {
            let (stream_end, mut samples) = reader.join().expect("TCP flow reader")?;
            finish = finish.max(stream_end);
            delays.append(&mut samples);
        }
        Ok((finish, delays))
    })?;
    latency_report(&mut delays);
    println!("received {} {}", (rounds - warmup) * bytes_per_tick as u64, finished);
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args().collect();
    match args[1].as_str() {
        "udp-echo" => return udp::echo(&args[2], args[3].parse().unwrap()),
        "udp-roundtrip" => {
            return udp::roundtrip(
                &args[2],
                &args[5],
                args[3].parse().unwrap(),
                args[4].parse().unwrap(),
                args[6].parse().unwrap(),
                args[7].parse().unwrap(),
            )
        }
        _ => {}
    }
    let hz = tick_hz();
    let warmup = args[3].parse::<u64>().unwrap() * hz;
    let rounds = warmup + args[4].parse::<u64>().unwrap() * hz;
    let streams = match args.get(5) {
        Some(target) => proxy(&args[2], target)?,
        None => listen(&args[2])?,
    };
    match args[1].as_str() {
        "send" => send(streams, rounds),
        "receive" => receive(streams, warmup, rounds),
        _ => panic!("send or receive"),
    }
}
