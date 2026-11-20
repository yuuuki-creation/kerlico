use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

mod udp;

const STREAMS: usize = 8;
const BLOCK: usize = 78_125;
const TICK_NS: u64 = 10_000_000;

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
    (0..BLOCK)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn listen(address: &str) -> io::Result<Vec<(TcpStream, Vec<u8>)>> {
    let listener = TcpListener::bind(address)?;
    println!("listening");
    let mut streams = Vec::with_capacity(STREAMS);
    for _ in 0..STREAMS {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
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
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
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

fn send(mut streams: Vec<(TcpStream, Vec<u8>)>, rounds: u64) -> io::Result<()> {
    let start = now() + 500_000_000;
    println!("start {start}");
    let mut maximum = 0;
    for tick in 0..rounds {
        let deadline = start + tick * TICK_NS;
        wait_until(deadline);
        for (stream, block) in &mut streams {
            block[..8].copy_from_slice(&tick.to_be_bytes());
            stream.write_all(block)?;
        }
        maximum = maximum.max(now().saturating_sub(deadline));
    }
    println!("sent {} {maximum}", rounds * (STREAMS * BLOCK) as u64);
    Ok(())
}

fn receive(mut streams: Vec<(TcpStream, Vec<u8>)>, warmup: u64, rounds: u64) -> io::Result<()> {
    let mut buffer = vec![0; BLOCK];
    for tick in 0..rounds {
        for (stream, expected) in &mut streams {
            stream.read_exact(&mut buffer)?;
            expected[..8].copy_from_slice(&tick.to_be_bytes());
            if buffer != *expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "payload mismatch",
                ));
            }
        }
        if tick + 1 == warmup {
            println!("warmed {}", now());
        }
    }
    println!(
        "received {} {}",
        (rounds - warmup) * (STREAMS * BLOCK) as u64,
        now()
    );
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args().collect();
    match args[1].as_str() {
        "udp-echo" => return udp::echo(&args[2]),
        "udp-roundtrip" => {
            return udp::roundtrip(
                &args[2],
                &args[5],
                args[3].parse().unwrap(),
                args[4].parse().unwrap(),
                args[6].parse().unwrap(),
            )
        }
        _ => {}
    }
    let warmup = args[3].parse::<u64>().unwrap() * 100;
    let rounds = warmup + args[4].parse::<u64>().unwrap() * 100;
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
