use std::collections::VecDeque;
use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;

use super::udp_batch::{ReceiveBatch, SendBatch};
use super::{
    check_tun_mtu, deliver_via, unmapped, TunBinding, TunCarrier, MAX_IP_PACKET, POLL, QUEUE,
};
use crate::linux_link::{LinkState, Monitor};
use crate::{uapi, Hub};

const BURST: usize = 32;

pub(crate) fn run(
    name: &str,
    mtu: u16,
    mut hub: Hub,
    carrier: TunCarrier,
    up: bool,
    managed: bool,
    ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    check_tun_mtu(&hub, usize::from(mtu))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut config = tun::Configuration::default();
        config.tun_name(name).mtu(mtu);
        if up {
            config.up();
        }
        let tun = tun::create(&config).map_err(io::Error::other)?;
        tun.set_nonblock()?;
        let monitor = Monitor::open(name)?;
        let (updates, state) = mpsc::channel();
        hub.update_mtu(monitor.initial.mtu);
        let binding = TunBinding::new(carrier, monitor.initial.up)?;
        let (requests, control) = if managed {
            let (requests, control) = uapi::open(name)?;
            (Some(requests), Some(control))
        } else {
            (None, None)
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let (finish, done) = tokio::sync::oneshot::channel();
        let worker = thread::Builder::new()
            .name("kerlico-wg-io".into())
            .spawn(move || {
                let _ = finish.send(drive(tun, binding, hub, state, requests, &stop));
            })?;
        let result = match ready() {
            Err(error) => Err(error),
            Ok(()) => tokio::select! {
                biased;
                result = done => result.unwrap_or_else(|_| Err(io::ErrorKind::BrokenPipe.into())),
                result = crate::tun_device::stop_signal() => result,
                result = monitor.watch(updates) => result,
                result = async {
                    match control {
                        Some(control) => control.await,
                        None => std::future::pending().await,
                    }
                } => result,
            },
        };
        stopped.store(true, Ordering::Release);
        let joined = worker
            .join()
            .map_err(|_| io::Error::other("WireGuard data thread panicked"));
        result.and(joined)
    })
}

fn drive(
    tun: tun::Device,
    mut binding: TunBinding,
    mut hub: Hub,
    state: Receiver<LinkState>,
    requests: Option<Receiver<uapi::Request>>,
    stopped: &AtomicBool,
) -> io::Result<()> {
    let (dual, reserved) = (binding.carrier.dual, binding.carrier.reserved);
    let mut receive = ReceiveBatch::new();
    let mut inner = vec![0; MAX_IP_PACKET];
    let mut batches = SendBatch::default();
    let mut to_tun = VecDeque::new();
    while !stopped.load(Ordering::Acquire) {
        for link in state.try_iter().take(BURST) {
            hub.update_mtu(link.mtu);
            if binding.up == link.up {
                continue;
            }
            binding.up = link.up;
            if link.up {
                match binding
                    .carrier
                    .open(binding.port, binding.mark)
                    .and_then(|socket| Ok((socket.local_addr()?.port(), socket)))
                {
                    Ok((port, socket)) => {
                        binding.port = port;
                        binding.socket = Some(socket);
                        hub.reset_transport();
                    }
                    // Keep UAPI available to free or change the saved port.
                    Err(error) => eprintln!("WireGuard: bring up UDP carrier: {error}"),
                }
            } else {
                binding.socket = None;
                binding.carrier.first = None;
                hub.reset_transport();
                to_tun.clear();
                for _ in 0..QUEUE {
                    if !matches!(tun.recv(&mut inner), Ok(1..)) {
                        break;
                    }
                }
            }
        }
        if let Some(requests) = &requests {
            for request in requests.try_iter().take(4) {
                binding.control(&mut hub, request);
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: if binding.up { tun.as_raw_fd() } else { -1 },
                events: libc::POLLIN | if to_tun.is_empty() { 0 } else { libc::POLLOUT },
                revents: 0,
            },
            libc::pollfd {
                fd: binding.socket.as_ref().map_or(-1, UdpSocket::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Both descriptors are owned by this thread for the entire call.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, POLL.as_millis() as _) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if stopped.load(Ordering::Acquire) {
            break;
        }
        if fds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if fds[0].revents & libc::POLLHUP != 0 {
            return Ok(());
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLIN) == libc::POLLERR {
            // Let the monitor report a concurrent link-down before trying again.
            thread::sleep(POLL);
        }
        let socket = binding.socket.as_ref();
        if fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..BURST {
                match tun.recv(&mut inner) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        if let Some((socket, event)) = socket
                            .and_then(|socket| hub.send(&inner[..n]).map(|event| (socket, event)))
                        {
                            deliver_via(
                                dual,
                                reserved,
                                event,
                                |peer, datagram| batches.push(socket, peer, datagram),
                                |_| {},
                            );
                        }
                    }
                    Err(error) if changed_interface(&error) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            if let Some(socket) = socket {
                batches.flush(socket);
            }
        }
        if let Some(socket) = socket {
            let mut emit = |event| {
                deliver_via(
                    dual,
                    reserved,
                    event,
                    |peer, datagram| {
                        let _ = socket.send_to(&datagram, peer);
                    },
                    |packet| {
                        if to_tun.len() < QUEUE {
                            to_tun.push_back(packet);
                        }
                    },
                )
            };
            if fds[1].revents & (libc::POLLIN | libc::POLLERR) != 0 {
                receive.drain(socket, BURST, |from, packet| {
                    reserved.apply(packet, true);
                    hub.receive(unmapped(from, dual), packet, &mut emit);
                })?;
            }
            hub.tick(emit);
        }
        for _ in 0..BURST {
            let Some(packet) = to_tun.front() else {
                break;
            };
            match tun.send(packet) {
                Ok(n) if n == packet.len() => {
                    to_tun.pop_front();
                }
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if changed_interface(&error) => break,
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn changed_interface(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || matches!(error.raw_os_error(), Some(libc::ENETDOWN | libc::EIO))
}
