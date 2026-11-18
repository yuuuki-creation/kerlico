use std::collections::VecDeque;
use std::io;
use std::net::UdpSocket;
use std::pin::Pin;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::task::Poll;

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::unix::AsyncFd;
use tun_rs::async_framed::{BytesCodec, DeviceFramedRead, DeviceFramedWrite};
use tun_rs::{AsyncDevice, DeviceBuilder};

use super::udp_batch::{ReceiveBatch, SendBatch};
use super::{
    carrier_endpoint, check_tun_mtu, deliver_via, unmapped, TunBinding, TunCarrier, POLL, QUEUE,
};
use crate::linux_link::{LinkState, Monitor};
use crate::{uapi, Hub};

const BURST: usize = 64;

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
        let create = |offload| {
            let config = DeviceBuilder::new().name(name).mtu(mtu).offload(offload);
            if up {
                config.enable(true)
            } else {
                config.inherit_enable_state()
            }
            .build_async()
        };
        let tun = match create(true) {
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOTTY | libc::EOPNOTSUPP)
                ) =>
            {
                create(false)?
            }
            result => result?,
        };
        let tun = Arc::new(tun);
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
        ready()?;
        tokio::select! {
            result = drive(tun, binding, hub, state, requests) => result,
            result = crate::tun_device::stop_signal() => result,
            result = monitor.watch(updates) => result,
            result = async {
                match control {
                    Some(control) => control.await,
                    None => std::future::pending().await,
                }
            } => result,
        }
    })
}

fn watch(socket: Option<&UdpSocket>) -> io::Result<Option<AsyncFd<UdpSocket>>> {
    socket
        .map(|socket| {
            let fd = socket.try_clone()?;
            // SAFETY: the registration owns this descriptor. It is not closed
            // or registered elsewhere while AsyncFd is live.
            Ok(unsafe { AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE)? })
        })
        .transpose()
}

async fn drive(
    tun: Arc<AsyncDevice>,
    mut binding: TunBinding,
    mut hub: Hub,
    state: Receiver<LinkState>,
    requests: Option<Receiver<uapi::Request>>,
) -> io::Result<()> {
    let (dual, reserved) = (binding.carrier.dual, binding.carrier.reserved);
    let mut reader = DeviceFramedRead::new(tun.clone(), BytesCodec::new());
    let mut writer = DeviceFramedWrite::new(tun.clone(), BytesCodec::new());
    let mut carrier = watch(binding.socket.as_ref())?;
    let mut receive = ReceiveBatch::new();
    let mut batches = SendBatch::default();
    let mut queue = VecDeque::new();
    let mut submitted = 0;
    let mut retry_tun = false;
    let mut timer = tokio::time::interval(POLL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    std::future::poll_fn(move |cx| {
        let maintenance = timer.poll_tick(cx).is_ready();
        if maintenance {
            retry_tun = false;
            for link in state.try_iter().take(BURST) {
                hub.update_mtu(link.mtu);
                reader.set_read_buffer_size(link.mtu.saturating_add(tun_rs::VIRTIO_NET_HDR_LEN));
                if binding.up == link.up {
                    continue;
                }
                // Release the registered clone before changing or releasing the port.
                drop(carrier.take());
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
                        Err(e) => eprintln!("WireGuard: bring up UDP carrier: {e}"),
                    }
                } else {
                    binding.socket = None;
                    binding.carrier.first = None;
                    hub.reset_transport();
                    queue.clear();
                    submitted = 0;
                    reader = DeviceFramedRead::new(tun.clone(), BytesCodec::new());
                    writer = DeviceFramedWrite::new(tun.clone(), BytesCodec::new());
                    let mut discarded = vec![0; u16::MAX as usize + tun_rs::VIRTIO_NET_HDR_LEN];
                    for _ in 0..QUEUE {
                        if !matches!(tun.try_recv(&mut discarded), Ok(1..)) {
                            break;
                        }
                    }
                }
                carrier = watch(binding.socket.as_ref())?;
            }
            if let Some(requests) = &requests {
                for request in requests.try_iter().take(4) {
                    drop(carrier.take());
                    binding.control(&mut hub, request);
                    carrier = watch(binding.socket.as_ref())?;
                }
            }
        }

        let mut full_turn = false;
        let socket = binding.socket.as_ref();
        if binding.up && !retry_tun {
            for i in 0..BURST {
                match Pin::new(&mut reader).poll_next(cx) {
                    Poll::Ready(Some(Ok(packet))) => {
                        if let Some(socket) = socket {
                            batches.encode(socket, |buffer, offset| {
                                hub.send_with(&packet, Some((buffer, offset)), |peer, frame| {
                                    reserved.apply(frame, false);
                                    (carrier_endpoint(peer, dual), frame.len())
                                })
                            });
                        }
                        full_turn |= i + 1 == BURST;
                    }
                    Poll::Pending => break,
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Ready(Some(Err(error))) if changed_interface(&error) => {
                        retry_tun = true;
                        break;
                    }
                    Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                }
            }
            if let Some(socket) = socket {
                batches.flush(socket);
            }
        }
        if let Some(registered) = carrier.as_ref() {
            let socket = registered.get_ref();
            let mut emit = |event| {
                deliver_via(
                    dual,
                    reserved,
                    event,
                    |peer, frame| {
                        let _ = socket.send_to(&frame, peer);
                    },
                    |packet| {
                        if queue.len() + submitted < QUEUE {
                            queue.push_back(packet);
                        }
                    },
                )
            };
            let mut n = 0;
            while n < BURST {
                let mut ready = match registered.poll_read_ready(cx) {
                    Poll::Pending => break,
                    Poll::Ready(result) => result?,
                };
                match ready.try_io(|_| {
                    receive.read(socket, BURST - n, |from, packet| {
                        reserved.apply(packet, true);
                        hub.receive(unmapped(from, dual), packet, &mut emit);
                    })
                }) {
                    // WouldBlock cleared readiness. Poll again to register the
                    // next packet's waker before returning to the executor.
                    Err(_) => continue,
                    Ok(Ok(0)) => break,
                    Ok(Ok(count)) => n += count,
                    Ok(Err(e))
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted
                                | io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        break
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            full_turn |= n == BURST;
            if maintenance {
                hub.tick(emit);
            }
        }

        if binding.up && !retry_tun {
            for _ in 0..BURST {
                if queue.is_empty() {
                    break;
                }
                match Sink::<Bytes>::poll_ready(Pin::new(&mut writer), cx) {
                    Poll::Pending => break,
                    Poll::Ready(Err(e)) if changed_interface(&e) => {
                        retry_tun = true;
                        break;
                    }
                    Poll::Ready(result) => result?,
                }
                Pin::new(&mut writer).start_send(Bytes::from(queue.pop_front().unwrap()))?;
                submitted += 1;
            }
            if submitted != 0 {
                match Sink::<Bytes>::poll_flush(Pin::new(&mut writer), cx) {
                    Poll::Ready(Ok(())) => {
                        submitted = 0;
                        full_turn |= !queue.is_empty();
                    }
                    Poll::Ready(Err(e)) if changed_interface(&e) => retry_tun = true,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }
        }
        if full_turn || maintenance {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}

fn changed_interface(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || matches!(error.raw_os_error(), Some(libc::ENETDOWN | libc::EIO))
}
