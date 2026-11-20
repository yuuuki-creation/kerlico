mod input;
mod multishot;
use std::collections::VecDeque;
use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::task::Poll;

use bytes::BytesMut;
use futures_util::Sink;
use tokio::io::unix::AsyncFd;
use tun_rs::async_framed::{DeviceFramedWrite, Encoder};
use tun_rs::{AsyncDevice, DeviceBuilder};

use super::udp_batch::{ReceiveBatch, SendBatch};
use super::{
    carrier_endpoint, check_tun_mtu, deliver_via, unmapped, TunBinding, TunCarrier, POLL, QUEUE,
};
use crate::linux_link::{LinkState, Monitor};
use crate::{hub::HubEventRef, uapi, Hub};

const BURST: usize = 64;
const EGRESS_SEND_BUDGET: usize = 256;

// DeviceFramedWrite appends to its own GRO arena before start_send returns.
struct TunPayload;
impl Encoder<&[u8]> for TunPayload {
    type Error = io::Error;
    fn encode(&mut self, packet: &[u8], storage: &mut BytesMut) -> io::Result<()> {
        storage.extend_from_slice(packet);
        Ok(())
    }
}

fn deliver_packet(
    packet: &[u8],
    queue: &mut VecDeque<Vec<u8>>,
    submitted: &mut usize,
    mut try_write: impl FnMut(&[u8]) -> io::Result<bool>,
) -> io::Result<()> {
    if queue.len() + *submitted >= QUEUE {
        return Ok(());
    }
    if queue.is_empty() && try_write(packet)? {
        *submitted += 1;
    } else {
        // The hub will reuse the plaintext scratch on the next datagram.
        queue.push_back(packet.to_vec());
    }
    Ok(())
}

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
            // Older kernels simply continue delivering individual datagrams.
            let _ = super::udp_batch::enable_gro(&fd);
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
    let send_budget = if binding.carrier.egress_class.is_some() {
        EGRESS_SEND_BUDGET
    } else {
        tun_rs::IDEAL_BATCH_SIZE
    };
    let mut reader = input::Input::new();
    let mut reads = multishot::Multishot::new(tun.as_raw_fd()).ok();
    let mut mtu = hub.mtu();
    let mut writer = DeviceFramedWrite::new(tun.clone(), TunPayload);
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
                mtu = hub.mtu();
                if binding.up == link.up {
                    continue;
                }
                // Release the registered clone before changing or releasing the port.
                drop(carrier.take());
                receive.discard_pending();
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
                    if let Some(reads) = reads.as_mut() {
                        reads.discard()?;
                    }
                    reader.discard();
                    writer = DeviceFramedWrite::new(tun.clone(), TunPayload);
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
                    let previous = binding.port;
                    binding.control(&mut hub, request);
                    if binding.port != previous {
                        receive.discard_pending();
                    }
                    carrier = watch(binding.socket.as_ref())?;
                }
            }
        }

        let mut full_turn = false;
        let socket = binding.socket.as_ref();
        if binding.up && !retry_tun {
            // Service one bounded TUN batch before flushing the UDP trains.
            // No packet is held when the TUN reader first returns Pending.
            for i in 0..send_budget {
                match reader.poll_slot(cx, &tun, &mut reads, &mut batches, mtu) {
                    Poll::Ready(Ok(Some(slot))) => {
                        if let Some(socket) = socket {
                            batches.encode_prepared(socket, slot.start, slot.stride, |storage| {
                                hub.send_prepared(storage, slot.ip_len, |peer, frame| {
                                    reserved.apply(frame, false);
                                    (carrier_endpoint(peer, dual), frame.len())
                                })
                            });
                        }
                        full_turn |= i + 1 == send_budget;
                    }
                    Poll::Pending => break,
                    Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) if changed_interface(&error) => {
                        retry_tun = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                }
            }
            if let Some(socket) = socket {
                batches.flush(socket);
            }
        }
        if let Some(registered) = carrier.as_ref() {
            let socket = registered.get_ref();
            let mut n = 0;
            while n < BURST {
                let ready = if receive.has_pending() {
                    None
                } else {
                    match registered.poll_read_ready(cx) {
                        Poll::Pending => break,
                        Poll::Ready(result) => Some(result?),
                    }
                };
                let mut tun_error = None;
                let mut read = || {
                    receive.read(socket, BURST - n, |from, packet| {
                        reserved.apply(packet, true);
                        hub.receive_mut(unmapped(from, dual), packet, |event| match event {
                            HubEventRef::Datagram(endpoint, wire) => {
                                reserved.apply(wire, false);
                                let _ = socket.send_to(wire, carrier_endpoint(endpoint, dual));
                            }
                            HubEventRef::Packet(_, _, ip) if tun_error.is_none() => {
                                if let Err(error) =
                                    deliver_packet(ip, &mut queue, &mut submitted, |bytes| {
                                        if retry_tun {
                                            return Ok(false);
                                        }
                                        match Sink::<&[u8]>::poll_ready(Pin::new(&mut writer), cx) {
                                            Poll::Pending => Ok(false),
                                            Poll::Ready(Err(e)) if changed_interface(&e) => {
                                                retry_tun = true;
                                                Ok(false)
                                            }
                                            Poll::Ready(status) => {
                                                status?;
                                                Pin::new(&mut writer).start_send(bytes)?;
                                                Ok(true)
                                            }
                                        }
                                    })
                                {
                                    tun_error = Some(error);
                                }
                            }
                            HubEventRef::Packet(..) => {}
                        });
                    })
                };
                let result = match ready {
                    Some(mut ready) => ready.try_io(|_| read()),
                    None => Ok(read()),
                };
                if let Some(error) = tun_error {
                    return Poll::Ready(Err(error));
                }
                match result {
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
                hub.tick(|event| {
                    deliver_via(
                        dual,
                        reserved,
                        event,
                        |peer, wire| {
                            let _ = socket.send_to(&wire, peer);
                        },
                        |ip| {
                            if queue.len() + submitted < QUEUE {
                                queue.push_back(ip);
                            }
                        },
                    )
                });
            }
        }

        if binding.up && !retry_tun {
            for _ in 0..BURST {
                if queue.is_empty() {
                    break;
                }
                match Sink::<&[u8]>::poll_ready(Pin::new(&mut writer), cx) {
                    Poll::Pending => break,
                    Poll::Ready(Err(e)) if changed_interface(&e) => {
                        retry_tun = true;
                        break;
                    }
                    Poll::Ready(result) => result?,
                }
                Pin::new(&mut writer).start_send(&queue.pop_front().unwrap())?;
                submitted += 1;
            }
            if submitted != 0 {
                match Sink::<&[u8]>::poll_flush(Pin::new(&mut writer), cx) {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backpressure_preserves_borrowed_bytes_and_queue_order() -> io::Result<()> {
        let mut queue = VecDeque::new();
        let mut submitted = 0;
        let mut frame = [1u8; 160];
        deliver_packet(&frame, &mut queue, &mut submitted, |_| Ok(true))?;
        assert!(queue.is_empty());
        assert_eq!(submitted, 1);
        frame.fill(2);
        deliver_packet(&frame, &mut queue, &mut submitted, |_| Ok(false))?;
        frame.fill(3);
        deliver_packet(&frame, &mut queue, &mut submitted, |_| {
            panic!("queued packet overtaken")
        })?;
        frame.fill(4);
        assert_eq!(queue.pop_front().unwrap(), [2; 160]);
        assert_eq!(queue.pop_front().unwrap(), [3; 160]);
        submitted = QUEUE;
        deliver_packet(&frame, &mut queue, &mut submitted, |_| {
            panic!("over budget")
        })?;
        assert!(queue.is_empty());
        Ok(())
    }
}
