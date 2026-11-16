//! Linux TUN state notifications from the kernel's route netlink socket.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc::Sender;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

const IFLA_MTU: u16 = 4;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct LinkState {
    pub up: bool,
    pub mtu: usize,
}

pub(crate) struct Monitor {
    socket: AsyncFd<OwnedFd>,
    index: i32,
    pub initial: LinkState,
}

impl Monitor {
    pub fn open(name: &str) -> io::Result<Self> {
        let name = CString::new(name).map_err(io::Error::other)?;
        if name.as_bytes_with_nul().len() > libc::IFNAMSIZ {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Subscribe before reading the initial state, so subsequent changes are queued.
        let socket = unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let socket = OwnedFd::from_raw_fd(fd);
            let mut address: libc::sockaddr_nl = std::mem::zeroed();
            address.nl_family = libc::AF_NETLINK as _;
            address.nl_groups = libc::RTMGRP_LINK as _;
            if libc::bind(
                fd,
                (&address as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as _,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            socket
        };
        // These ioctl buffers have the Linux ifreq layout and a terminated interface name.
        let query = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        let (index, initial) = unsafe {
            let index = libc::if_nametoindex(name.as_ptr());
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut req: libc::ifreq = std::mem::zeroed();
            for (to, from) in req.ifr_name.iter_mut().zip(name.as_bytes()) {
                *to = *from as libc::c_char;
            }
            let fd = query.as_raw_fd();
            if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }
            let up = i32::from(req.ifr_ifru.ifru_flags) & libc::IFF_UP != 0;
            if libc::ioctl(fd, libc::SIOCGIFMTU, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }
            (
                index as i32,
                LinkState {
                    up,
                    mtu: req.ifr_ifru.ifru_mtu as usize,
                },
            )
        };
        // The registered descriptor is exclusively owned and is never closed or replaced.
        let socket = unsafe { AsyncFd::register_with_interest(socket, Interest::READABLE)? };
        Ok(Self {
            socket,
            index,
            initial,
        })
    }

    pub async fn watch(self, updates: Sender<LinkState>) -> io::Result<()> {
        let mut state = self.initial;
        let mut bytes = [0; 65_536];
        loop {
            let mut ready = self.socket.readable().await?;
            let read = ready.try_io(|fd| {
                // recvfrom writes only to the owned byte buffer and sockaddr of the supplied size.
                unsafe {
                    let mut source: libc::sockaddr_nl = std::mem::zeroed();
                    let mut len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
                    let count = libc::recvfrom(
                        fd.get_ref().as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        0,
                        (&mut source as *mut libc::sockaddr_nl).cast(),
                        &mut len,
                    );
                    if count < 0 {
                        Err(io::Error::last_os_error())
                    } else if source.nl_pid != 0 {
                        Ok(0)
                    } else {
                        Ok(count as usize)
                    }
                }
            });
            let Ok(read) = read else {
                continue;
            };
            let mut messages = &bytes[..read?];
            // nlmsghdr (16 bytes), ifinfomsg (16 bytes), then aligned attributes.
            while messages.len() >= 16 {
                let len = u32::from_ne_bytes(messages[..4].try_into().unwrap()) as usize;
                let Some(message) = messages.get(..len).filter(|m| m.len() >= 16) else {
                    break;
                };
                let kind = u16::from_ne_bytes(message[4..6].try_into().unwrap());
                if message.len() >= 32
                    && i32::from_ne_bytes(message[20..24].try_into().unwrap()) == self.index
                {
                    if kind == libc::RTM_DELLINK {
                        return Ok(());
                    }
                    if kind == libc::RTM_NEWLINK {
                        let flags = u32::from_ne_bytes(message[24..28].try_into().unwrap());
                        let next = LinkState {
                            up: flags & libc::IFF_UP as u32 != 0,
                            mtu: mtu(&message[32..]).unwrap_or(state.mtu),
                        };
                        if next != state {
                            if updates.send(next).is_err() {
                                return Ok(());
                            }
                            state = next;
                        }
                    }
                }
                messages = messages.get(len.next_multiple_of(4)..).unwrap_or_default();
            }
        }
    }
}

fn mtu(mut attrs: &[u8]) -> Option<usize> {
    while attrs.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes(attrs[..2].try_into().ok()?));
        let kind = u16::from_ne_bytes(attrs[2..4].try_into().ok()?);
        if !(4..=attrs.len()).contains(&len) {
            break;
        }
        if kind == IFLA_MTU && len == 8 {
            return Some(u32::from_ne_bytes(attrs[4..8].try_into().ok()?) as usize);
        }
        attrs = attrs.get(len.next_multiple_of(4)..)?;
    }
    None
}
