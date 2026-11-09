use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

use nix::libc::{in6_addr, in6_pktinfo, in_addr, in_pktinfo};
use nix::sys::socket::{
    recvmsg, sendmsg, setsockopt, sockopt, ControlMessage, ControlMessageOwned, MsgFlags,
    SockaddrIn, SockaddrIn6, SockaddrStorage,
};

use super::super::malformed;
use super::{EchoSocket, Source};

pub(super) fn receive_packet_info(socket: &EchoSocket) -> io::Result<()> {
    if socket.ipv4 {
        setsockopt(&socket.io, sockopt::Ipv4PacketInfo, &true)?;
    } else {
        setsockopt(&socket.io, sockopt::Ipv6RecvPacketInfo, &true)?;
    }
    Ok(())
}

pub(super) fn recv(socket: &EchoSocket, wire: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<Source>)> {
    let mut control = nix::cmsg_space!(in_pktinfo, in6_pktinfo);
    let mut slices = [IoSliceMut::new(wire)];
    let message = recvmsg::<SockaddrStorage>(socket.io.as_raw_fd(), &mut slices, Some(&mut control), MsgFlags::empty())?;
    let remote = message.address.and_then(|addr| {
        addr.as_sockaddr_in().copied().map(SocketAddr::from)
            .or_else(|| addr.as_sockaddr_in6().copied().map(SocketAddr::from))
    }).ok_or_else(|| malformed("ICMP packet has no source IP"))?;
    let source = message.cmsgs()?.find_map(|info| match info {
        ControlMessageOwned::Ipv4PacketInfo(info) => Some(Source {
            ip: info.ipi_addr.s_addr.to_ne_bytes().into(),
            interface: info.ipi_ifindex as u32,
        }),
        ControlMessageOwned::Ipv6PacketInfo(info) => Some(Source {
            ip: info.ipi6_addr.s6_addr.into(),
            interface: info.ipi6_ifindex,
        }),
        _ => None,
    });
    Ok((message.bytes, remote, source))
}

pub(super) fn send(socket: &EchoSocket, wire: &[u8], remote: SocketAddr, source: Option<Source>) -> io::Result<usize> {
    let fd = socket.io.as_raw_fd();
    let slices = [IoSlice::new(wire)];
    let flags = MsgFlags::empty();
    match (remote, source) {
        (SocketAddr::V4(remote), Some(Source { ip: IpAddr::V4(ip), .. })) => {
            let info = in_pktinfo {
                ipi_ifindex: 0,
                ipi_addr: in_addr { s_addr: 0 },
                ipi_spec_dst: in_addr { s_addr: u32::from_ne_bytes(ip.octets()) },
            };
            Ok(sendmsg(fd, &slices, &[ControlMessage::Ipv4PacketInfo(&info)], flags, Some(&SockaddrIn::from(remote)))?)
        }
        (SocketAddr::V6(remote), Some(Source { ip: IpAddr::V6(ip), interface })) => {
            let info = in6_pktinfo {
                ipi6_addr: in6_addr { s6_addr: ip.octets() },
                ipi6_ifindex: interface,
            };
            Ok(sendmsg(fd, &slices, &[ControlMessage::Ipv6PacketInfo(&info)], flags, Some(&SockaddrIn6::from(remote)))?)
        }
        _ => socket.io.send_to(wire, remote),
    }
}
