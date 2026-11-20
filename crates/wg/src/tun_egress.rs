//! An opt-in Linux transmit class for the standalone TUN carrier.

use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// Linux UAPI in linux/bpf.h and linux/pkt_cls.h.
const BPF_PROG_LOAD: libc::c_uint = 5;
const BPF_LINK_CREATE: libc::c_uint = 28;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
const BPF_TCX_EGRESS: u32 = 47;
const BPF_FUNC_SKB_PULL_DATA: i32 = 39;
const TCX_NEXT: i32 = -1;
const SKB_LEN: i16 = 0;
const SKB_PRIORITY: i16 = 32;

#[repr(C)]
struct Instruction {
    code: u8,
    registers: u8,
    offset: i16,
    immediate: i32,
}

fn instruction(code: u8, dst: u8, src: u8, offset: i16, immediate: i32) -> Instruction {
    #[cfg(target_endian = "little")]
    let registers = src << 4 | dst;
    #[cfg(target_endian = "big")]
    let registers = dst << 4 | src;
    Instruction {
        code,
        registers,
        offset,
        immediate,
    }
}

fn program(class: u32) -> [Instruction; 8] {
    // Short packets and other classes continue unchanged. The helper makes the
    // selected GSO frame contiguous before it reaches the egress qdisc.
    [
        instruction(0x61, 2, 1, SKB_LEN, 0),      // ldxw r2, [r1 + len]
        instruction(0xa5, 2, 0, 4, 4096),         // if r2 < 4096 goto next
        instruction(0x25, 2, 0, 3, 65535),        // if r2 > 65535 goto next
        instruction(0x61, 3, 1, SKB_PRIORITY, 0), // ldxw r3, [r1 + priority]
        instruction(0x56, 3, 0, 1, class as i32), // if (u32)r3 != class goto next
        instruction(0x85, 0, 0, 0, BPF_FUNC_SKB_PULL_DATA),
        instruction(0xb7, 0, 0, 0, TCX_NEXT),
        instruction(0x95, 0, 0, 0, 0),
    ]
}

#[repr(C)]
struct Load {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct Link {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
}

pub(crate) fn class_id(text: &str) -> io::Result<u32> {
    let class = text.split_once(':').and_then(|(major, minor)| {
        let major = u16::from_str_radix(major, 16).ok()?;
        let minor = u16::from_str_radix(minor, 16).ok()?;
        (major != 0 && minor != 0).then_some((u32::from(major) << 16) | u32::from(minor))
    });
    class.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid WireGuard egress class",
        )
    })
}

pub(crate) fn set_class(socket: &UdpSocket, class: u32) -> io::Result<()> {
    let class = class as libc::c_int;
    // SAFETY: the descriptor is borrowed from a live socket and SO_PRIORITY
    // takes a native int.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            (&class as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn attach(device: &str, class: u32) -> io::Result<OwnedFd> {
    let device = CString::new(device).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: device is a live NUL-terminated name.
    let ifindex = unsafe { libc::if_nametoindex(device.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    let instructions = program(class);
    let loaded = bpf_fd(
        BPF_PROG_LOAD,
        &Load {
            prog_type: BPF_PROG_TYPE_SCHED_CLS,
            insn_cnt: instructions.len() as u32,
            insns: instructions.as_ptr() as usize as u64,
            license: c"GPL".as_ptr() as usize as u64,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            kern_version: 0,
            prog_flags: 0,
            prog_name: *b"kerlico_wg\0\0\0\0\0\0",
            prog_ifindex: 0,
            expected_attach_type: BPF_TCX_EGRESS,
        },
    )?;
    bpf_fd(
        BPF_LINK_CREATE,
        &Link {
            prog_fd: loaded.as_raw_fd() as u32,
            target_ifindex: ifindex,
            attach_type: BPF_TCX_EGRESS,
            flags: 0,
        },
    )
}

fn bpf_fd<T>(command: libc::c_uint, attr: &T) -> io::Result<OwnedFd> {
    // SAFETY: the caller provides the Linux UAPI for a BPF descriptor
    // creation command and all pointed-to storage lives through the call.
    let result = unsafe { libc::syscall(libc::SYS_bpf, command, attr, size_of::<T>()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: success returns a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(result as libc::c_int) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_ids_use_the_tc_hexadecimal_notation() -> io::Result<()> {
        assert_eq!(class_id("1:2")?, 0x0001_0002);
        assert_eq!(class_id("a:b")?, 0x000a_000b);
        for invalid in ["1", "0:2", "1:0", "q:2", "10000:1", "1:2:3"] {
            assert!(class_id(invalid).is_err());
        }
        Ok(())
    }
}
