//! Windows byte pipe for the standalone WireGuard administrative interface.

use std::{ffi::c_void, io, mem, ptr};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::{
    Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
    SECURITY_ATTRIBUTES,
};

use crate::uapi::MAX_CLIENTS;

const PREFIX: &str = r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\";
// wg.exe checks the LocalSystem owner before sending keys. Match the ACL and
// integrity label used by wireguard-go, and never fall back to a public pipe.
const SECURITY: &str = "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)";

pub(crate) struct Listener {
    next: NamedPipeServer,
    path: String,
    security: &'static str,
}

impl Listener {
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.encode_utf16().count() >= 128
            || name
                .chars()
                .any(|c| c.is_control() || matches!(c, '\\' | '/'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WireGuard interface name",
            ));
        }
        Self::open_at(format!("{PREFIX}{name}"), SECURITY)
    }

    fn open_at(path: String, security: &'static str) -> io::Result<Self> {
        let next = instance(&path, security, true)?;
        Ok(Self {
            next,
            path,
            security,
        })
    }

    pub(crate) async fn accept(&mut self) -> io::Result<Option<NamedPipeServer>> {
        self.next.connect().await?;
        // Keep a pipe present while transferring the connected instance to a worker.
        let next = instance(&self.path, self.security, false)?;
        Ok(Some(mem::replace(&mut self.next, next)))
    }
}

fn instance(path: &str, sddl: &str, first: bool) -> io::Result<NamedPipeServer> {
    let sddl: Vec<_> = sddl.encode_utf16().chain([0]).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: sddl is a NUL-terminated UTF-16 string, and descriptor is an output pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: CreateNamedPipeW copies these attributes; free the descriptor afterwards.
    let result = unsafe {
        ServerOptions::new()
            .max_instances(MAX_CLIENTS + 1)
            .reject_remote_clients(true)
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(
                path,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
    };
    unsafe { LocalFree(descriptor) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawHandle;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER, ERROR_PRIVILEGE_NOT_HELD,
    };
    use windows_sys::Win32::Security::{
        Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, OWNER_SECURITY_INFORMATION,
    };

    async fn command(pipe: &mut BufReader<NamedPipeClient>, request: &str) -> String {
        pipe.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(pipe.read_line(&mut line).await.unwrap(), 0);
            if line == "\n" {
                return answer;
            }
            answer.push_str(&line);
        }
    }

    #[tokio::test]
    async fn windows_pipe_updates_the_live_hub() {
        // A user-owned, private pipe has the same transport, framing and hub
        // as production. It can run without a TUN or a LocalSystem token.
        let path = format!(
            r"\\.\pipe\kerlico-uapi-{}-{:016x}",
            std::process::id(),
            OsRng.next_u64()
        );
        let sddl = "D:P(A;;GA;;;OW)";
        let listener = Listener::open_at(path.clone(), sddl).unwrap();
        assert!(Listener::open_at(path.clone(), sddl).is_err());
        let (control, manage) = crate::uapi::serve_on(listener);
        let server = tokio::spawn(manage);
        let _link = crate::PacketLink::from_hub(
            crate::packet::TunCarrier::listener("127.0.0.1:0".parse().unwrap(), false),
            crate::Hub::without_key(1420).unwrap(),
            1420,
            Some(control),
        )
        .unwrap();
        let mut held = BufReader::new(ClientOptions::new().open(&path).unwrap());
        let initial = command(&mut held, "get=1\n\n").await;
        let port: u16 = initial
            .lines()
            .next()
            .unwrap()
            .strip_prefix("listen_port=")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(port, 0);
        assert_eq!(initial, format!("listen_port={port}\nerrno=0\n"));

        let mut pipe = BufReader::new(ClientOptions::new().open(&path).unwrap());
        // A second management connection can proceed while the first is idle.
        let busy = UdpSocket::bind("127.0.0.1:0").unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        let key = "01".repeat(32);
        let canonical = format!("00{}41", "01".repeat(30));
        assert_eq!(
            command(
                &mut pipe,
                &format!("set=1\nprivate_key={key}\nlisten_port={busy_port}\n\n")
            )
            .await,
            "errno=-98\n"
        );
        assert_eq!(
            command(&mut pipe, "get=1\n\n").await,
            format!("listen_port={port}\nerrno=0\n")
        );
        drop(busy);
        assert_eq!(
            command(
                &mut pipe,
                &format!("set=1\nprivate_key={key}\nlisten_port={busy_port}\nfwmark=1\n\n")
            )
            .await,
            "errno=0\n"
        );
        assert_eq!(
            command(&mut pipe, "get=1\n\n").await,
            format!("private_key={canonical}\nlisten_port={busy_port}\nfwmark=1\nerrno=0\n")
        );
        assert_eq!(
            command(&mut pipe, "set=1\ninvalid_key=0\n\n").await,
            "errno=-22\n"
        );
        assert!(command(&mut pipe, "get=1\n\n")
            .await
            .starts_with(&format!("private_key={canonical}\n")));
        assert_eq!(
            command(
                &mut pipe,
                &format!("set=1\nprivate_key={}\n\n", "00".repeat(32))
            )
            .await,
            "errno=0\n"
        );
        assert_eq!(
            command(&mut pipe, "get=1\n\n").await,
            format!("listen_port={busy_port}\nfwmark=1\nerrno=0\n")
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn protected_pipe_requires_the_system_owner() {
        let name = format!(
            "KerlicoUapiFixture-{}-{:016x}",
            std::process::id(),
            OsRng.next_u64()
        );
        let listener = match Listener::open(&name) {
            Ok(listener) => listener,
            Err(error) => {
                let code = error.raw_os_error().unwrap_or_default() as u32;
                assert!(
                    matches!(
                        code,
                        ERROR_ACCESS_DENIED | ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD
                    ),
                    "{error}"
                );
                return;
            }
        };
        let mut owner = ptr::null_mut();
        let mut actual = ptr::null_mut();
        let mut system = ptr::null_mut();
        let sid: Vec<_> = "S-1-5-18".encode_utf16().chain([0]).collect();
        unsafe {
            assert_ne!(ConvertStringSidToSidW(sid.as_ptr(), &mut system), 0);
            assert_eq!(
                GetSecurityInfo(
                    listener.next.as_raw_handle().cast(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut actual,
                ),
                0
            );
            let system_owned = EqualSid(owner, system);
            LocalFree(actual);
            LocalFree(system);
            assert_ne!(system_owned, 0);
        }
    }
}
