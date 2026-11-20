//! OS TUN attachment for the packet plane. The owner supplies addresses and routes.

#[cfg(not(target_os = "linux"))]
use std::time::Duration;
use std::{
    io,
    net::{SocketAddr, UdpSocket},
};
#[cfg(not(target_os = "linux"))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::packet::{peer_hub, TunCarrier};
#[cfg(not(target_os = "linux"))]
use crate::PacketLink;
use crate::{Hub, LinkPeer, Reserved};

pub fn bind_tun(bind: SocketAddr, hub: Hub, name: &str, mtu: u16) -> io::Result<()> {
    run_tun_hub(
        name,
        mtu,
        hub,
        TunCarrier::listener(bind, false),
        true,
        true,
        || Ok(()),
    )
}

/// Open a standalone Linux TUN with a transmit class on a preconfigured link.
#[cfg(target_os = "linux")]
pub fn bind_tun_with_egress(
    bind: SocketAddr,
    hub: Hub,
    name: &str,
    mtu: u16,
    device: &str,
    class: &str,
) -> io::Result<()> {
    let class = crate::tun_egress::class_id(class)?;
    let _link = crate::tun_egress::attach(device, class).map_err(|error| {
        io::Error::other(format!("attach WireGuard egress to {device}: {error}"))
    })?;
    let mut carrier = TunCarrier::listener(bind, false);
    carrier.egress_class = Some(class);
    run_tun_hub(name, mtu, hub, carrier, true, true, || Ok(()))
}

#[cfg(any(target_os = "linux", windows))]
pub fn run_interface(name: &str) -> io::Result<()> {
    run_interface_ready(name, || Ok(()))
}

#[cfg(any(target_os = "linux", windows))]
pub fn run_interface_ready(name: &str, ready: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    let mtu = 1420;
    run_tun_hub(
        name,
        mtu,
        Hub::without_key(usize::from(mtu))?,
        TunCarrier::listener(SocketAddr::from(([0; 8], 0)), true),
        !cfg!(target_os = "linux"),
        true,
        ready,
    )
}

fn run_tun_hub(
    name: &str,
    mtu: u16,
    hub: Hub,
    carrier: TunCarrier,
    up: bool,
    managed: bool,
    ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    return crate::packet::tun_linux::run(name, mtu, hub, carrier, up, managed, ready);
    #[cfg(windows)]
    return run_tun_until(name, mtu, up, usize::from(mtu), ready, || {
        let (requests, control) = if managed {
            let (requests, control) = crate::uapi::open(name)?;
            (Some(requests), Some(control))
        } else {
            (None, None)
        };
        let link = PacketLink::from_hub(carrier, hub, usize::from(mtu), requests)?;
        Ok((link, async move {
            tokio::select! {
                biased;
                result = stop_signal() => result,
                result = async move {
                    match control {
                        Some(control) => control.await,
                        None => std::future::pending().await,
                    }
                } => result,
            }
        }))
    });
    #[cfg(not(any(target_os = "linux", windows)))]
    run_tun_until(name, mtu, up, usize::from(mtu), ready, || {
        Ok((
            PacketLink::from_hub(carrier, hub, usize::from(mtu))?,
            stop_signal(),
        ))
    })
}

/// Attach outbound-owned client carriers to the same lifecycle as an independent TUN.
pub fn run_tun(
    name: &str,
    mtu: u16,
    socket: UdpSocket,
    dual: bool,
    peers: Vec<LinkPeer>,
    reserved: Reserved,
    mut reopen: impl FnMut(u16) -> io::Result<UdpSocket> + Send + 'static,
) -> io::Result<()> {
    if matches!(reserved, Reserved::Warp(_)) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let bind = socket.local_addr()?;
    let (hub, _) = peer_hub(bind, dual, peers, usize::from(mtu), false)?;
    let carrier = TunCarrier {
        bind,
        dual,
        reserved,
        first: Some(socket),
        reopen: Box::new(move |port, _| reopen(port)),
        #[cfg(target_os = "linux")]
        egress_class: None,
    };
    run_tun_hub(name, mtu, hub, carrier, true, false, || Ok(()))
}

#[cfg(target_os = "linux")]
pub(crate) async fn stop_signal() -> io::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => Ok(()),
        result = tokio::signal::ctrl_c() => result,
    }
}

#[cfg(not(target_os = "linux"))]
async fn stop_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(not(target_os = "linux"))]
fn run_tun_until<S: std::future::Future<Output = io::Result<()>>>(
    name: &str,
    mtu: u16,
    up: bool,
    buffer_size: usize,
    ready: impl FnOnce() -> io::Result<()>,
    start: impl FnOnce() -> io::Result<(PacketLink, S)>,
) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let device = create_tun(name, mtu, up)?;
        let (link, shutdown) = start()?;
        let (outbound, inbound) = link.into_halves();
        tokio::pin!(shutdown);
        let (mut reader, mut writer) = tokio::io::split(device);
        let (send, mut recv) = tokio::sync::mpsc::channel(32);
        std::thread::Builder::new().name("kerlico-wireguard-tun-rx".into()).spawn(move || {
            while !send.is_closed() {
                match inbound.recv_for(Duration::from_millis(200)) {
                    Ok(packet) => if send.blocking_send(packet).is_err() { return; },
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => {},
                    Err(_) => return,
                }
            }
        })?;
        let mut buffer = vec![0; buffer_size];
        ready()?;
        loop {
            tokio::select! {
                result = &mut shutdown => return result,
                result = reader.read(&mut buffer) => {
                    let n = result?;
                    if n == 0 { return Ok(()); }
                    if let Err(error) = outbound.send(buffer[..n].to_vec()) {
                        if !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::InvalidInput) { return Err(error); }
                    }
                },
                packet = recv.recv() => {
                    let packet = packet.ok_or(io::ErrorKind::BrokenPipe)?;
                    if writer.write(&packet).await? != packet.len() { return Err(io::ErrorKind::WriteZero.into()); }
                }
            }
        }
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn create_tun(name: &str, mtu: u16, up: bool) -> io::Result<impl AsyncRead + AsyncWrite + Unpin> {
    let mut config = tun::Configuration::default();
    config.tun_name(name).mtu(mtu);
    if up {
        config.up();
    }
    tun::create_as_async(&config).map_err(io::Error::other)
}

#[cfg(windows)]
fn create_tun(name: &str, mtu: u16, _up: bool) -> io::Result<impl AsyncRead + AsyncWrite + Unpin> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    use wintun_bindings::{Adapter, AsyncSession, MAX_RING_CAPACITY};

    if name.is_empty() || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Wintun adapter name",
        ));
    }
    let path = std::env::current_exe()?.with_file_name("wintun.dll");
    // Load only the DLL installed alongside this executable.
    let wintun = unsafe { wintun_bindings::load_from_path(&path) }
        .map_err(|error| io::Error::other(format!("load {}: {error}", path.display())))?;
    // Create an owned adapter. Opening someone else's adapter must not change its MTU.
    let adapter = Adapter::create(&wintun, name, "WireGuard", None).map_err(io::Error::other)?;
    if adapter.get_name().map_err(io::Error::other)? != name {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Wintun adapter name already in use",
        ));
    }
    if mtu < 1280 {
        wintun_bindings::set_adapter_mtu(&adapter.get_luid(), usize::from(mtu), false)?;
    } else {
        adapter
            .set_mtu(usize::from(mtu))
            .map_err(io::Error::other)?;
    }
    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(io::Error::other)?;
    Ok(AsyncSession::from(session).compat())
}
