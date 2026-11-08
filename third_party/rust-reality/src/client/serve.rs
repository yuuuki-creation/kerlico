//! Client accept loops for loopback SOCKS5 and HTTP CONNECT.

use std::{io, sync::Arc, time::Duration};

use tokio::net::TcpListener;

use crate::config::node::{ClientConfig, InboundProtocol, ListenerConfig};

use super::{
    http_inbound,
    line::LineError,
    selection::{LineGroup, LinePool, SelectionPolicy},
    socks5_inbound,
};

/// Client runtime failure.
#[derive(Debug)]
pub enum ClientRuntimeError {
    /// Configuration could not compile a LINE.
    Line(LineError),
    /// Listener bind failed.
    Bind(io::Error),
    /// Accept failed.
    Accept(io::Error),
}

impl std::fmt::Display for ClientRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client runtime failed")
    }
}

impl std::error::Error for ClientRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Line(e) => Some(e),
            Self::Bind(e) | Self::Accept(e) => Some(e),
        }
    }
}

/// Runs the client until the process is cancelled.
pub async fn run_client(config: &ClientConfig) -> Result<(), ClientRuntimeError> {
    let policy = selection_policy(config);
    let pool = if let Some(groups) = &config.line_groups {
        LinePool::from_groups(&config.lines, groups, policy)
    } else {
        LinePool::from_lines(&config.lines, policy)
    }
    .map_err(ClientRuntimeError::Line)?;
    let pool = Arc::new(pool);

    if config.listeners.is_empty() {
        return Err(ClientRuntimeError::Line(LineError::Config("listeners")));
    }

    let mut joins = Vec::with_capacity(config.listeners.len());
    for listener_cfg in &config.listeners {
        let group = pool
            .group(listener_cfg.line_group.as_deref())
            .map_err(ClientRuntimeError::Line)?;
        let (listener, bound) = open_listener(listener_cfg).await?;
        let protocol = listener_cfg.protocol.unwrap_or(InboundProtocol::Socks5);
        eprintln!(
            "rust-reality client listening {} on {bound} (lineGroup={})",
            protocol.as_str(),
            group.name()
        );
        joins.push(tokio::spawn(async move {
            accept_loop(listener, bound, protocol, group).await
        }));
    }

    let (result, _index, _rest) = futures_util::future::select_all(joins).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(join) => Err(ClientRuntimeError::Accept(io::Error::other(
            join.to_string(),
        ))),
    }
}

fn selection_policy(config: &ClientConfig) -> SelectionPolicy {
    let mut policy = SelectionPolicy::default();
    if let Some(selection) = &config.selection {
        if let Some(ms) = selection.hedge_ms {
            policy.hedge = Duration::from_millis(ms);
        }
        if let Some(ms) = selection.timeout_ms {
            policy.timeout = Duration::from_millis(ms);
        }
    }
    policy
}

async fn open_listener(
    listener_cfg: &ListenerConfig,
) -> Result<(TcpListener, std::net::SocketAddr), ClientRuntimeError> {
    let bind = std::net::SocketAddr::new(
        std::net::IpAddr::V4(listener_cfg.ipv4_address()),
        listener_cfg.port,
    );
    let bind = if bind.ip().is_unspecified() {
        std::net::SocketAddr::from(([127, 0, 0, 1], listener_cfg.port))
    } else {
        bind
    };
    let listener = TcpListener::bind(bind)
        .await
        .map_err(ClientRuntimeError::Bind)?;
    let bound = listener.local_addr().map_err(ClientRuntimeError::Bind)?;
    Ok((listener, bound))
}

async fn accept_loop(
    listener: TcpListener,
    bound: std::net::SocketAddr,
    protocol: InboundProtocol,
    group: Arc<LineGroup>,
) -> Result<(), ClientRuntimeError> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(ClientRuntimeError::Accept)?;
        let group = Arc::clone(&group);
        tokio::spawn(async move {
            match protocol {
                InboundProtocol::Socks5 => {
                    let _ = socks5_inbound::handle_connection(stream, bound, &group).await;
                }
                InboundProtocol::Http => {
                    let _ = http_inbound::handle_connection(stream, &group).await;
                }
            }
        });
    }
}
