//! 模块间共享的地址、I/O 和取消契约；不依赖具体协议或配置格式。

use std::{fmt, future::Future, io, net::IpAddr, pin::Pin, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
pub use tokio_util::sync::CancellationToken;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("地址或端口不合法")]
    InvalidAddress,
    #[error("配置不合法：{0}")]
    Config(String),
    #[error("不支持的能力：{0}")]
    Unsupported(&'static str),
    #[error("协议错误：{0}")]
    Protocol(&'static str),
    #[error("连接被策略拒绝")]
    Rejected,
    #[error("操作已取消")]
    Cancelled,
    #[error("操作超时")]
    Timeout,
    #[error("资源达到上限")]
    ResourceLimit,
    #[error("网络 I/O 失败：{0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Destination {
    address: Address,
    port: u16,
}

impl Destination {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        if port == 0 || host.is_empty() || host.trim() != host {
            return Err(Error::InvalidAddress);
        }
        let address = if let Ok(ip) = host.parse() {
            Address::Ip(ip)
        } else {
            if host
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || "/\\:@[]".contains(c))
            {
                return Err(Error::InvalidAddress);
            }
            let ascii = idna::domain_to_ascii(host).map_err(|_| Error::InvalidAddress)?;
            if ascii.trim_end_matches('.').is_empty()
                || ascii.len() > 255
                || ascii
                    .strip_suffix('.')
                    .unwrap_or(&ascii)
                    .split('.')
                    .any(|part| part.is_empty() || part.len() > 63)
            {
                return Err(Error::InvalidAddress);
            }
            Address::Domain(ascii.to_ascii_lowercase())
        };
        Ok(Self { address, port })
    }

    pub fn address(&self) -> &Address {
        &self.address
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn host(&self) -> String {
        match &self.address {
            Address::Ip(ip) => ip.to_string(),
            Address::Domain(name) => name.clone(),
        }
    }
    pub fn is_loopback(&self) -> bool {
        matches!(self.address, Address::Ip(ip) if ip.is_loopback())
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.address {
            Address::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            _ => write!(f, "{}:{}", self.host(), self.port),
        }
    }
}

pub trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> IoStream for T {}
pub type BoxStream = Box<dyn IoStream>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub tcp: bool,
    /// 是否能将写端 EOF 传播到最终目标，同时继续接收反向数据。
    pub tcp_eof: bool,
    /// 固定目标数据报；不等于 XUDP 或逐包多目标。
    pub udp: bool,
}

#[derive(Clone)]
pub struct ConnectContext {
    pub cancel: CancellationToken,
    pub timeout: Duration,
}

impl ConnectContext {
    pub fn new(timeout: Duration) -> Self {
        Self {
            cancel: CancellationToken::new(),
            timeout,
        }
    }

    pub async fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(Error::Cancelled),
            result = tokio::time::timeout(self.timeout, future) => result.map_err(|_| Error::Timeout)?,
        }
    }
}

pub trait DatagramSender: Send {
    /// 取消后必须丢弃整个会话；不保证部分分帧发送可以重新执行。
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>>;
}

pub trait DatagramReceiver: Send {
    /// 空负载为合法数据报；None 表示完整会话结束。
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>>;
}

pub struct DatagramChannel {
    pub sender: Box<dyn DatagramSender>,
    pub receiver: Box<dyn DatagramReceiver>,
}

pub trait Outbound: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>>;
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation_and_idna() {
        assert_eq!(
            Destination::new("EXAMPLE.INVALID", 443).unwrap().host(),
            "example.invalid"
        );
        assert_eq!(
            Destination::new("例子.invalid", 443).unwrap().host(),
            "xn--fsqu00a.invalid"
        );
        assert_eq!(Destination::new("::1", 53).unwrap().to_string(), "[::1]:53");
        for name in ["", " bad.invalid", "a/b", "a\0b", "name:443"] {
            assert!(Destination::new(name, 1).is_err());
        }
        assert!(Destination::new("127.0.0.1", 0).is_err());
    }

    #[tokio::test]
    async fn cancellation_and_budget() {
        let context = ConnectContext::new(Duration::from_millis(1));
        assert!(matches!(
            context.run(std::future::pending::<Result<()>>()).await,
            Err(Error::Timeout)
        ));
        context.cancel.cancel();
        assert!(matches!(
            context.run(async { Ok(()) }).await,
            Err(Error::Cancelled)
        ));
    }
}
