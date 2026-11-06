//! 经命名出站的 HTTP 延迟探测与策略组/提供者后台健康检查。
//!
//! 语义对齐 Mihomo `URLTest`：经出站建立到测试 URL 的连接，发送 `HEAD`，
//! 计时从拨号前开始、到读到状态行为止；状态码不满足 `expected-status` 视为失败。

use crate::{Dispatcher, candidates_with_strategy, connect_candidates, group::HealthOwner};
use kerlico_config::{CompiledProxyGroup, CompiledProxyProvider, ProxyGroupKind};
use kerlico_core::{
    BoxStream, CancellationToken, ConnectContext, Destination, Error, OutId, Result, TargetPolicy,
};
use kerlico_net::TcpConnector;
use std::{
    fmt,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::{Instant, MissedTickBehavior},
};

/// Mihomo 的默认测试地址，请求未给出 URL 时使用。
pub const DEFAULT_TEST_URL: &str = "https://cp.cloudflare.com/generate_204";
const MAX_STATUS_LINE: usize = 4096;
const MAX_CONCURRENT_PROBES: usize = 10;

/// 已解析的 http/https 测试地址；主机保持原文，`Remote` 出站由远端解析。
pub struct ProbeTarget {
    destination: Destination,
    authority: String,
    path: String,
    tls: Option<TcpConnector>,
}

impl ProbeTarget {
    pub fn parse(url: &str) -> Result<Self> {
        let invalid = || Error::Config(format!("测试 URL 不合法：{url}"));
        let trimmed = url.trim();
        let (secure, rest) = match trimmed.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => (true, rest),
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (false, rest),
            _ => return Err(invalid()),
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let (authority, path) = match rest.find(['/', '?']) {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        if authority.is_empty()
            || authority.contains('@')
            || path.bytes().any(|b| b <= b' ' || b == 0x7f)
        {
            return Err(invalid());
        }
        let default_port = if secure { 443 } else { 80 };
        let parse_port = |raw: &str| raw.parse::<u16>().map_err(|_| invalid());
        let (host, port) = match authority.strip_prefix('[') {
            Some(bracketed) => {
                let (host, tail) = bracketed.split_once(']').ok_or_else(invalid)?;
                let port = match tail {
                    "" => default_port,
                    tail => parse_port(tail.strip_prefix(':').ok_or_else(invalid)?)?,
                };
                (host, port)
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, parse_port(port)?),
                None => (authority, default_port),
            },
        };
        if host.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            destination: Destination::new(host, port)?,
            authority: authority.to_owned(),
            path,
            tls: secure.then(|| TcpConnector::tls(host, None)).transpose()?,
        })
    }

    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// 在已建立的出站流上发送 `HEAD` 并返回状态码。
    async fn head(&self, stream: BoxStream) -> Result<u16> {
        let mut stream = match &self.tls {
            Some(connector) => connector.handshake(stream).await?,
            None => stream,
        };
        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: kerlico\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            self.path, self.authority
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut received = Vec::with_capacity(256);
        let mut chunk = [0u8; 512];
        loop {
            if let Some(end) = received.windows(2).position(|w| w == b"\r\n") {
                return parse_status_line(&received[..end]);
            }
            if received.len() > MAX_STATUS_LINE {
                return Err(Error::Protocol("探测响应状态行过长"));
            }
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(Error::Protocol("探测响应在状态行前结束"));
            }
            received.extend_from_slice(&chunk[..read]);
        }
    }
}

fn parse_status_line(line: &[u8]) -> Result<u16> {
    let malformed = Error::Protocol("探测响应状态行不合法");
    let line = std::str::from_utf8(line).map_err(|_| Error::Protocol("探测响应状态行不合法"))?;
    let mut parts = line.splitn(3, ' ');
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(malformed);
    }
    parts
        .next()
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..=599).contains(code))
        .ok_or(malformed)
}

/// Mihomo `expected-status` 语法：空或 `*` 接受任意状态；`204`、`200/302`、`200-299,302`。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedStatus(Vec<(u16, u16)>);

impl ExpectedStatus {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() || raw == "*" {
            return Ok(Self::default());
        }
        let invalid = || Error::Config(format!("expected-status 不合法：{raw}"));
        let items: Vec<&str> = raw.split(['/', ',']).collect();
        if items.len() > 28 {
            return Err(invalid());
        }
        let parse = |s: &str| s.trim().parse::<u16>().map_err(|_| invalid());
        let mut ranges = Vec::with_capacity(items.len());
        for item in items.into_iter().map(str::trim).filter(|s| !s.is_empty()) {
            let (low, high) = match item.split_once('-') {
                Some((low, high)) => (parse(low)?, parse(high)?),
                None => {
                    let code = parse(item)?;
                    (code, code)
                }
            };
            if low > high {
                return Err(invalid());
            }
            ranges.push((low, high));
        }
        Ok(Self(ranges))
    }

    pub fn matches(&self, status: u16) -> bool {
        self.0.is_empty()
            || self
                .0
                .iter()
                .any(|(low, high)| (*low..=*high).contains(&status))
    }
}

/// 一次延迟探测的完整输入。
pub struct ProbeSpec {
    pub target: ProbeTarget,
    pub timeout: Duration,
    pub expected: ExpectedStatus,
}

impl ProbeSpec {
    pub fn new(url: &str, timeout: Duration, expected: &str) -> Result<Self> {
        Ok(Self {
            target: ProbeTarget::parse(url)?,
            timeout,
            expected: ExpectedStatus::parse(expected)?,
        })
    }
}

#[derive(Debug)]
pub enum ProbeError {
    /// 名称既不是命名出站也不是策略组，或策略组没有可用的具体出站。
    UnknownOutbound,
    Timeout,
    Failed(Error),
    UnexpectedStatus(u16),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOutbound => f.write_str("出站不存在"),
            Self::Timeout => f.write_str("探测超时"),
            Self::Failed(error) => write!(f, "探测失败：{error}"),
            Self::UnexpectedStatus(status) => write!(f, "状态码 {status} 不满足 expected-status"),
        }
    }
}

pub type ProbeResult = std::result::Result<u32, ProbeError>;

impl Dispatcher {
    /// 探测并把结果写入控制面：成功记录延迟，失败记为不可用。
    pub(crate) async fn probe(
        &self,
        id: &OutId,
        spec: &ProbeSpec,
        cancel: Option<CancellationToken>,
    ) -> ProbeResult {
        let result = self.measure(id, spec, cancel).await;
        match &result {
            Ok(delay) => self.control_plane.record_delay(id, Some(*delay), None),
            Err(ProbeError::UnknownOutbound) => {}
            Err(error) => self
                .control_plane
                .record_delay(id, None, Some(error.to_string())),
        }
        result
    }

    async fn measure(
        &self,
        id: &OutId,
        spec: &ProbeSpec,
        cancel: Option<CancellationToken>,
    ) -> ProbeResult {
        if !self.control_plane.has_proxy(id) {
            return Err(ProbeError::UnknownOutbound);
        }
        let concrete = self
            .control_plane
            .resolve_untouched(id)
            .map_err(|_| ProbeError::UnknownOutbound)?;
        let service = self
            .services
            .get(&concrete)
            .ok_or(ProbeError::UnknownOutbound)?;
        if !service.capabilities.tcp {
            return Err(ProbeError::Failed(Error::Unsupported(
                "所选命名出站没有 TCP 能力",
            )));
        }
        let mut context = ConnectContext::for_service(spec.timeout, &service.host);
        if let Some(cancel) = cancel {
            context = context.with_cancel(cancel);
        }
        let target = spec.target.destination();
        let started = Instant::now();
        let status = context
            .run(async {
                let opened = match service.policy {
                    TargetPolicy::Remote => service.backend.connect_tcp(target, &context).await?,
                    TargetPolicy::Local => {
                        let candidates = candidates_with_strategy(
                            self.resolver.as_ref(),
                            target,
                            context.target_mode(),
                            None,
                        )
                        .await?;
                        connect_candidates(service.backend.as_ref(), &candidates, &context)
                            .await?
                            .0
                    }
                };
                spec.target.head(opened.stream).await
            })
            .await
            .map_err(|error| match error {
                Error::Timeout => ProbeError::Timeout,
                error => ProbeError::Failed(error),
            })?;
        let delay = u32::try_from(started.elapsed().as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        if spec.expected.matches(status) {
            Ok(delay)
        } else {
            Err(ProbeError::UnexpectedStatus(status))
        }
    }

    /// 并发探测多个出站，最多同时 10 个，结果按输入顺序返回。
    pub(crate) async fn probe_all(
        self: &Arc<Self>,
        ids: &[OutId],
        spec: &Arc<ProbeSpec>,
        cancel: Option<CancellationToken>,
    ) -> Vec<(OutId, ProbeResult)> {
        let mut running = JoinSet::new();
        let mut done = Vec::with_capacity(ids.len());
        for (index, id) in ids.iter().enumerate() {
            if running.len() >= MAX_CONCURRENT_PROBES
                && let Some(Ok(finished)) = running.join_next().await
            {
                done.push(finished);
            }
            let dispatcher = self.clone();
            let spec = spec.clone();
            let cancel = cancel.clone();
            let id = id.clone();
            running.spawn(async move {
                let result = dispatcher.probe(&id, &spec, cancel).await;
                (index, id, result)
            });
        }
        while let Some(finished) = running.join_next().await {
            if let Ok(finished) = finished {
                done.push(finished);
            }
        }
        done.sort_by_key(|(index, _, _)| *index);
        done.into_iter()
            .map(|(_, id, result)| (id, result))
            .collect()
    }
}

/// 控制接口使用的探测句柄；不延长运行时生命周期，运行时释放后探测返回取消。
#[derive(Clone)]
pub struct Prober(pub(crate) Weak<Dispatcher>);

impl Prober {
    pub async fn probe(&self, id: &OutId, spec: &ProbeSpec) -> ProbeResult {
        match self.0.upgrade() {
            Some(dispatcher) => dispatcher.probe(id, spec, None).await,
            None => Err(ProbeError::Failed(Error::Cancelled)),
        }
    }

    pub async fn probe_all(
        &self,
        ids: &[OutId],
        spec: Arc<ProbeSpec>,
    ) -> Vec<(OutId, ProbeResult)> {
        match self.0.upgrade() {
            Some(dispatcher) => dispatcher.probe_all(ids, &spec, None).await,
            None => ids
                .iter()
                .map(|id| (id.clone(), Err(ProbeError::Failed(Error::Cancelled))))
                .collect(),
        }
    }
}

/// 一个周期性健康检查：同一组成员、同一测试规格。
pub(crate) struct HealthJob {
    owner: HealthOwner,
    members: Vec<OutId>,
    spec: Arc<ProbeSpec>,
    interval: Duration,
    lazy: bool,
}

/// `url-test`、`fallback`、`load-balance` 组与开启 `health-check` 的提供者各一个任务。
///
/// Xray `balancer` 的探测由 observatory 配置，这里不为其建立任务。
pub(crate) fn health_jobs(
    groups: &[CompiledProxyGroup],
    providers: &[CompiledProxyProvider],
) -> (Vec<HealthJob>, Vec<String>) {
    let mut jobs = Vec::new();
    let mut rejected = Vec::new();
    let mut add = |owner, members: &[OutId], url: &str, timeout_ms, expected: &str, secs, lazy| {
        if members.is_empty() || secs == 0 || url.trim().is_empty() {
            return;
        }
        match ProbeSpec::new(url, Duration::from_millis(timeout_ms), expected) {
            Ok(spec) => jobs.push(HealthJob {
                owner,
                members: members.to_vec(),
                spec: Arc::new(spec),
                interval: Duration::from_secs(secs),
                lazy,
            }),
            Err(error) => rejected.push(error.to_string()),
        }
    };
    for group in groups {
        if matches!(
            group.kind,
            ProxyGroupKind::UrlTest | ProxyGroupKind::Fallback | ProxyGroupKind::LoadBalance
        ) {
            add(
                HealthOwner::Group(group.id.clone()),
                &group.candidates,
                &group.url,
                group.timeout_ms,
                &group.expected_status,
                group.interval_secs,
                group.lazy,
            );
        }
    }
    for provider in providers.iter().filter(|p| p.health_check_enable) {
        add(
            HealthOwner::Provider,
            &provider.proxies,
            &provider.health_check_url,
            provider.health_check_timeout_ms,
            &provider.health_check_expected_status,
            provider.health_check_interval,
            provider.health_check_lazy,
        );
    }
    (jobs, rejected)
}

/// 启动即检查一轮，之后每个周期检查；`lazy` 时跳过周期内未被路由使用的组。
pub(crate) async fn run_health_job(
    dispatcher: Weak<Dispatcher>,
    job: HealthJob,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(job.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let window_ms = u64::try_from(job.interval.as_millis()).unwrap_or(u64::MAX);
    let mut first = true;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let Some(dispatcher) = dispatcher.upgrade() else {
            return;
        };
        if !first
            && job.lazy
            && !dispatcher
                .control_plane
                .touched_within(&job.owner, &job.members, window_ms)
        {
            continue;
        }
        first = false;
        dispatcher
            .probe_all(&job.members, &job.spec, Some(cancel.clone()))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_status_follows_mihomo_syntax() {
        let any = ExpectedStatus::parse("").unwrap();
        assert!(any.matches(500));
        assert!(ExpectedStatus::parse("*").unwrap().matches(418));
        let exact = ExpectedStatus::parse("204").unwrap();
        assert!(exact.matches(204) && !exact.matches(200));
        let mixed = ExpectedStatus::parse("200-299/302").unwrap();
        assert!(mixed.matches(250) && mixed.matches(302) && !mixed.matches(301));
        assert!(ExpectedStatus::parse("200,204").unwrap().matches(204));
        assert!(ExpectedStatus::parse("299-200").is_err());
        assert!(ExpectedStatus::parse("abc").is_err());
    }

    #[test]
    fn target_keeps_host_and_splits_path() {
        let target = ProbeTarget::parse("http://probe.test:8080/generate_204?x=1#frag").unwrap();
        assert_eq!(
            target.destination(),
            &Destination::new("probe.test", 8080).unwrap()
        );
        assert_eq!(target.authority, "probe.test:8080");
        assert_eq!(target.path, "/generate_204?x=1");
        assert!(target.tls.is_none());

        let secure = ProbeTarget::parse("HTTPS://cp.cloudflare.com").unwrap();
        assert_eq!(secure.destination().port(), 443);
        assert_eq!(secure.path, "/");
        assert!(secure.tls.is_some());

        let v6 = ProbeTarget::parse("http://[::1]:9/").unwrap();
        assert_eq!(v6.destination(), &Destination::new("::1", 9).unwrap());

        for bad in [
            "ftp://x/",
            "http://",
            "http://u@h/",
            "http://h:x/",
            "http://h/a b",
        ] {
            assert!(ProbeTarget::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn status_line_requires_http1_and_three_digits() {
        assert_eq!(parse_status_line(b"HTTP/1.1 204 No Content").unwrap(), 204);
        assert_eq!(parse_status_line(b"HTTP/1.0 200").unwrap(), 200);
        assert!(parse_status_line(b"HTTP/2 200 OK").is_err());
        assert!(parse_status_line(b"HTTP/1.1 20 OK").is_err());
    }
}
