//! Connection selection and per-session/request budgets shared by XHTTP and XDrive.

use std::io;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Range(i32, i32);

impl Range {
    fn draw(self) -> i32 { rand::random_range(self.0..=self.1) }
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input { Number(i32), Text(String) }
        let (a, b) = match Input::deserialize(deserializer)? {
            Input::Number(n) => (n, n),
            Input::Text(text) => {
                let parse = |s: &str| s.parse::<i32>().map_err(serde::de::Error::custom);
                match text.char_indices().skip(1).find(|(_, c)| *c == '-') {
                    Some((at, _)) => (parse(&text[..at])?, parse(&text[at + 1..])?),
                    None => { let n = parse(&text)?; (n, n) }
                }
            }
        };
        Ok(Self(a.min(b), a.max(b)))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct XmuxConfig {
    max_concurrency: Range,
    max_connections: Range,
    #[serde(rename = "cMaxReuseTimes")]
    connection_uses: Range,
    #[serde(rename = "hMaxRequestTimes")]
    requests: Range,
    #[serde(rename = "hMaxReusableSecs")]
    reusable_seconds: Range,
    #[serde(rename = "hKeepAlivePeriod")]
    pub keepalive_seconds: i64,
}

impl XmuxConfig {
    pub fn xhttp(value: Option<&serde_json::Value>) -> io::Result<Self> {
        Self::parse(value, 3, Range(600, 900))
    }

    pub fn xdrive(value: Option<&serde_json::Value>, google_drive: bool, http3: bool) -> io::Result<Self> {
        Self::parse(value, if google_drive && !http3 { 4 } else { 1 }, Range::default())
    }

    fn parse(value: Option<&serde_json::Value>, connections: i32, requests: Range) -> io::Result<Self> {
        let mut config: Self = match value.filter(|value| !value.is_null()) {
            Some(value) => serde_json::from_value(value.clone()).map_err(io::Error::other)?,
            None => Self::default(),
        };
        if config.max_concurrency.1 > 0 && config.max_connections.1 > 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "xmux maxConnections and maxConcurrency are mutually exclusive"));
        }
        if config == Self::default() {
            config.max_connections = Range(connections, connections);
            config.reusable_seconds = Range(1800, 3000);
            config.requests = requests;
        }
        Ok(config)
    }
}

pub trait XmuxConnection: Send + Sync {
    fn is_closed(&self) -> bool;
}

pub struct XmuxPool<T> {
    config: XmuxConfig,
    concurrency: usize,
    connections: usize,
    clients: Mutex<Vec<Arc<Client<T>>>>,
}

struct Client<T> {
    connection: T,
    running: AtomicUsize,
    uses: AtomicI32,
    requests: AtomicI32,
    deadline: Option<Instant>,
}

pub struct XmuxLease<T> { client: Arc<Client<T>> }

impl<T: XmuxConnection> XmuxPool<T> {
    pub fn new(config: XmuxConfig) -> Self {
        Self {
            concurrency: config.max_concurrency.draw().max(0) as usize,
            connections: config.max_connections.draw().max(0) as usize,
            config,
            clients: Mutex::new(Vec::new()),
        }
    }

    pub fn acquire(&self, make: impl FnOnce() -> io::Result<T>) -> io::Result<XmuxLease<T>> {
        let mut clients = self.clients.lock().expect("XMUX pool");
        let now = Instant::now();
        clients.retain(|client| !client.connection.is_closed()
            && client.uses.load(Ordering::Relaxed) != 0
            && client.requests.load(Ordering::Relaxed) > 0
            && !client.deadline.is_some_and(|deadline| now >= deadline));
        let eligible: Vec<_> = clients.iter().filter(|client| self.concurrency == 0
            || client.running.load(Ordering::Relaxed) < self.concurrency).collect();
        let client = if !eligible.is_empty() && (self.connections == 0 || clients.len() >= self.connections) {
            let client = eligible[rand::random_range(0..eligible.len())].clone();
            if client.uses.load(Ordering::Relaxed) > 0 { client.uses.fetch_sub(1, Ordering::Relaxed); }
            client
        } else {
            let seconds = self.config.reusable_seconds.draw();
            let requests = self.config.requests.draw();
            let uses = self.config.connection_uses.draw();
            let client = Arc::new(Client {
                connection: make()?,
                running: AtomicUsize::new(0),
                uses: AtomicI32::new(if uses > 0 { uses - 1 } else { -1 }),
                requests: AtomicI32::new(if requests > 0 { requests } else { i32::MAX }),
                deadline: (seconds > 0).then(|| now + Duration::from_secs(seconds as u64)),
            });
            clients.push(client.clone());
            client
        };
        client.running.fetch_add(1, Ordering::Relaxed);
        Ok(XmuxLease { client })
    }
}

impl<T> XmuxLease<T> {
    pub fn connection(&self) -> &T { &self.client.connection }

    pub fn request(&self) -> bool {
        if self.client.deadline.is_some_and(|deadline| Instant::now() >= deadline) { return false; }
        self.client.requests.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| (remaining > 0).then_some(remaining - 1)).is_ok()
    }
}

impl<T> Drop for XmuxLease<T> {
    fn drop(&mut self) { self.client.running.fetch_sub(1, Ordering::Relaxed); }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Connection(usize);
    impl XmuxConnection for Connection { fn is_closed(&self) -> bool { false } }

    #[test]
    fn concurrent_sessions_and_request_exhaustion_select_distinct_connections() {
        let config = XmuxConfig::xhttp(Some(&serde_json::json!({"maxConcurrency": 1, "hMaxRequestTimes": 2}))).unwrap();
        let pool = XmuxPool::new(config);
        let first = pool.acquire(|| Ok(Connection(1))).unwrap();
        assert!(first.request());
        let second = pool.acquire(|| Ok(Connection(2))).unwrap();
        assert_eq!(second.connection().0, 2);
        drop(second);
        let reused = pool.acquire(|| panic!("idle connection should be reused")).unwrap();
        assert_eq!(reused.connection().0, 2);
        assert!(first.request());
        assert!(!first.request());
        drop(first);
        let replacement = pool.acquire(|| Ok(Connection(3))).unwrap();
        assert_eq!(replacement.connection().0, 3);
    }

    #[test]
    fn session_reuse_budget_does_not_interrupt_an_active_session() {
        let config = XmuxConfig::xhttp(Some(&serde_json::json!({"cMaxReuseTimes": 1}))).unwrap();
        let pool = XmuxPool::new(config);
        let first = pool.acquire(|| Ok(Connection(1))).unwrap();
        let second = pool.acquire(|| Ok(Connection(2))).unwrap();
        assert_eq!(second.connection().0, 2);
        assert!(first.request());
        assert_eq!(first.connection().0, 1);
    }
}
