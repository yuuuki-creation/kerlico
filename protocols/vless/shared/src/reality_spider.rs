use crate::H2Conn;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{self, Read, Write},
    sync::{Arc, LazyLock, Mutex},
    thread,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct RealitySpiderConfig {
    pub path: String,
    padding: Range,
    concurrency: Range,
    times: Range,
    interval: Range,
    returns: Range,
}

#[derive(Clone, Copy, Debug, Default)]
struct Range(u64, u64);
impl Range {
    fn parse(text: &str) -> io::Result<Self> {
        let (low, high) = text.split_once('-').unwrap_or((text, text));
        let low = low.parse::<u64>().map_err(io::Error::other)?;
        let high = high.parse::<u64>().map_err(io::Error::other)?;
        Ok(Self(low.min(high), low.max(high)))
    }
    fn choose(self) -> io::Result<u64> {
        if self.1 - self.0 <= 1 {
            return Ok(self.0);
        }
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
        Ok(self.0 + u64::from_le_bytes(bytes) % (self.1 - self.0))
    }
}

impl RealitySpiderConfig {
    pub fn parse(spider_x: &str) -> io::Result<Self> {
        let path = if spider_x.is_empty() { "/" } else { spider_x };
        if !path.starts_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spiderX must start with /",
            ));
        }
        let mut url =
            url::Url::parse(&format!("https://spider.invalid{path}")).map_err(io::Error::other)?;
        let mut query: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, value) in url.query_pairs() {
            query
                .entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        let mut range = |key: &str| -> io::Result<Range> {
            query
                .remove(key)
                .and_then(|values| values.into_iter().next())
                .filter(|value| !value.is_empty())
                .map(|value| Range::parse(&value))
                .transpose()
                .map(Option::unwrap_or_default)
        };
        let (padding, concurrency, times, interval, returns) = (
            range("p")?,
            range("c")?,
            range("t")?,
            range("i")?,
            range("r")?,
        );
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, values) in query {
            for value in values {
                encoded.append_pair(&key, &value);
            }
        }
        let query = encoded.finish();
        url.set_query((!query.is_empty()).then_some(query.as_str()));
        let path = format!(
            "{}{}",
            url.path(),
            url.query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        Ok(Self {
            path,
            padding,
            concurrency,
            times,
            interval,
            returns,
        })
    }
    pub fn return_delay(&self) -> io::Result<Duration> {
        self.returns.choose().map(Duration::from_millis)
    }
}

type Paths = Arc<Mutex<HashSet<String>>>;
static PATHS: LazyLock<Mutex<HashMap<String, Paths>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HREF: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"href="([/h].*?)""#).expect("REALITY href pattern"));

/// Runs only on a PKI-verified decoy stream supplied by the caller. It never dials.
/// Retains the HTTP/2 connection and services control frames until the peer closes it.
pub fn run_reality_spider<R: Read + Send + 'static, W: Write + Send + 'static>(
    read: R,
    write: W,
    name: &str,
    config: &RealitySpiderConfig,
) -> io::Result<()> {
    let connection = Arc::new(H2Conn::connect(read, write)?);
    crawl(connection.clone(), name, config)?;
    connection.wait_closed()
}

fn crawl<W: Write + Send + 'static>(
    connection: Arc<H2Conn<W>>,
    name: &str,
    config: &RealitySpiderConfig,
) -> io::Result<()> {
    let paths = {
        let mut hosts = PATHS.lock().map_err(|_| io::Error::other("spider paths"))?;
        if hosts.len() >= 1024 {
            hosts.retain(|_, paths| Arc::strong_count(paths) > 1);
        }
        let paths = hosts.entry(name.into()).or_default().clone();
        paths
            .lock()
            .map_err(|_| io::Error::other("spider paths"))?
            .insert(config.path.clone());
        paths
    };
    let first = format!("https://{name}{}", choose_path(&paths)?);
    fetch(
        &connection,
        name,
        &first,
        &paths,
        &padding_cookie(config.padding)?,
        false,
    )?;
    let mut tasks = Vec::new();
    for _ in 0..config.concurrency.choose()? {
        let (connection, name, paths, config, first) = (
            connection.clone(),
            name.to_string(),
            paths.clone(),
            config.clone(),
            first.clone(),
        );
        tasks.push(thread::spawn(move || -> io::Result<()> {
            let mut referer = first;
            let mut cookie = String::new();
            for _ in 0..config.times.choose()? {
                if !cookie.is_empty() {
                    cookie.push_str("; ");
                }
                cookie.push_str(&padding_cookie(config.padding)?);
                referer = fetch(&connection, &name, &referer, &paths, &cookie, true)?;
                thread::sleep(Duration::from_millis(config.interval.choose()?));
            }
            Ok(())
        }));
    }
    for task in tasks {
        let _ = task.join().map_err(|_| io::Error::other("spider worker"))?;
    }
    Ok(())
}

fn choose_path(paths: &Paths) -> io::Result<String> {
    let paths = paths.lock().map_err(|_| io::Error::other("spider paths"))?;
    let index = Range(0, paths.len() as u64).choose()? as usize;
    Ok(paths
        .iter()
        .nth(index)
        .cloned()
        .unwrap_or_else(|| "/".into()))
}

fn padding_cookie(range: Range) -> io::Result<String> {
    let count = usize::try_from(range.choose()?).map_err(io::Error::other)?;
    Ok(format!("padding={}", "0".repeat(count)))
}

fn fetch<W: Write + Send + 'static>(
    connection: &H2Conn<W>,
    name: &str,
    referer: &str,
    paths: &Paths,
    cookie: &str,
    follow: bool,
) -> io::Result<String> {
    let prefix = format!("https://{name}");
    let mut path = if follow {
        choose_path(paths)?
    } else {
        referer.strip_prefix(&prefix).unwrap_or("/").to_string()
    };
    let headers = vec![
        ("user-agent", crate::raw_http::CHROME_UA), ("sec-ch-ua", crate::raw_http::CHROME_HINT),
        ("sec-ch-ua-mobile", "?0"), ("sec-ch-ua-platform", "\"Windows\""), ("dnt", "1"),
        ("accept-language", "en-US,en;q=0.9"), ("accept-encoding", "gzip"), ("cache-control", "max-age=0"), ("upgrade-insecure-requests", "1"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        ("sec-fetch-site", "none"), ("sec-fetch-mode", "navigate"), ("sec-fetch-user", "?1"),
        ("sec-fetch-dest", "document"), ("priority", "u=0, i"), ("cookie", cookie),
    ];
    let mut previous = follow.then(|| referer.to_string());
    let mut redirects = 0;
    let response = loop {
        let response = {
            let mut headers = headers.clone();
            if let Some(previous) = &previous {
                headers.push(("referer", previous));
            }
            connection.request_any_status("GET", &path, name, "https", &headers, true)?
        };
        let status = response.header(":status").unwrap_or_default();
        if !matches!(status.as_str(), "301" | "302" | "303" | "307" | "308") {
            break response;
        }
        let Some(location) = response.header("location") else {
            break response;
        };
        if redirects >= 10 {
            return Err(io::Error::other("spider redirect limit"));
        }
        let current = url::Url::parse(&format!("{prefix}{path}")).map_err(io::Error::other)?;
        let next = current.join(&location).map_err(io::Error::other)?;
        if next.origin() != current.origin() {
            return Err(io::Error::other(
                "spider redirect changes authenticated origin",
            ));
        }
        previous = Some(current.to_string());
        path = format!(
            "{}{}",
            next.path(),
            next.query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        redirects += 1;
        drop(response);
    };
    let compressed = response
        .header("content-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("gzip"));
    let mut body = Vec::new();
    response.take(8 * 1024 * 1024 + 1).read_to_end(&mut body)?;
    if compressed {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(body.as_slice())
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut decoded)?;
        body = decoded;
    }
    if body.len() > 8 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spider response exceeds limit",
        ));
    }
    let body = String::from_utf8_lossy(&body);
    let mut paths = paths.lock().map_err(|_| io::Error::other("spider paths"))?;
    for href in HREF.captures_iter(&body) {
        let path = href[1].strip_prefix(&prefix).unwrap_or(&href[1]);
        if path.starts_with('/') && !path.contains('.') && paths.len() < 4096 {
            paths.insert(path.into());
        }
    }
    Ok(format!("{prefix}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spider_controls_are_removed_and_requests_share_one_http2_connection() {
        let config =
            RealitySpiderConfig::parse("/start?z=last&p=8&c=2&t=2&i=0&r=7&x=first").unwrap();
        assert_eq!(config.path, "/start?x=first&z=last");
        assert_eq!(config.return_delay().unwrap(), Duration::from_millis(7));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, crate::HTTP2_PREFACE);
            let connection = H2Conn::serve(socket.try_clone().unwrap(), socket).unwrap();
            let mut repeated_cookies = 0;
            for index in 0..6 {
                let response = connection.accept().unwrap();
                let cookie = response.header("cookie").unwrap();
                assert!(cookie
                    .split("; ")
                    .all(|cookie| cookie == "padding=00000000"));
                repeated_cookies += usize::from(cookie.split("; ").count() == 2);
                assert_eq!(
                    response.header(":authority").as_deref(),
                    Some("spider.test")
                );
                if index > 0 {
                    assert!(response
                        .header("referer")
                        .unwrap()
                        .starts_with("https://spider.test/"));
                }
                if index == 0 {
                    response
                        .reply_with(302, &[("location", "/redirect")], true)
                        .unwrap();
                    continue;
                }
                response
                    .reply_with(200, &[("content-encoding", "gzip")], false)
                    .unwrap();
                let mut gzip =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                gzip.write_all(b"<a href=\"/next\">next</a><a href=\"/not.html\">ignored</a>")
                    .unwrap();
                response.finish(&gzip.finish().unwrap()).unwrap();
            }
            assert_eq!(repeated_cookies, 2);
        });
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let connection = Arc::new(H2Conn::connect(socket.try_clone().unwrap(), socket).unwrap());
        crawl(connection, "spider.test", &config).unwrap();
        task.join().unwrap();
        let hosts = PATHS.lock().unwrap();
        let paths = hosts["spider.test"].lock().unwrap();
        assert!(paths.contains("/next"));
        assert!(!paths.contains("/not.html"));
    }
}
