use super::{Body, empty, full, http_error};
use bytes::Bytes;
use futures_util::stream;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use std::collections::VecDeque;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub(super) async fn response(root: &Path, request: &Request<()>) -> Response<Body> {
    match open(root, request).await {
        Ok(response) => response,
        Err(error) => {
            let status = match error.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => StatusCode::NOT_FOUND,
                io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            http_error(status)
        }
    }
}

async fn open(root: &Path, request: &Request<()>) -> io::Result<Response<Body>> {
    let uri = request.uri();
    let raw_path = percent_decode_str(uri.path()).decode_utf8_lossy();
    if raw_path.ends_with("/index.html") {
        return Ok(redirect("./", uri.query()));
    }
    let mut relative = PathBuf::new();
    for component in raw_path.split('/') {
        match component {
            "" | "." => {}
            ".." => { relative.pop(); }
            name => {
                let mut components = Path::new(name).components();
                if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
                    return Err(io::ErrorKind::NotFound.into());
                }
                relative.push(name);
            }
        }
    }
    let path = root.join(relative);
    let metadata = fs::metadata(&path).await?;
    let basename = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    let basename = utf8_percent_encode(basename, NON_ALPHANUMERIC);
    let path = if metadata.is_dir() {
        if !raw_path.ends_with('/') {
            return Ok(redirect(&format!("{basename}/"), uri.query()));
        }
        let index = path.join("index.html");
        if fs::metadata(&index).await.is_ok_and(|metadata| metadata.is_file()) {
            index
        } else {
            return directory(&path, metadata.modified().ok(), request).await;
        }
    } else if raw_path.ends_with('/') {
        return Ok(redirect(&format!("../{basename}"), uri.query()));
    } else {
        path
    };
    let file = File::open(&path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(io::ErrorKind::NotFound.into());
    }
    content(file, &path, metadata.len(), metadata.modified().ok(), request).await
}

fn redirect(location: &str, query: Option<&str>) -> Response<Body> {
    let location = if let Some(query) = query {
        format!("{location}?{query}")
    } else {
        location.to_owned()
    };
    Response::builder().status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location).body(empty()).unwrap()
}

async fn directory(path: &Path, modified: Option<SystemTime>, request: &Request<()>) -> io::Result<Response<Body>> {
    let mut response = with_modified(modified);
    if let Some(status) = precondition(request, modified) {
        return Ok(response.status(status).body(empty()).unwrap());
    }
    let mut entries = fs::read_dir(path).await?;
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        names.push((entry.file_name().to_string_lossy().into_owned(), entry.file_type().await?.is_dir()));
    }
    names.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut html = String::from("<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n");
    for (name, is_dir) in names {
        let suffix = if is_dir { "/" } else { "" };
        let href = utf8_percent_encode(&name, NON_ALPHANUMERIC);
        let escaped = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
            .replace('"', "&#34;").replace('\'', "&#39;");
        html.push_str(&format!("<a href=\"{href}{suffix}\">{escaped}{suffix}</a>\n"));
    }
    html.push_str("</pre>\n");
    response = response.header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_LENGTH, html.len());
    Ok(response.body(full(Bytes::from(html))).unwrap())
}

async fn content(
    mut file: File,
    path: &Path,
    len: u64,
    modified: Option<SystemTime>,
    request: &Request<()>,
) -> io::Result<Response<Body>> {
    let mut response = with_modified(modified);
    if let Some(status) = precondition(request, modified) {
        return Ok(response.status(status).body(empty()).unwrap());
    }
    let mime = media_type(&mut file, path).await?;
    let ranges = match request.headers().get(header::RANGE).and_then(|value| value.to_str().ok()) {
        Some(value) if range_allowed(request, modified) => match parse_ranges(value, len) {
            Ok(ranges) => ranges,
            Err(()) => {
                let mut response = http_error(StatusCode::RANGE_NOT_SATISFIABLE);
                response.headers_mut().insert(header::CONTENT_RANGE, format!("bytes */{len}").parse().unwrap());
                return Ok(response);
            }
        },
        _ => Vec::new(),
    };
    response = response.header(header::ACCEPT_RANGES, "bytes");
    let mut pieces = VecDeque::new();
    let (content_type, content_len) = match ranges.as_slice() {
        [] => {
            pieces.push_back(Piece::Range { start: 0, length: len });
            (mime, len)
        }
        &[(start, end)] => {
            let length = end - start + 1;
            pieces.push_back(Piece::Range { start, length });
            response = response.status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
            (mime, length)
        }
        ranges => {
            let mut boundary = [0; 30];
            getrandom::getrandom(&mut boundary).map_err(|error| io::Error::other(error.to_string()))?;
            let boundary: String = boundary.iter().map(|byte| format!("{byte:02x}")).collect();
            let mut size: u64 = 0;
            for (i, &(start, end)) in ranges.iter().enumerate() {
                let separator = if i == 0 { "" } else { "\r\n" };
                let header = format!("{separator}--{boundary}\r\nContent-Range: bytes {start}-{end}/{len}\r\nContent-Type: {mime}\r\n\r\n");
                let length = end - start + 1;
                size += header.len() as u64 + length;
                pieces.push_back(Piece::Bytes(Bytes::from(header)));
                pieces.push_back(Piece::Range { start, length });
            }
            let end = format!("\r\n--{boundary}--\r\n");
            size += end.len() as u64;
            pieces.push_back(Piece::Bytes(Bytes::from(end)));
            response = response.status(StatusCode::PARTIAL_CONTENT);
            (format!("multipart/byteranges; boundary={boundary}"), size)
        }
    };
    Ok(response.header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, content_len)
        .body(file_body(file, pieces)).unwrap())
}

fn with_modified(modified: Option<SystemTime>) -> http::response::Builder {
    let mut response = Response::builder();
    if let Some(modified) = modified.filter(|value| seconds(*value).is_some()) {
        if seconds(modified).is_some_and(|s| s < 253_402_300_800) {
            response = response.header(header::LAST_MODIFIED, httpdate::fmt_http_date(modified));
        }
    }
    response
}

fn precondition(request: &Request<()>, modified: Option<SystemTime>) -> Option<StatusCode> {
    let headers = request.headers();
    let time = modified.and_then(seconds);
    let date = |name| headers.get(name).and_then(|value| httpdate::parse_http_date(value.to_str().ok()?).ok()).and_then(seconds);
    if let Some(matching) = headers.get(header::IF_MATCH) {
        if matching != "*" {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if let (Some(time), Some(limit)) = (time, date(header::IF_UNMODIFIED_SINCE)) {
        if time > limit {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    }
    let cacheable = matches!(*request.method(), Method::GET | Method::HEAD);
    if let Some(none) = headers.get(header::IF_NONE_MATCH) {
        if none == "*" {
            return Some(if cacheable { StatusCode::NOT_MODIFIED } else { StatusCode::PRECONDITION_FAILED });
        }
    } else if cacheable {
        if let (Some(time), Some(limit)) = (time, date(header::IF_MODIFIED_SINCE)) {
            if time <= limit {
                return Some(StatusCode::NOT_MODIFIED);
            }
        }
    }
    None
}

fn range_allowed(request: &Request<()>, modified: Option<SystemTime>) -> bool {
    let Some(range) = request.headers().get(header::IF_RANGE) else { return true };
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return false;
    }
    let date = range.to_str().ok().and_then(|value| httpdate::parse_http_date(value).ok()).and_then(seconds);
    date.is_some() && date == modified.and_then(seconds)
}

fn seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().map(|duration| duration.as_secs())
}

fn parse_ranges(value: &str, len: u64) -> Result<Vec<(u64, u64)>, ()> {
    let values = value.strip_prefix("bytes=").ok_or(())?;
    let mut ranges = Vec::new();
    let mut requested = 0u64;
    let mut nonoverlap = false;
    for value in values.split(',').map(str::trim).filter(|value| !value.is_empty()) {
        let (start, end) = value.split_once('-').ok_or(())?;
        let (start, end) = if start.trim().is_empty() {
            let last = end.trim().parse::<u64>().map_err(|_| ())?;
            if last == 0 || len == 0 {
                nonoverlap = true;
                continue;
            }
            (len.saturating_sub(last), len - 1)
        } else {
            let start = start.trim().parse::<u64>().map_err(|_| ())?;
            if start >= len {
                nonoverlap = true;
                continue;
            }
            let end = if end.trim().is_empty() { len - 1 } else { end.trim().parse::<u64>().map_err(|_| ())?.min(len - 1) };
            if start > end {
                return Err(());
            }
            (start, end)
        };
        requested = requested.saturating_add(end - start + 1);
        ranges.push((start, end));
    }
    if ranges.is_empty() && nonoverlap && len != 0 {
        return Err(());
    }
    if requested > len {
        ranges.clear();
    }
    Ok(ranges)
}

async fn media_type(file: &mut File, path: &Path) -> io::Result<String> {
    if let Some(mime) = mime_guess::from_path(path).first() {
        let suffix = if mime.type_() == mime_guess::mime::TEXT && mime.get_param("charset").is_none() {
            "; charset=utf-8"
        } else {
            ""
        };
        return Ok(format!("{mime}{suffix}"));
    }
    let mut bytes = [0; 512];
    let n = file.read(&mut bytes).await?;
    Ok(sniff(&bytes[..n]).into())
}

pub(super) fn sniff(bytes: &[u8]) -> &'static str {
    let bytes = &bytes[..bytes.len().min(512)];
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if bytes.starts_with(b"%PDF-") {
        "application/pdf"
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        "image/gif"
    } else if bytes.starts_with(b"PK\x03\x04") {
        "application/zip"
    } else if bytes.iter().all(|&byte| !matches!(byte, 0..=8 | 11 | 14..=26 | 28..=31)) {
        let text = String::from_utf8_lossy(bytes).trim_start().to_ascii_lowercase();
        if text.starts_with("<!doctype html") || text.starts_with("<html") {
            "text/html; charset=utf-8"
        } else {
            "text/plain; charset=utf-8"
        }
    } else {
        "application/octet-stream"
    }
}

enum Piece {
    Bytes(Bytes),
    Range { start: u64, length: u64 },
}

fn file_body(file: File, pieces: VecDeque<Piece>) -> Body {
    let chunks = stream::try_unfold((file, pieces, 0u64), |(mut file, mut pieces, mut remaining)| async move {
        loop {
            if remaining != 0 {
                let mut data = vec![0; remaining.min(32 * 1024) as usize];
                let count = file.read(&mut data).await?;
                if count == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                remaining -= count as u64;
                data.truncate(count);
                return Ok(Some((Frame::data(Bytes::from(data)), (file, pieces, remaining))));
            }
            match pieces.pop_front() {
                Some(Piece::Bytes(bytes)) => return Ok(Some((Frame::data(bytes), (file, pieces, remaining)))),
                Some(Piece::Range { start, length }) => {
                    file.seek(io::SeekFrom::Start(start)).await?;
                    remaining = length;
                }
                None => return Ok(None),
            }
        }
    });
    StreamBody::new(chunks).boxed_unsync()
}
