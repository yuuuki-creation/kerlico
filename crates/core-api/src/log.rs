//! 进程级日志管线：按级别过滤后写入标准输出或文件，并广播给控制面 `/logs` 订阅者。
//!
//! 级别与输出跨引擎重载保留在进程内；订阅者收到全部级别的事件，各自按请求级别过滤（同 Mihomo）。

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;

const SUBSCRIBER_BACKLOG: usize = 1024;

/// 顺序同 Mihomo：`debug < info < warning < error < silent`。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

impl LogLevel {
    /// 接受 Mihomo、sing-box 与 Xray 的级别名。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "trace" | "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warning),
            "error" | "fatal" | "panic" => Some(Self::Error),
            "silent" | "none" => Some(Self::Silent),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Silent => "silent",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
            Self::Silent => "",
        }
    }

    fn from_u8(raw: u8) -> Self {
        [
            Self::Debug,
            Self::Info,
            Self::Warning,
            Self::Error,
            Self::Silent,
        ]
        .get(usize::from(raw))
        .copied()
        .unwrap_or(Self::Silent)
    }
}

#[derive(Clone, Debug)]
pub struct LogEvent {
    pub time_ms: u64,
    pub level: LogLevel,
    pub payload: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum LogTarget {
    #[default]
    Stdout,
    Stderr,
    File(PathBuf),
}

/// 进程日志输出设置；`disabled` 的配置折算为 `Silent`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogOutput {
    pub level: LogLevel,
    pub target: LogTarget,
    pub timestamp: bool,
}

impl Default for LogOutput {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            target: LogTarget::Stdout,
            timestamp: false,
        }
    }
}

enum Sink {
    Stdout,
    Stderr,
    File(File),
}

struct Hub {
    level: AtomicU8,
    output: Mutex<(Sink, bool)>,
    events: broadcast::Sender<Arc<LogEvent>>,
}

fn hub() -> &'static Hub {
    static HUB: OnceLock<Hub> = OnceLock::new();
    HUB.get_or_init(|| Hub {
        level: AtomicU8::new(LogLevel::Info as u8),
        output: Mutex::new((Sink::Stdout, false)),
        events: broadcast::channel(SUBSCRIBER_BACKLOG).0,
    })
}

/// 打开新输出后整体替换；文件无法打开时保留原输出并返回错误。
pub fn configure(output: &LogOutput) -> io::Result<()> {
    let sink = match &output.target {
        LogTarget::Stdout => Sink::Stdout,
        LogTarget::Stderr => Sink::Stderr,
        LogTarget::File(path) => {
            Sink::File(OpenOptions::new().create(true).append(true).open(path)?)
        }
    };
    let hub = hub();
    *hub.output.lock().unwrap_or_else(|e| e.into_inner()) = (sink, output.timestamp);
    hub.level.store(output.level as u8, Ordering::Relaxed);
    Ok(())
}

pub fn set_level(level: LogLevel) {
    hub().level.store(level as u8, Ordering::Relaxed);
}

pub fn level() -> LogLevel {
    LogLevel::from_u8(hub().level.load(Ordering::Relaxed))
}

/// 该级别的事件会被写出或有订阅者接收；调用方据此跳过格式化开销。
pub fn enabled(level: LogLevel) -> bool {
    level != LogLevel::Silent && (level >= self::level() || hub().events.receiver_count() > 0)
}

pub fn subscribe() -> broadcast::Receiver<Arc<LogEvent>> {
    hub().events.subscribe()
}

pub fn log(level: LogLevel, payload: impl Into<String>) {
    if !enabled(level) {
        return;
    }
    let hub = hub();
    let event = LogEvent {
        time_ms: unix_ms(),
        level,
        payload: payload.into(),
    };
    if level >= self::level() {
        let line = {
            let output = hub.output.lock().unwrap_or_else(|e| e.into_inner());
            let line = if output.1 {
                format!(
                    "{} {} {}\n",
                    rfc3339_ms(event.time_ms),
                    level.label(),
                    event.payload
                )
            } else {
                format!("{} {}\n", level.label(), event.payload)
            };
            if let Sink::File(file) = &output.0 {
                let _ = (&*file).write_all(line.as_bytes());
                None
            } else {
                Some((line, matches!(output.0, Sink::Stderr)))
            }
        };
        match line {
            Some((line, true)) => {
                let _ = io::stderr().lock().write_all(line.as_bytes());
            }
            Some((line, false)) => {
                let _ = io::stdout().lock().write_all(line.as_bytes());
            }
            None => {}
        }
    }
    let _ = hub.events.send(Arc::new(event));
}

pub fn debug(payload: impl Into<String>) {
    log(LogLevel::Debug, payload);
}

pub fn info(payload: impl Into<String>) {
    log(LogLevel::Info, payload);
}

pub fn warning(payload: impl Into<String>) {
    log(LogLevel::Warning, payload);
}

pub fn error(payload: impl Into<String>) {
    log(LogLevel::Error, payload);
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Unix 毫秒转 RFC 3339 UTC 文本（公历换算按 Howard Hinnant 的 civil_from_days）。
pub fn rfc3339_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_unix_milliseconds_in_utc() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn levels_parse_aliases_and_order_like_mihomo() {
        assert_eq!(LogLevel::parse("WARN"), Some(LogLevel::Warning));
        assert_eq!(LogLevel::parse("trace"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("none"), Some(LogLevel::Silent));
        assert_eq!(LogLevel::parse("loud"), None);
        assert!(LogLevel::Debug < LogLevel::Info && LogLevel::Error < LogLevel::Silent);
    }

    #[test]
    fn file_output_receives_lines_at_or_above_the_level_and_subscribers_get_all() {
        let path = std::env::temp_dir().join(format!("kerlico-log-{}.txt", unix_ms()));
        configure(&LogOutput {
            level: LogLevel::Warning,
            target: LogTarget::File(path.clone()),
            timestamp: true,
        })
        .unwrap();
        let mut events = subscribe();
        info("below the file level");
        warning("written to the file");
        let text = std::fs::read_to_string(&path).unwrap();
        configure(&LogOutput::default()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(!text.contains("below the file level"));
        let line = text
            .lines()
            .find(|l| l.contains("written to the file"))
            .unwrap();
        assert!(line.ends_with("Z WARN written to the file"), "{line}");
        let first = events.try_recv().unwrap();
        assert_eq!(
            (first.level, first.payload.as_str()),
            (LogLevel::Info, "below the file level")
        );
        assert_eq!(events.try_recv().unwrap().level, LogLevel::Warning);
    }
}
