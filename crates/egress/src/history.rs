//! 按运行绝对水位提交历史；数据库只保存结构化元数据，不保存协议凭据或业务载荷。

use crate::{FlowEnd, FlowRecord, Telemetry, Usage, UsageSnapshot};
use kerlico_core::{Error, NodeId, OutId, Result, Source, TargetBind, UserId};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    net::IpAddr,
    path::{Component, Path},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnlineSource {
    pub user: Option<String>,
    pub node: String,
    pub address: Option<IpAddr>,
    pub active_flows: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredUsage {
    pub run: String,
    pub dimension: String,
    pub key: String,
    pub usage: Usage,
}
#[derive(Clone, Debug)]
pub enum HistoryScope {
    Engine,
    User(UserId),
    Node(NodeId),
    Outbound(OutId),
}
impl HistoryScope {
    fn parameters(&self) -> (&'static str, String) {
        match self {
            Self::Engine => ("engine", "engine".into()),
            Self::User(user) => ("user", user.to_string()),
            Self::Node(node) => ("node", node.to_string()),
            Self::Outbound(outbound) => ("outbound", outbound.to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredFlow {
    pub run: String,
    pub sequence: u64,
    pub node: String,
    pub user: Option<String>,
    pub credential_epoch: Option<u64>,
    pub outbound: String,
    pub original: Option<String>,
    pub original_host: Option<String>,
    pub observed_source: Option<String>,
    pub observed_target: Option<String>,
    pub target_bind: Option<String>,
    pub kind: String,
    pub stage: String,
    pub end: Option<String>,
    pub started_ms: u64,
    pub ended_ms: Option<u64>,
    pub usage: Usage,
    pub saturated: bool,
    pub datagram_targets: serde_json::Value,
    pub omitted_target_events: u64,
}
impl StoredFlow {
    fn from_record(record: &FlowRecord, mask_source: bool) -> Self {
        let observed_source = record.observed_source.map(|address| {
            if !mask_source {
                return address.to_string();
            }
            match address.ip() {
                IpAddr::V4(ip) => {
                    let mut bytes = ip.octets();
                    bytes[3] = 0;
                    format!("{}/24", std::net::Ipv4Addr::from(bytes))
                }
                IpAddr::V6(ip) => {
                    let mut bytes = ip.octets();
                    bytes[6..].fill(0);
                    format!("{}/48", std::net::Ipv6Addr::from(bytes))
                }
            }
        });
        Self {
            run: record.id.run.to_string(), sequence: record.id.sequence,
            node: record.source.node().to_string(), user: record.source.user().map(|user| user.to_string()),
            credential_epoch: match record.source { Source::User { credential_epoch, .. } => Some(credential_epoch), Source::Local { .. } => None },
            outbound: record.outbound.to_string(),
            original: record.original.as_ref().map(|original| original.target().to_string()),
            original_host: record.original.as_ref().map(|original| original.representation().to_string()),
            observed_source,
            observed_target: record.observed_target.as_ref().map(ToString::to_string),
            target_bind: match &record.target_bind { TargetBind::Known { endpoint, .. } => Some(endpoint.to_string()), TargetBind::Unknown => None },
            kind: match record.kind { crate::FlowKind::Tcp => "tcp", crate::FlowKind::FixedUdp => "fixed-udp", crate::FlowKind::UdpAssociation => "udp-association" }.into(),
            stage: match record.stage { crate::FlowStage::Opening => "opening", crate::FlowStage::LocalConnected => "local-connected", crate::FlowStage::LocalDatagramReady => "local-datagram-ready", crate::FlowStage::ProxyReady => "proxy-ready" }.into(),
            end: record.end.map(|end| match end { FlowEnd::Completed => "completed", FlowEnd::ClosedByCaller => "closed-by-caller", FlowEnd::Cancelled => "cancelled", FlowEnd::Failed => "failed", FlowEnd::Timeout => "timeout" }.into()),
            started_ms: record.started_ms, ended_ms: record.ended_ms, usage: record.usage, saturated: record.saturated,
            datagram_targets: record.datagram_targets.iter().map(|target| serde_json::json!({
                "original": target.original.to_string(), "local_target": target.local_target.as_ref().map(ToString::to_string),
                "upload_bytes": target.upload_bytes, "upload_packets": target.upload_packets, "failed_sends": target.failed_sends,
            })).collect(),
            omitted_target_events: record.omitted_target_events,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BandwidthSample {
    pub run: String,
    pub sequence: u64,
    pub sampled_ms: u64,
    pub elapsed_ms: u64,
    pub dimension: String,
    pub key: String,
    pub upload_bytes_per_second: f64,
    pub download_bytes_per_second: f64,
    pub average_upload_bytes_per_second: f64,
    pub average_download_bytes_per_second: f64,
    pub peak_upload_bytes_per_second: f64,
    pub peak_download_bytes_per_second: f64,
}

#[derive(Clone, Debug)]
pub struct HistoryQuery {
    pub user: Option<String>,
    pub node: Option<String>,
    pub outbound: Option<String>,
    pub since_ms: u64,
    pub until_ms: u64,
    pub after: i64,
    pub limit: usize,
}
impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            user: None,
            node: None,
            outbound: None,
            since_ms: 0,
            until_ms: i64::MAX as u64,
            after: 0,
            limit: 1000,
        }
    }
}
fn storage_error(_: impl std::fmt::Debug) -> Error {
    Error::Protocol("统计历史存储操作失败")
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as u64
}
fn number(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::ResourceLimit)
}
fn encoded(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(storage_error)
}
const APPLICATION_ID: i64 = 0x4b524c48;

fn private_path(path: &Path, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || directory != metadata.is_dir()
        || !directory && !metadata.is_file()
    {
        return Err(Error::Config("统计目录及文件必须为普通私有路径".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let forbidden = if directory { 0o022 } else { 0o077 };
        let owner = rustix::process::geteuid().as_raw();
        let trusted_owner = metadata.uid() == owner || directory && metadata.uid() == 0;
        if !trusted_owner || metadata.mode() & forbidden != 0 || !directory && metadata.nlink() != 1
        {
            return Err(Error::Config("统计路径权限或硬链接数量不安全".into()));
        }
    }
    Ok(())
}
fn check_sidecars(directory: &Path) -> Result<()> {
    for name in [
        "history.sqlite3-wal",
        "history.sqlite3-shm",
        "history.sqlite3-journal",
    ] {
        let path = directory.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => private_path(&path, false)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn check_directory(path: &Path, create: bool) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(Error::Config("统计目录不能为空或包含上级路径".into()));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = std::path::PathBuf::new();
    for part in absolute.components() {
        current.push(part);
        if !current.try_exists()? && create {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&current)?;
        }
        private_path(&current, true)?;
    }
    Ok(())
}
fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            private_path(path, false)?;
            OpenOptions::new().read(true).write(true).open(path)?
        }
        Err(error) => return Err(error.into()),
    };
    private_path(path, false)?;
    Ok(file)
}

pub struct HistoryWriter {
    connection: Connection,
    _lease: File,
    telemetry: Telemetry,
    previous: BTreeMap<(String, String), Usage>,
    peaks: BTreeMap<(String, String), (f64, f64)>,
    started: Instant,
    sampled: Instant,
    sequence: u64,
    mask_source: bool,
    access_records: bool,
    retention: Duration,
}
#[cfg(not(test))]
fn schema_statement_done(_: usize) {}
#[cfg(test)]
fn schema_statement_done(step: usize) {
    if std::env::var("KERLICO_HISTORY_CRASH_AT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        == Some(step)
    {
        std::process::exit(86);
    }
}
fn initialize_schema(connection: &mut Connection) -> Result<()> {
    connection
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .map_err(storage_error)?;
    let transaction = connection.transaction().map_err(storage_error)?;
    for (step, statement) in [
        "CREATE TABLE IF NOT EXISTS usage(run TEXT NOT NULL, dimension TEXT NOT NULL, key TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run,dimension,key))",
        "CREATE TABLE IF NOT EXISTS flows(cursor INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT NOT NULL, sequence INTEGER NOT NULL, started_ms INTEGER NOT NULL, ended_ms INTEGER, user TEXT, node TEXT NOT NULL, outbound TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(run,sequence))",
        "CREATE INDEX IF NOT EXISTS flows_started ON flows(started_ms)",
        "CREATE TABLE IF NOT EXISTS bandwidth(cursor INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT NOT NULL, sequence INTEGER NOT NULL, sampled_ms INTEGER NOT NULL, dimension TEXT NOT NULL, key TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(run,sequence,dimension,key))",
        "CREATE INDEX IF NOT EXISTS bandwidth_sampled ON bandwidth(sampled_ms)",
        "PRAGMA user_version=1",
    ].iter().enumerate() {
        transaction.execute_batch(statement).map_err(storage_error)?;
        schema_statement_done(step);
    }
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(storage_error)?;
    transaction.commit().map_err(storage_error)
}
impl HistoryWriter {
    /// 必须在启动业务前调用；同目录只准一个写者，查询使用独立只读连接。
    pub fn open(
        directory: &Path,
        telemetry: Telemetry,
        mask_source: bool,
        access_records: bool,
        retention: Duration,
    ) -> Result<Self> {
        check_directory(directory, true)?;
        let lease = private_file(&directory.join("writer.lock"))?;
        lease
            .try_lock()
            .map_err(|_| Error::Config("统计目录已有写者".into()))?;
        let database = directory.join("history.sqlite3");
        let _file = private_file(&database)?;
        check_sidecars(directory)?;
        let mut connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage_error)?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(storage_error)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(storage_error)?;
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(storage_error)?;
        if application != APPLICATION_ID {
            let tables: i64 = connection
                .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
                .map_err(storage_error)?;
            if application != 0 || version != 0 || tables != 0 {
                return Err(Error::Config("统计目录包含其他应用数据库".into()));
            }
        }
        if version > 1 {
            return Err(Error::Config("统计历史版本高于当前程序".into()));
        }
        initialize_schema(&mut connection)?;
        telemetry.enable_history()?;
        let started = Instant::now();
        Ok(Self {
            connection,
            _lease: lease,
            telemetry,
            previous: BTreeMap::new(),
            peaks: BTreeMap::new(),
            started,
            sampled: started,
            sequence: 0,
            mask_source,
            access_records,
            retention,
        })
    }
    /// 同一次快照的累计用量和访问记录在一个事务内替换；失败后可安全重试。
    pub fn checkpoint(&mut self) -> Result<()> {
        let (snapshot, records, saved) = self.telemetry.history_snapshot()?;
        let now = Instant::now();
        let wall = now_ms();
        let elapsed = now.duration_since(self.sampled).as_secs_f64().max(0.001);
        let age = now.duration_since(self.started).as_secs_f64().max(0.001);
        let run = self.telemetry.run_id().to_string();
        let rows = usage_rows(&run, snapshot);
        let next = self.sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
        let mut peaks = self.peaks.clone();
        let transaction = self.connection.transaction().map_err(storage_error)?;
        for row in &rows {
            let key = (row.dimension.clone(), row.key.clone());
            let previous = self.previous.get(&key).copied().unwrap_or_default();
            let up = row.usage.upload_bytes.saturating_sub(previous.upload_bytes) as f64 / elapsed;
            let down = row
                .usage
                .download_bytes
                .saturating_sub(previous.download_bytes) as f64
                / elapsed;
            let peak = peaks.entry(key).or_default();
            peak.0 = peak.0.max(up);
            peak.1 = peak.1.max(down);
            let sample = BandwidthSample {
                run: run.clone(),
                sequence: next,
                sampled_ms: wall,
                elapsed_ms: now
                    .duration_since(self.sampled)
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
                dimension: row.dimension.clone(),
                key: row.key.clone(),
                upload_bytes_per_second: up,
                download_bytes_per_second: down,
                average_upload_bytes_per_second: row.usage.upload_bytes as f64 / age,
                average_download_bytes_per_second: row.usage.download_bytes as f64 / age,
                peak_upload_bytes_per_second: peak.0,
                peak_download_bytes_per_second: peak.1,
            };
            transaction.execute("INSERT INTO usage VALUES(?1,?2,?3,?4) ON CONFLICT(run,dimension,key) DO UPDATE SET payload=excluded.payload", params![run, row.dimension, row.key, encoded(row)?]).map_err(storage_error)?;
            transaction.execute("INSERT INTO bandwidth(run,sequence,sampled_ms,dimension,key,payload) VALUES(?1,?2,?3,?4,?5,?6)", params![run, number(next)?, number(wall)?, row.dimension, row.key, encoded(&sample)?]).map_err(storage_error)?;
        }
        if self.access_records {
            for record in records {
                let flow = StoredFlow::from_record(&record, self.mask_source);
                transaction.execute("INSERT INTO flows(run,sequence,started_ms,ended_ms,user,node,outbound,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(run,sequence) DO UPDATE SET ended_ms=excluded.ended_ms,payload=excluded.payload", params![run, number(flow.sequence)?, number(flow.started_ms)?, flow.ended_ms.map(number).transpose()?, flow.user, flow.node, flow.outbound, encoded(&flow)?]).map_err(storage_error)?;
            }
        }
        let cutoff = wall.saturating_sub(self.retention.as_millis().min(u64::MAX as u128) as u64);
        transaction.execute("DELETE FROM flows WHERE ended_ms < ?1 OR (ended_ms IS NULL AND started_ms < ?1 AND run != ?2)", params![number(cutoff)?, run]).map_err(storage_error)?;
        transaction
            .execute(
                "DELETE FROM bandwidth WHERE sampled_ms < ?1",
                [number(cutoff)?],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        self.telemetry.acknowledge_history(&saved)?;
        self.previous = rows
            .into_iter()
            .map(|row| ((row.dimension, row.key), row.usage))
            .collect();
        self.peaks = peaks;
        self.sequence = next;
        self.sampled = now;
        Ok(())
    }
}
fn usage_rows(run: &str, snapshot: UsageSnapshot) -> Vec<StoredUsage> {
    let mut rows = vec![StoredUsage {
        run: run.into(),
        dimension: "engine".into(),
        key: "engine".into(),
        usage: snapshot.engine,
    }];
    rows.extend(snapshot.users.into_iter().map(|(key, usage)| StoredUsage {
        run: run.into(),
        dimension: "user".into(),
        key: key.to_string(),
        usage,
    }));
    rows.extend(snapshot.nodes.into_iter().map(|(key, usage)| StoredUsage {
        run: run.into(),
        dimension: "node".into(),
        key: key.to_string(),
        usage,
    }));
    rows.extend(
        snapshot
            .outbounds
            .into_iter()
            .map(|(key, usage)| StoredUsage {
                run: run.into(),
                dimension: "outbound".into(),
                key: key.to_string(),
                usage,
            }),
    );
    rows
}

pub struct HistoryReader(Connection);
impl HistoryReader {
    pub fn open(directory: &Path) -> Result<Self> {
        check_directory(directory, false)?;
        let path = directory.join("history.sqlite3");
        private_path(&path, false)?;
        check_sidecars(directory)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(storage_error)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(storage_error)?;
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(storage_error)?;
        if application != APPLICATION_ID {
            return Err(Error::Config("数据库不属于统计历史".into()));
        }
        if version != 1 {
            return Err(Error::Config("统计历史版本不支持".into()));
        }
        Ok(Self(connection))
    }
    /// 累加各运行的绝对水位，四个投影独立返回，不能相互求和。
    pub fn usage(&self) -> Result<Vec<StoredUsage>> {
        self.usage_in(None)
    }
    pub fn usage_in(&self, scope: Option<&HistoryScope>) -> Result<Vec<StoredUsage>> {
        let projection = scope.map(HistoryScope::parameters);
        let mut statement = self
            .0
            .prepare("SELECT payload FROM usage WHERE (?1 IS NULL OR dimension=?1) AND (?2 IS NULL OR key=?2) ORDER BY run,dimension,key")
            .map_err(storage_error)?;
        let mut totals: BTreeMap<(String, String), Usage> = BTreeMap::new();
        for row in statement
            .query_map(
                params![
                    projection.as_ref().map(|row| row.0),
                    projection.as_ref().map(|row| row.1.as_str())
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(storage_error)?
        {
            let value: StoredUsage =
                serde_json::from_str(&row.map_err(storage_error)?).map_err(storage_error)?;
            totals
                .entry((value.dimension, value.key))
                .or_default()
                .add(value.usage);
        }
        Ok(totals
            .into_iter()
            .map(|((dimension, key), usage)| StoredUsage {
                run: "all".into(),
                dimension,
                key,
                usage,
            })
            .collect())
    }
    /// 返回 rowid 游标，读取时不创建库、不清理历史、不重置计量基线。
    pub fn flows(&self, query: &HistoryQuery) -> Result<Vec<(i64, StoredFlow)>> {
        if query.limit == 0
            || query.limit > 4096
            || query.after < 0
            || query.since_ms > query.until_ms
        {
            return Err(Error::ResourceLimit);
        }
        let mut statement = self.0.prepare("SELECT rowid,payload FROM flows WHERE rowid>?1 AND started_ms>=?2 AND started_ms<=?3 AND (?4 IS NULL OR user=?4) AND (?5 IS NULL OR node=?5) AND (?6 IS NULL OR outbound=?6) ORDER BY rowid LIMIT ?7").map_err(storage_error)?;
        let rows = statement
            .query_map(
                params![
                    query.after,
                    number(query.since_ms)?,
                    number(query.until_ms)?,
                    query.user,
                    query.node,
                    query.outbound,
                    query.limit as i64
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(storage_error)?;
        rows.map(|row| {
            let (cursor, payload) = row.map_err(storage_error)?;
            Ok((
                cursor,
                serde_json::from_str(&payload).map_err(storage_error)?,
            ))
        })
        .collect()
    }
    pub fn bandwidth(
        &self,
        since_ms: u64,
        after: i64,
        limit: usize,
    ) -> Result<Vec<(i64, BandwidthSample)>> {
        self.bandwidth_in(since_ms, after, limit, None)
    }
    pub fn bandwidth_in(
        &self,
        since_ms: u64,
        after: i64,
        limit: usize,
        scope: Option<&HistoryScope>,
    ) -> Result<Vec<(i64, BandwidthSample)>> {
        if limit == 0 || limit > 4096 || after < 0 {
            return Err(Error::ResourceLimit);
        }
        let projection = scope.map(HistoryScope::parameters);
        let mut statement = self.0.prepare("SELECT rowid,payload FROM bandwidth WHERE rowid>?1 AND sampled_ms>=?2 AND (?4 IS NULL OR dimension=?4) AND (?5 IS NULL OR key=?5) ORDER BY rowid LIMIT ?3").map_err(storage_error)?;
        let rows = statement
            .query_map(
                params![
                    after,
                    number(since_ms)?,
                    limit as i64,
                    projection.as_ref().map(|row| row.0),
                    projection.as_ref().map(|row| row.1.as_str())
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(storage_error)?;
        rows.map(|row| {
            let (cursor, payload) = row.map_err(storage_error)?;
            Ok((
                cursor,
                serde_json::from_str(&payload).map_err(storage_error)?,
            ))
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initialization_crash_child() {
        if let Some(directory) = std::env::var_os("KERLICO_HISTORY_CRASH_DIRECTORY") {
            let _ = HistoryWriter::open(
                Path::new(&directory),
                Telemetry::new(4),
                true,
                true,
                Duration::from_secs(60),
            );
            panic!("初始化故障注入未触发");
        }
    }

    #[test]
    fn initialization_survives_process_exit_between_schema_statements() {
        for step in 0..6 {
            let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "history::tests::initialization_crash_child"])
                .env("KERLICO_HISTORY_CRASH_DIRECTORY", directory.path())
                .env("KERLICO_HISTORY_CRASH_AT", step.to_string())
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(86), "步骤{step}未到真实中断点");
            let mut writer = HistoryWriter::open(
                directory.path(),
                Telemetry::new(4),
                true,
                true,
                Duration::from_secs(60),
            )
            .unwrap();
            writer.checkpoint().unwrap();
            assert_eq!(
                HistoryReader::open(directory.path())
                    .unwrap()
                    .usage()
                    .unwrap()[0]
                    .usage,
                Usage::default()
            );
        }
    }

    #[test]
    fn exclusive_writer_failed_commit_retry_and_read_only_query() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let telemetry = Telemetry::new(4);
        let mut writer = HistoryWriter::open(
            directory.path(),
            telemetry.clone(),
            true,
            true,
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(
            HistoryWriter::open(
                directory.path(),
                Telemetry::new(4),
                true,
                true,
                Duration::from_secs(60)
            )
            .is_err()
        );
        writer
            .connection
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
        assert!(writer.checkpoint().is_err());
        writer
            .connection
            .execute_batch("PRAGMA query_only=OFF")
            .unwrap();
        writer.checkpoint().unwrap();
        writer.checkpoint().unwrap();
        let reader = HistoryReader::open(directory.path()).unwrap();
        assert_eq!(reader.usage().unwrap().len(), 1);
        assert_eq!(reader.usage().unwrap()[0].usage, Usage::default());
        assert_eq!(reader.bandwidth(0, 0, 10).unwrap().len(), 2);
        drop(writer);
        let mut restarted = HistoryWriter::open(
            directory.path(),
            Telemetry::new(4),
            true,
            true,
            Duration::from_secs(60),
        )
        .unwrap();
        restarted.checkpoint().unwrap();
        assert_eq!(reader.usage().unwrap()[0].usage, Usage::default());
        assert_eq!(reader.bandwidth(0, 0, 10).unwrap().len(), 3);
    }

    #[test]
    fn untrusted_storage_and_linked_database_are_rejected_before_write() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            let unsafe_directory = directory.path().join("unsafe");
            std::fs::create_dir(&unsafe_directory).unwrap();
            std::fs::set_permissions(&unsafe_directory, std::fs::Permissions::from_mode(0o777))
                .unwrap();
            assert!(
                HistoryWriter::open(
                    &unsafe_directory.join("new"),
                    Telemetry::new(4),
                    true,
                    true,
                    Duration::from_secs(60)
                )
                .is_err()
            );
            assert!(!unsafe_directory.join("new").exists());
            let outside = directory.path().join("outside");
            std::fs::write(&outside, b"unchanged").unwrap();
            symlink(&outside, directory.path().join("history.sqlite3")).unwrap();
            assert!(
                HistoryWriter::open(
                    directory.path(),
                    Telemetry::new(4),
                    true,
                    true,
                    Duration::from_secs(60)
                )
                .is_err()
            );
            assert_eq!(std::fs::read(outside).unwrap(), b"unchanged");
        }
        assert!(
            HistoryWriter::open(
                &directory.path().join("../escape"),
                Telemetry::new(4),
                true,
                true,
                Duration::from_secs(60)
            )
            .is_err()
        );
    }

    #[test]
    fn foreign_database_is_rejected_without_modification() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let database = directory.path().join("history.sqlite3");
        drop(private_file(&database).unwrap());
        let foreign = Connection::open(&database).unwrap();
        foreign
            .execute_batch("CREATE TABLE other(value TEXT); INSERT INTO other VALUES('preserve');")
            .unwrap();
        drop(foreign);
        let before = std::fs::read(&database).unwrap();
        assert!(
            HistoryWriter::open(
                directory.path(),
                Telemetry::new(4),
                true,
                true,
                Duration::from_secs(60)
            )
            .is_err()
        );
        assert_eq!(std::fs::read(database).unwrap(), before);
    }
}
