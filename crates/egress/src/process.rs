//! 本机 Socket 源端口到进程名与进程路径的实时反查（支持 `PROCESS-NAME` 与 `PROCESS-PATH` 路由规则）。

use kerlico_config::Network;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

type ProcessEntry = (Instant, Option<(String, String)>);

static PROCESS_CACHE: LazyLock<Mutex<HashMap<(u16, bool), ProcessEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(target_os = "linux")]
struct InodeIndex {
    scanned_at: Option<Instant>,
    inode_to_pid: HashMap<u64, u32>,
    pid_info: HashMap<u32, (String, String)>,
}

#[cfg(target_os = "linux")]
static INODE_INDEX: LazyLock<Mutex<InodeIndex>> = LazyLock::new(|| {
    Mutex::new(InodeIndex {
        scanned_at: None,
        inode_to_pid: HashMap::new(),
        pid_info: HashMap::new(),
    })
});

/// 根据入站观测到的源地址与协议反查本机进程 `(process_name, process_path)`。
pub fn resolve_local_process(
    source_addr: Option<SocketAddr>,
    network: Network,
) -> Option<(String, String)> {
    let addr = source_addr?;
    let port = addr.port();
    if port == 0 {
        return None;
    }
    let is_tcp = matches!(network, Network::Tcp);
    let now = Instant::now();
    if let Ok(mut cache) = PROCESS_CACHE.lock() {
        if cache.len() > 2048 {
            cache.retain(|_, (ts, _)| now.duration_since(*ts) < Duration::from_secs(5));
        }
        if let Some((ts, cached)) = cache.get(&(port, is_tcp))
            && now.duration_since(*ts) < Duration::from_secs(2)
        {
            return cached.clone();
        }
    }
    let resolved = lookup_process_by_port(addr, is_tcp);
    if let Ok(mut cache) = PROCESS_CACHE.lock() {
        cache.insert((port, is_tcp), (now, resolved.clone()));
    }
    resolved
}

fn lookup_process_by_port(local_addr: SocketAddr, is_tcp: bool) -> Option<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        let local_port = local_addr.port();
        let tables = match (is_tcp, local_addr.is_ipv6()) {
            (true, false) => ["/proc/net/tcp", "/proc/net/tcp6"],
            (true, true) => ["/proc/net/tcp6", "/proc/net/tcp"],
            (false, false) => ["/proc/net/udp", "/proc/net/udp6"],
            (false, true) => ["/proc/net/udp6", "/proc/net/udp"],
        };
        let mut target_inode = None;
        for table_path in tables {
            if let Ok(content) = std::fs::read_to_string(table_path)
                && let Some(inode) = parse_proc_net_inode(&content, local_port)
            {
                target_inode = Some(inode);
                break;
            }
        }
        let inode = target_inode?;
        lookup_process_by_inode(inode)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (local_addr, is_tcp);
        None
    }
}

#[cfg(target_os = "linux")]
fn lookup_process_by_inode(inode: u64) -> Option<(String, String)> {
    let mut index = INODE_INDEX.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    // 1. 优先命中已缓存的 inode -> pid 映射
    if let Some(&pid) = index.inode_to_pid.get(&inode)
        && let Some(info) = resolve_pid_info(&mut index.pid_info, pid)
    {
        return Some(info);
    }
    // 2. 先检查最近已知持有 socket 的进程（如压测 worker），避免全量遍历 /proc
    if index.inode_to_pid.len() > 4096 {
        index.inode_to_pid.clear();
    }
    let known_pids: Vec<u32> = index.pid_info.keys().copied().collect();
    for pid in known_pids {
        let dir = std::path::PathBuf::from(format!("/proc/{pid}"));
        if scan_pid_inodes(&dir, pid, &mut index.inode_to_pid) {
            if index.inode_to_pid.get(&inode) == Some(&pid) {
                return resolve_pid_info(&mut index.pid_info, pid);
            }
        } else {
            index.pid_info.remove(&pid);
        }
    }
    // 3. 对全量 /proc 扫描做节流（短命新进程至多每 200ms 扫一次全表）
    if index
        .scanned_at
        .is_some_and(|last| now.duration_since(last) < Duration::from_millis(200))
    {
        return None;
    }
    index.scanned_at = Some(now);
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if index.pid_info.contains_key(&pid) {
            continue;
        }
        let path = entry.path();
        if scan_pid_inodes(&path, pid, &mut index.inode_to_pid)
            && index.inode_to_pid.get(&inode) == Some(&pid)
        {
            return resolve_pid_info(&mut index.pid_info, pid);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn scan_pid_inodes(
    proc_path_dir: &std::path::Path,
    pid: u32,
    inode_to_pid: &mut HashMap<u64, u32>,
) -> bool {
    let Ok(fd_dir) = std::fs::read_dir(proc_path_dir.join("fd")) else {
        return false;
    };
    for fd_entry in fd_dir.flatten() {
        let Ok(link) = std::fs::read_link(fd_entry.path()) else {
            continue;
        };
        let Some(link_str) = link.to_str() else {
            continue;
        };
        let inode_str = link_str
            .strip_prefix("socket:[")
            .and_then(|s| s.strip_suffix(']'))
            .or_else(|| link_str.strip_prefix("[0000]:"));
        if let Some(s) = inode_str
            && let Ok(ino) = s.parse::<u64>()
            && ino > 0
        {
            inode_to_pid.insert(ino, pid);
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn resolve_pid_info(
    pid_info: &mut HashMap<u32, (String, String)>,
    pid: u32,
) -> Option<(String, String)> {
    if let Some(info) = pid_info.get(&pid) {
        return Some(info.clone());
    }
    let dir = std::path::PathBuf::from(format!("/proc/{pid}"));
    let proc_path = std::fs::read_link(dir.join("exe"))
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_default();
    let proc_name = std::fs::read_to_string(dir.join("comm"))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            proc_path
                .rsplit(['/', '\\'])
                .next()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })?;
    let info = (proc_name, proc_path);
    pid_info.insert(pid, info.clone());
    Some(info)
}

/// 从 `/proc/net/{tcp,tcp6,udp,udp6}` 文本中按本机端口提取非零 socket inode。
pub fn parse_proc_net_inode(table_text: &str, local_port: u16) -> Option<u64> {
    let port_suffix = format!(":{local_port:04X}");
    for line in table_text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _sl = cols.next()?;
        let local_addr = cols.next()?;
        if local_addr.len() < port_suffix.len()
            || !local_addr[local_addr.len() - port_suffix.len()..]
                .eq_ignore_ascii_case(&port_suffix)
        {
            continue;
        }
        // 跳过 rem_address(2), st(3), tx_queue:rx_queue(4), tr:tm->when(5), retrnsmt(6), uid(7), timeout(8)
        let inode_str = cols.nth(7)?;
        if let Ok(inode) = inode_str.parse::<u64>()
            && inode > 0
        {
            return Some(inode);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_net_inode_extracts_matching_socket_inode() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:D431 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 482910 1 0000000000000000 20 4 30 10 -1
";
        assert_eq!(parse_proc_net_inode(sample, 0xD431), Some(482910));
        assert_eq!(parse_proc_net_inode(sample, 8080), None);
    }
}
