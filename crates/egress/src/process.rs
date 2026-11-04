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
        if cache.len() > 1024 {
            cache.retain(|_, (ts, _)| now.duration_since(*ts) < Duration::from_secs(5));
        }
        if let Some((ts, cached)) = cache.get(&(port, is_tcp))
            && now.duration_since(*ts) < Duration::from_secs(2)
        {
            return cached.clone();
        }
    }
    let resolved = lookup_process_by_port(port, is_tcp);
    if let Ok(mut cache) = PROCESS_CACHE.lock() {
        cache.insert((port, is_tcp), (now, resolved.clone()));
    }
    resolved
}

fn lookup_process_by_port(local_port: u16, is_tcp: bool) -> Option<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        let tables = if is_tcp {
            ["/proc/net/tcp", "/proc/net/tcp6"]
        } else {
            ["/proc/net/udp", "/proc/net/udp6"]
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
        let socket_tag_1 = format!("socket:[{inode}]");
        let socket_tag_2 = format!("[0000]:{inode}");
        // Fast path: check current process first (/proc/self/fd)
        if let Some(found) = check_proc_entry(
            std::path::Path::new("/proc/self"),
            &socket_tag_1,
            &socket_tag_2,
        ) {
            return Some(found);
        }
        let proc_dir = std::fs::read_dir("/proc").ok()?;
        for entry in proc_dir.flatten() {
            let file_name = entry.file_name();
            let Some(pid_str) = file_name.to_str() else {
                continue;
            };
            if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Some(found) = check_proc_entry(&entry.path(), &socket_tag_1, &socket_tag_2) {
                return Some(found);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (local_port, is_tcp);
        None
    }
}

#[cfg(target_os = "linux")]
fn check_proc_entry(
    proc_path_dir: &std::path::Path,
    socket_tag_1: &str,
    socket_tag_2: &str,
) -> Option<(String, String)> {
    let fd_dir = std::fs::read_dir(proc_path_dir.join("fd")).ok()?;
    for fd_entry in fd_dir.flatten() {
        let Ok(link) = std::fs::read_link(fd_entry.path()) else {
            continue;
        };
        let Some(link_str) = link.to_str() else {
            continue;
        };
        if link_str == socket_tag_1 || link_str == socket_tag_2 {
            let proc_path = std::fs::read_link(proc_path_dir.join("exe"))
                .ok()
                .and_then(|p| p.to_str().map(str::to_owned))
                .unwrap_or_default();
            let proc_name = std::fs::read_to_string(proc_path_dir.join("comm"))
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
            return Some((proc_name, proc_path));
        }
    }
    None
}

/// 从 `/proc/net/{tcp,tcp6,udp,udp6}` 文本中按本机端口提取非零 socket inode。
pub fn parse_proc_net_inode(table_text: &str, local_port: u16) -> Option<u64> {
    let port_suffix = format!(":{local_port:04X}");
    for line in table_text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _sl = cols.next()?;
        let local_addr = cols.next()?;
        if !local_addr.to_ascii_uppercase().ends_with(&port_suffix) {
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
