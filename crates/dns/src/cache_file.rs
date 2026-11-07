//! `cache_file` 的唯一持有者：同一路径下 Fake-IP 映射与策略组选择各占一个顶层分区。
//!
//! 进程内按路径缓存整份文档，所有写入在同一把锁下更新分区并原子替换文件，一方写入不会覆盖另一方。

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

pub const FAKEIP: &str = "fakeip";
pub const SELECTED: &str = "selected";

type SectionMap = BTreeMap<String, Vec<u8>>;
type Documents = HashMap<PathBuf, SectionMap>;

fn with_document<R>(path: &Path, f: impl FnOnce(&mut SectionMap) -> R) -> R {
    static DOCUMENTS: OnceLock<Mutex<Documents>> = OnceLock::new();
    let mut docs = DOCUMENTS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let doc = docs.entry(path.to_path_buf()).or_insert_with(|| {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Map<String, Value>>(&bytes).ok())
            .map(|map| {
                map.into_iter()
                    .filter_map(|(k, v)| serde_json::to_vec(&v).ok().map(|b| (k, b)))
                    .collect()
            })
            .unwrap_or_default()
    });
    f(doc)
}

pub fn load<T: DeserializeOwned>(path: &Path, section: &str) -> Option<T> {
    with_document(path, |doc| {
        doc.get(section)
            .and_then(|bytes| serde_json::from_slice(bytes).ok())
    })
}

pub fn store<T: Serialize>(path: &Path, section: &str, value: &T) -> io::Result<()> {
    let section_bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    with_document(path, |doc| {
        doc.insert(section.to_owned(), section_bytes);
        let cap = doc.values().map(|v| v.len() + 32).sum::<usize>() + 2;
        let mut bytes = Vec::with_capacity(cap);
        bytes.push(b'{');
        for (i, (k, v)) in doc.iter().enumerate() {
            if i > 0 {
                bytes.push(b',');
            }
            serde_json::to_writer(&mut bytes, k).map_err(io::Error::other)?;
            bytes.push(b':');
            bytes.extend_from_slice(v);
        }
        bytes.push(b'}');
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeIpPool;
    use std::collections::BTreeMap;

    fn sections(path: &Path) -> Map<String, Value> {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn fakeip_and_selected_share_one_file_without_clobbering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let pool = FakeIpPool::new(
            Some("198.18.0.0/15"),
            None,
            16,
            1,
            Vec::new(),
            Some(path.clone()),
        )
        .unwrap();
        let first = pool.allocate_v4("a.example").unwrap();
        let selected = BTreeMap::from([("proxy".to_owned(), "node-b".to_owned())]);
        store(&path, SELECTED, &selected).unwrap();
        pool.allocate_v4("b.example").unwrap();
        drop(pool);

        let doc = sections(&path);
        assert_eq!(doc[SELECTED], serde_json::json!({"proxy": "node-b"}));
        assert!(doc[FAKEIP]["v4"]["a.example"].is_string());
        assert!(doc[FAKEIP]["v4"]["b.example"].is_string());

        store(&path, SELECTED, &BTreeMap::<String, String>::new()).unwrap();
        let reopened = FakeIpPool::new(
            Some("198.18.0.0/15"),
            None,
            16,
            1,
            Vec::new(),
            Some(path.clone()),
        )
        .unwrap();
        assert_eq!(reopened.allocate_v4("a.example").unwrap(), first);
    }
}
