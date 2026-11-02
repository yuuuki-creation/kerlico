//! 目录 fd 限定的单写者状态；秘密从不派生 Debug。
use kerlico_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub(crate) struct Record {
    pub private_key: String,
    pub response: Option<serde_json::Value>,
}
impl Drop for Record {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}
fn denied() -> Error {
    Error::Config("WARP状态目录须有可信祖先、私有权限及唯一写者".into())
}
#[cfg(unix)]
pub(crate) struct StateStore {
    directory: std::fs::File,
    _lock: std::fs::File,
}
#[cfg(not(unix))]
pub(crate) struct StateStore;
#[cfg(unix)]
impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        use rustix::{
            fs::{Mode, OFlags, mkdirat, open, openat},
            io::Errno,
            process::geteuid,
        };
        use std::{fs::File, os::unix::fs::MetadataExt, path::Component};
        if !path.is_absolute() {
            return Err(denied());
        }
        let own = geteuid().as_raw();
        let mut directory = File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| denied())?,
        );
        let names = path
            .components()
            .filter_map(|part| match part {
                Component::Normal(name) => Some(Ok(name)),
                Component::RootDir => None,
                _ => Some(Err(denied())),
            })
            .collect::<Result<Vec<_>>>()?;
        if names.is_empty() {
            return Err(denied());
        }
        for (index, name) in names.iter().enumerate() {
            let final_component = index + 1 == names.len();
            if final_component {
                match mkdirat(&directory, *name, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => (),
                    Err(_) => return Err(denied()),
                }
            }
            directory = File::from(
                openat(
                    &directory,
                    *name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| denied())?,
            );
            let metadata = directory.metadata().map_err(|_| denied())?;
            let owner = metadata.uid() == own || (!final_component && metadata.uid() == 0);
            if !metadata.is_dir()
                || !owner
                || metadata.mode() & if final_component { 0o077 } else { 0o022 } != 0
            {
                return Err(denied());
            }
        }
        let lock = File::from(
            openat(
                &directory,
                "instance.lock",
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| denied())?,
        );
        Self::check_file(&lock)?;
        lock.try_lock().map_err(|_| denied())?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
    fn check_file(file: &std::fs::File) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(|_| denied())?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(denied());
        }
        Ok(())
    }
    pub fn read(&self) -> Result<Option<Record>> {
        use rustix::{
            fs::{Mode, OFlags, openat},
            io::Errno,
        };
        use std::{fs::File, io::Read};
        let mut file = match openat(
            &self.directory,
            "identity.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(denied()),
        };
        Self::check_file(&file)?;
        if file.metadata()?.len() > 131072 {
            return Err(denied());
        }
        let mut content = zeroize::Zeroizing::new(Vec::new());
        file.read_to_end(&mut content)?;
        serde_json::from_slice(&content)
            .map(Some)
            .map_err(|_| denied())
    }
    pub fn save(&self, record: &Record) -> Result<()> {
        use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};
        use std::{fs::File, io::Write};
        let content = zeroize::Zeroizing::new(serde_json::to_vec(record).map_err(|_| denied())?);
        let temporary = format!("identity-{:016x}.pending", rand::random::<u64>());
        let mut file = File::from(
            openat(
                &self.directory,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| denied())?,
        );
        let operation = (|| -> Result<()> {
            Self::check_file(&file)?;
            file.write_all(&content)?;
            file.sync_all()?;
            // renameat 在持有的可信目录 fd 内替换，不跟随外部路径。
            renameat(
                &self.directory,
                temporary.as_str(),
                &self.directory,
                "identity.json",
            )
            .map_err(|_| denied())?;
            self.directory.sync_all()?;
            Ok(())
        })();
        if operation.is_err() {
            let _ = unlinkat(&self.directory, temporary.as_str(), AtFlags::empty());
        }
        operation
    }
}
#[cfg(not(unix))]
impl StateStore {
    pub fn open(_: &Path) -> Result<Self> {
        Err(Error::Unsupported("WARP私有状态验证尚未实现此平台"))
    }
    pub fn read(&self) -> Result<Option<Record>> {
        Err(denied())
    }
    pub fn save(&self, _: &Record) -> Result<()> {
        Err(denied())
    }
}
