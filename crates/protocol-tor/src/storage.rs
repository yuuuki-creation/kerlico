use arti_client::{TorClientConfig, config::TorClientConfigBuilder};
use kerlico_core::{Error, OutId, Result};
use std::{fs::File, path::{Path, PathBuf}};

pub(crate) struct StateLease {
    _lock: File,
    state: PathBuf,
    cache: PathBuf,
}

fn storage_error() -> Error {
    Error::Config("Tor状态路径须有完整可信祖先，目录与锁须私有且未被其他实例占用".into())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::{fs::{Mode, OFlags, mkdirat, open, openat}, io::Errno, process::geteuid};
    use std::{ffi::OsStr, os::unix::fs::MetadataExt, path::Component};

    struct TrustedDirectory {
        file: File,
        path: PathBuf,
        own_uid: u32,
    }

    impl TrustedDirectory {
        fn check(&self, private: bool) -> Result<()> {
            let metadata = self.file.metadata().map_err(|_| storage_error())?;
            let trusted_owner = metadata.uid() == self.own_uid || (!private && metadata.uid() == 0);
            let forbidden = if private { 0o077 } else { 0o022 };
            if !metadata.is_dir() || !trusted_owner || metadata.mode() & forbidden != 0 {
                return Err(storage_error());
            }
            Ok(())
        }

        fn absolute(path: &Path) -> Result<Self> {
            if !path.is_absolute() {
                return Err(storage_error());
            }
            let own_uid = geteuid().as_raw();
            let file = open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
                .map(File::from).map_err(|_| storage_error())?;
            let mut directory = Self { file, path: PathBuf::from("/"), own_uid };
            directory.check(false)?;
            for component in path.components() {
                match component {
                    Component::RootDir | Component::CurDir => {}
                    Component::Normal(name) => directory = directory.child(name, false)?,
                    _ => return Err(storage_error()),
                }
            }
            Ok(directory)
        }

        fn child(&self, name: &OsStr, private: bool) -> Result<Self> {
            if private {
                match mkdirat(&self.file, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(_) => return Err(storage_error()),
                }
            }
            let file = openat(&self.file, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
                .map(File::from).map_err(|_| storage_error())?;
            let child = Self { file, path: self.path.join(name), own_uid: self.own_uid };
            child.check(private)?;
            Ok(child)
        }
    }

    pub(super) fn open_lease(base: &Path, relative: &Path, id: &OutId) -> Result<StateLease> {
        let mut directory = TrustedDirectory::absolute(base)?;
        let mut names = Vec::new();
        for component in relative.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(name) => names.push(name),
                _ => return Err(storage_error()),
            }
        }
        if names.is_empty() {
            return Err(storage_error());
        }
        for name in names {
            directory = directory.child(name, true)?;
        }
        directory = directory.child(OsStr::new(id.as_str()), true)?;
        let lock = openat(&directory.file, "instance.lock", OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::from_raw_mode(0o600))
            .map(File::from).map_err(|_| storage_error())?;
        let metadata = lock.metadata().map_err(|_| storage_error())?;
        if !metadata.is_file() || metadata.uid() != directory.own_uid
            || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1
        {
            return Err(storage_error());
        }
        lock.try_lock().map_err(|_| storage_error())?;
        let state = directory.child(OsStr::new("state"), true)?.path;
        let cache = directory.child(OsStr::new("cache"), true)?.path;
        Ok(StateLease { _lock: lock, state, cache })
    }
}

impl StateLease {
    pub fn open(relative: &Path, id: &OutId) -> Result<Self> {
        let base = std::env::current_dir().map_err(|_| storage_error())?;
        Self::open_at(&base, relative, id)
    }

    #[cfg(unix)]
    pub(crate) fn open_at(base: &Path, relative: &Path, id: &OutId) -> Result<Self> {
        unix::open_lease(base, relative, id)
    }

    #[cfg(not(unix))]
    pub(crate) fn open_at(_: &Path, _: &Path, _: &OutId) -> Result<Self> {
        Err(Error::Unsupported("Tor状态目录的完整祖先信任检查尚未实现该平台"))
    }

    pub fn config(&self) -> Result<TorClientConfig> {
        let mut builder = TorClientConfigBuilder::from_directories(&self.state, &self.cache);
        builder.storage().permissions().ignore_environment();
        builder.build().map_err(|_| Error::Config("Tor内部配置不合法".into()))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::{PermissionsExt, symlink}};

    fn directory() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap()
    }

    #[test]
    fn tor_storage_has_one_writer_per_named_instance() {
        let base = directory();
        let first = OutId::parse("tor-a").unwrap();
        let second = OutId::parse("tor-b").unwrap();
        let lease = StateLease::open_at(base.path(), Path::new("tor"), &first).unwrap();
        assert!(StateLease::open_at(base.path(), Path::new("tor"), &first).is_err());
        let other = StateLease::open_at(base.path(), Path::new("tor"), &second).unwrap();
        assert_ne!(lease.state, other.state);
        assert!(lease.config().is_ok());
        drop(lease);
        let _reopened = StateLease::open_at(base.path(), Path::new("tor"), &first).unwrap();
    }

    #[test]
    fn tor_storage_rejects_symlinks_and_public_permissions() {
        let base = directory();
        let id = OutId::parse("tor-a").unwrap();
        let target = base.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, base.path().join("link")).unwrap();
        assert!(StateLease::open_at(base.path(), Path::new("link"), &id).is_err());
        assert!(StateLease::open_at(&base.path().join("link"), Path::new("tor"), &id).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(StateLease::open_at(base.path(), Path::new("target"), &id).is_err());
    }

    #[test]
    fn tor_storage_rejects_untrusted_ancestor_during_replacement_race() {
        let base = directory();
        let hostile = base.path().join("hostile");
        let original = hostile.join("work");
        let moved = hostile.join("moved");
        let outside = base.path().join("outside");
        fs::create_dir(&hostile).unwrap();
        fs::create_dir(&original).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&hostile, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        let id = OutId::parse("tor-a").unwrap();
        assert!(StateLease::open_at(&original, Path::new("tor"), &id).is_err());
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let attack = scope.spawn(|| {
                start.wait();
                for _ in 0..128 {
                    fs::rename(&original, &moved).unwrap();
                    symlink(&outside, &original).unwrap();
                    std::thread::yield_now();
                    fs::remove_file(&original).unwrap();
                    fs::rename(&moved, &original).unwrap();
                }
            });
            start.wait();
            for _ in 0..128 {
                assert!(StateLease::open_at(&original, Path::new("tor"), &id).is_err());
            }
            attack.join().unwrap();
        });
        assert!(!outside.join("tor").exists());
        assert!(!original.join("tor").exists());
        fs::set_permissions(&hostile, fs::Permissions::from_mode(0o700)).unwrap();
        let _lease = StateLease::open_at(&original, Path::new("tor"), &id).unwrap();
    }

    #[test]
    fn tor_storage_rejects_writable_ancestors_before_creating_state() {
        let base = directory();
        let ancestor = base.path().join("shared");
        let work = ancestor.join("private");
        fs::create_dir(&ancestor).unwrap();
        fs::create_dir(&work).unwrap();
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
        let id = OutId::parse("tor-a").unwrap();
        for mode in [0o775, 0o1777] {
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode)).unwrap();
            assert!(StateLease::open_at(&work, Path::new("tor"), &id).is_err());
            assert!(!work.join("tor").exists());
        }
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
        let _lease = StateLease::open_at(&work, Path::new("tor"), &id).unwrap();
    }

    #[test]
    fn tor_storage_rejects_linked_lock_without_touching_its_target() {
        let base = directory();
        let id = OutId::parse("tor-a").unwrap();
        let lease = StateLease::open_at(base.path(), Path::new("tor"), &id).unwrap();
        drop(lease);
        let lock = base.path().join("tor/tor-a/instance.lock");
        let target = base.path().join("target");
        fs::write(&target, b"unchanged").unwrap();
        fs::remove_file(&lock).unwrap();
        symlink(&target, &lock).unwrap();
        assert!(StateLease::open_at(base.path(), Path::new("tor"), &id).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    }

    #[test]
    fn tor_storage_rejects_hardlinked_or_nonprivate_lock_without_modifying_it() {
        let base = directory();
        let id = OutId::parse("tor-a").unwrap();
        drop(StateLease::open_at(base.path(), Path::new("tor"), &id).unwrap());
        let lock = base.path().join("tor/tor-a/instance.lock");
        let alias = base.path().join("lock-alias");
        fs::write(&lock, b"unchanged").unwrap();
        fs::hard_link(&lock, &alias).unwrap();
        assert!(StateLease::open_at(base.path(), Path::new("tor"), &id).is_err());
        assert_eq!(fs::read(&alias).unwrap(), b"unchanged");
        fs::remove_file(&alias).unwrap();
        for mode in [0o640, 0o700] {
            fs::set_permissions(&lock, fs::Permissions::from_mode(mode)).unwrap();
            assert!(StateLease::open_at(base.path(), Path::new("tor"), &id).is_err());
            assert_eq!(fs::read(&lock).unwrap(), b"unchanged");
        }
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        let _lease = StateLease::open_at(base.path(), Path::new("tor"), &id).unwrap();
    }
}
