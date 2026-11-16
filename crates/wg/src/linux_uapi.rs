//! Linux transport for the standalone WireGuard administrative interface.

use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::net::{UnixListener as AsyncListener, UnixStream};

const DIR: &str = "/run/wireguard";

pub(crate) struct Listener {
    inner: AsyncListener,
    path: PathBuf,
    inode: u64,
    dev: u64,
}

impl Listener {
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || matches!(name, "." | "..")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WireGuard interface name",
            ));
        }
        let dir = Path::new(DIR);
        match DirBuilder::new().mode(0o755).create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = dir.symlink_metadata()?;
        if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "insecure WireGuard socket directory",
            ));
        }
        let path = dir.join(format!("{name}.sock"));
        let staging = dir.join(format!(".kerlico-{:016x}", OsRng.next_u64()));
        DirBuilder::new().mode(0o700).create(&staging)?;
        let temporary = staging.join("control");
        let setup = (|| {
            let listener = UnixListener::bind(&temporary)?;
            fs::set_permissions(&temporary, Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let inner = AsyncListener::from_std(listener)?;
            let info = temporary.symlink_metadata()?;
            // Publish the socket with its final permissions, without overwriting anyone.
            fs::hard_link(&temporary, &path)?;
            Ok(Self {
                inner,
                path,
                inode: info.ino(),
                dev: info.dev(),
            })
        })();
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_dir(&staging);
        setup
    }

    pub(crate) async fn accept(&mut self) -> io::Result<Option<UnixStream>> {
        loop {
            if !self.still_owned() {
                return Ok(None);
            }
            if let Ok(connection) =
                tokio::time::timeout(Duration::from_millis(20), self.inner.accept()).await
            {
                let (stream, _) = connection?;
                return Ok(self.still_owned().then_some(stream));
            }
        }
    }

    fn still_owned(&self) -> bool {
        self.path.symlink_metadata().is_ok_and(|info| {
            info.file_type().is_socket() && info.ino() == self.inode && info.dev() == self.dev
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if self.still_owned() {
            let _ = fs::remove_file(&self.path);
        }
    }
}
