use arti_client::{ErrorKind, HasKind};
use kerlico_core::{Error, ServiceFailure};
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Timeout,
    Rejected,
    InvalidTarget,
    Resource,
    Deprecated,
    Storage,
    Network,
    Refused,
    Protocol,
}

impl Failure {
    pub fn from_arti(error: &arti_client::Error) -> Self {
        Self::from_kind(error.kind())
    }
    fn from_kind(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::TorNetworkTimeout | ErrorKind::RemoteNetworkTimeout | ErrorKind::ExitTimeout => Self::Timeout,
            ErrorKind::ExitPolicyRejected | ErrorKind::ForbiddenStreamTarget
            | ErrorKind::OnionServiceMissingClientAuth | ErrorKind::OnionServiceWrongClientAuth => Self::Rejected,
            ErrorKind::InvalidStreamTarget | ErrorKind::OnionServiceAddressInvalid => Self::InvalidTarget,
            ErrorKind::LocalResourceExhausted | ErrorKind::RelayTooBusy => Self::Resource,
            ErrorKind::SoftwareDeprecated => Self::Deprecated,
            ErrorKind::PersistentStateAccessFailed | ErrorKind::LocalResourceAlreadyInUse
            | ErrorKind::FsPermissions | ErrorKind::PersistentStateCorrupted
            | ErrorKind::CacheAccessFailed | ErrorKind::CacheCorrupted
            | ErrorKind::KeystoreAccessFailed | ErrorKind::KeystoreCorrupted => Self::Storage,
            ErrorKind::RemoteConnectionRefused => Self::Refused,
            ErrorKind::LocalNetworkError | ErrorKind::RemoteNetworkFailed
            | ErrorKind::TorAccessFailed | ErrorKind::RemoteHostNotFound
            | ErrorKind::RemoteHostResolutionFailed | ErrorKind::OnionServiceNotFound
            | ErrorKind::OnionServiceNotRunning => Self::Network,
            _ => Self::Protocol,
        }
    }
    pub fn service_failure(self) -> ServiceFailure {
        match self {
            Self::Timeout => ServiceFailure::Timeout,
            Self::Rejected => ServiceFailure::Rejected,
            Self::InvalidTarget => ServiceFailure::InvalidAddress,
            Self::Resource => ServiceFailure::ResourceLimit,
            Self::Deprecated => ServiceFailure::Protocol("Tor协议版本已不满足网络要求，所属出站已停止"),
            Self::Storage => ServiceFailure::Protocol("Tor状态文件不可用或已被其他实例占用"),
            Self::Network => ServiceFailure::Io(io::ErrorKind::ConnectionAborted, "Tor网络或远端目标不可用"),
            Self::Refused => ServiceFailure::Io(io::ErrorKind::ConnectionRefused, "Tor远端拒绝连接"),
            Self::Protocol => ServiceFailure::Protocol("Tor建立或运行失败"),
        }
    }
    pub fn error(self) -> Error {
        self.service_failure().error()
    }
}

pub(crate) fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, Error::Cancelled)
}

pub(crate) fn sanitized_io(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "Tor流I/O失败")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_errors_keep_category_without_upstream_details() {
        assert!(matches!(Failure::from_kind(ErrorKind::SoftwareDeprecated).error(), Error::Protocol(_)));
        assert!(matches!(Failure::from_kind(ErrorKind::ExitPolicyRejected).error(), Error::Rejected));
        assert!(matches!(Failure::from_kind(ErrorKind::ExitTimeout).error(), Error::Timeout));
        assert!(matches!(Failure::from_kind(ErrorKind::InvalidStreamTarget).error(), Error::InvalidAddress));
        let error = sanitized_io(io::Error::other("不应导出的目标和目录"));
        assert_eq!(error.to_string(), "Tor流I/O失败");
        assert!(cancelled().get_ref().unwrap().downcast_ref::<Error>().is_some_and(|error| matches!(error, Error::Cancelled)));
    }
}
