//! 诊断事件保留类别和具体错误，由所属运行实例决定语言与接收方。
use crate::{Error, Language};
use std::{fmt, sync::Arc};

#[derive(Clone, Copy)]
pub struct Diagnostic<'a> {
    pub code: &'static str,
    pub error: &'a Error,
}
impl<'a> Diagnostic<'a> {
    pub fn localized(self, language: Language) -> LocalizedDiagnostic<'a> {
        LocalizedDiagnostic {
            event: self,
            language,
        }
    }
}
pub struct LocalizedDiagnostic<'a> {
    event: Diagnostic<'a>,
    language: Language,
}
impl fmt::Display for LocalizedDiagnostic<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self.event.code {
            "vless.mux.write_failed" => self
                .language
                .select("VLESS Mux 载体写入失败", "VLESS Mux transport write failed"),
            "vless.mux.read_failed" => self
                .language
                .select("VLESS Mux 载体读取失败", "VLESS Mux transport read failed"),
            "vless.xdrive.background_failed" => self
                .language
                .select("XDRIVE 后台任务失败", "XDRIVE background task failed"),
            "vless.xdrive.session_failed" => self
                .language
                .select("VLESS 存储会话失败", "VLESS storage session failed"),
            code => code,
        };
        write!(
            formatter,
            "[{}] {label}: [{}] {}",
            self.event.code,
            self.event.error.code(),
            self.event.error.localized(self.language)
        )
    }
}
type Emitter = dyn for<'a> Fn(Diagnostic<'a>) + Send + Sync;
#[derive(Clone)]
pub struct DiagnosticSink(Arc<Emitter>);
impl DiagnosticSink {
    pub fn new(emit: impl for<'a> Fn(Diagnostic<'a>) + Send + Sync + 'static) -> Self {
        Self(Arc::new(emit))
    }
    pub fn stderr(language: Language) -> Self {
        Self::new(move |event| eprintln!("{}", event.localized(language)))
    }
    pub fn emit(&self, event: Diagnostic<'_>) {
        (self.0)(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct UnusedDevice;
    impl crate::DeviceNetwork for UnusedDevice {
        fn connect_tcp(
            &self,
            _: std::net::SocketAddr,
        ) -> crate::BoxFuture<'_, crate::Result<crate::OpenedTcp>> {
            Box::pin(async { Err(Error::Unsupported("unused test device")) })
        }
        fn connect_udp(
            &self,
            _: std::net::SocketAddr,
        ) -> crate::BoxFuture<'_, crate::Result<Arc<tokio::net::UdpSocket>>> {
            Box::pin(async { Err(Error::Unsupported("unused test device")) })
        }
        fn udp_association(
            &self,
            _: crate::FamilyMode,
        ) -> crate::BoxFuture<'_, crate::Result<Arc<tokio::net::UdpSocket>>> {
            Box::pin(async { Err(Error::Unsupported("unused test device")) })
        }
    }
    #[test]
    fn diagnostic_language_follows_its_named_service_scope() {
        let device = crate::DeviceLease::borrow(Arc::new(UnusedDevice));
        let chinese = crate::ServiceContext::with_options(
            crate::OutId::parse("chinese").unwrap(),
            crate::RuntimeOptions {
                device: device.clone(),
                language: Language::ZhCn,
            },
        );
        let english = crate::ServiceContext::with_options(
            crate::OutId::parse("english").unwrap(),
            crate::RuntimeOptions {
                device,
                language: Language::En,
            },
        );
        let context = crate::ConnectContext::new(std::time::Duration::from_secs(1));
        let source = crate::Source::Local {
            node: crate::NodeId::parse("entry").unwrap(),
        };
        let scoped = |service: &crate::ServiceContext| {
            context.scoped(
                service,
                &source,
                crate::CancellationToken::new(),
                crate::CancellationToken::new(),
                crate::FamilyMode::DualV4Preferred,
            )
        };
        assert_eq!(scoped(&chinese).language(), Language::ZhCn);
        assert_eq!(scoped(&english).language(), Language::En);
        assert_eq!(scoped(&chinese).service_status().language(), Language::ZhCn);
        assert_eq!(chinese.language(), Language::ZhCn);
        assert_eq!(english.language(), Language::En);
    }
    #[test]
    fn explicit_sinks_keep_category_and_error_without_shared_language_state() {
        let error = Error::Protocol("Mux 载体写入失败");
        let event = Diagnostic {
            code: "vless.mux.write_failed",
            error: &error,
        };
        let english = event.localized(Language::En).to_string();
        let chinese = event.localized(Language::ZhCn).to_string();
        assert!(english.contains("vless.mux.write_failed"));
        assert!(chinese.contains("vless.mux.write_failed"));
        assert!(english.contains("Could not write to the Mux transport"));
        assert!(chinese.contains("Mux 载体写入失败"));
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let output = observed.clone();
        let sink = DiagnosticSink::new(move |event| {
            output
                .lock()
                .unwrap()
                .push(event.localized(Language::En).to_string())
        });
        sink.emit(event);
        assert_eq!(*observed.lock().unwrap(), vec![english]);
    }
}
