use pingap_proxy::Server;
use pingora::{protocols::l4::stream::Stream, proxy::HttpProxy, server::{ShutdownWatch, configuration}, services::listening::Service};
use std::sync::Arc;

pub(super) struct DefaultApp {
    app: Arc<HttpProxy<Server>>,
    #[cfg(feature = "openssl")]
    tls: Option<(pingora::tls::ssl::SslAcceptor, pingap_certificate::GlobalCertificate)>,
    #[cfg(feature = "tls-rustls")]
    tls: Option<pingora::listeners::tls::Acceptor>,
}

impl DefaultApp {
    pub(super) fn new(port: u16, server: Server, conf: Arc<configuration::ServerConf>) -> anyhow::Result<Self> {
        #[cfg(feature = "openssl")]
        let tls = if port == 443 {
            use pingora::tls::ssl::{SslAcceptor, SslMethod};
            let (cert, mut settings) = server.shared_tls_settings()?;
            // Move the configured builder, including its CA and ALPN policy.
            let builder = std::mem::replace(&mut *settings, SslAcceptor::mozilla_intermediate(SslMethod::tls())?);
            Some((builder.build(), cert))
        } else { None };
        #[cfg(feature = "tls-rustls")]
        let tls = if port == 443 { Some(server.shared_tls_settings()?.1.build()) } else { None };
        Ok(Self { app: Arc::new(server.into_shared_http(conf)), tls })
    }

    pub(super) async fn serve(&self, stream: Stream, shutdown: ShutdownWatch, grant: super::SiteGrant, tls: super::TlsIdentity) -> Option<anyhow::Result<()>> {
        let app = Arc::new(super::AuthorizedProxy { forwarding: Arc::new(grant.clone()), app: self.app.clone(), tls });
        grant.run(|_| async {
        #[cfg(feature = "openssl")]
        let stream: pingora::protocols::Stream = match &self.tls {
            Some((backend, cert)) => Box::new(tokio::time::timeout(std::time::Duration::from_secs(10),
                pingora::protocols::tls::server::handshake_with_callback(backend, stream, cert)).await??),
            None => Box::new(stream),
        };
        #[cfg(feature = "tls-rustls")]
        let stream: pingora::protocols::Stream = match &self.tls {
            Some(backend) => Box::new(tokio::time::timeout(std::time::Duration::from_secs(10), backend.tls_handshake(stream)).await??),
            None => Box::new(stream),
        };
        Service::handle_event(stream, app, shutdown).await;
        Ok(())
        }).await
    }
}
