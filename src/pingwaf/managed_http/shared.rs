use anyhow::{Context, ensure};
use pingap_proxy::Server;
use pingora::{protocols::l4::stream::Stream, proxy::HttpProxy, server::{ShutdownWatch, configuration}, services::listening::Service};
use std::sync::Arc;
use tokio::io::AsyncReadExt;

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

    pub(super) async fn hostname(&self, stream: &mut Stream) -> anyhow::Result<String> {
        if self.tls.is_some() { return Ok(super::tls::read_sni(stream).await?.unwrap_or_default()); }
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await?;
            ensure!(read > 0, "incomplete request header");
            bytes.extend_from_slice(&chunk[..read]);
            ensure!(bytes.len() <= 65536, "request header exceeds limit");
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let mut host = String::new();
                for line in bytes[..end].split(|b| *b == b'\n').skip(1) {
                    let Some(colon) = line.iter().position(|b| *b == b':') else { continue; };
                    if line[..colon].eq_ignore_ascii_case(b"host") {
                        let authority: http::uri::Authority = std::str::from_utf8(&line[colon + 1..])?.trim().parse().context("invalid Host")?;
                        host = authority.host().to_owned();
                        break;
                    }
                }
                stream.rewind(&bytes);
                return Ok(host);
            }
        }
    }

    pub(super) async fn serve(&self, stream: Stream, shutdown: ShutdownWatch) -> anyhow::Result<()> {
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
        Service::handle_event(stream, self.app.clone(), shutdown).await;
        Ok(())
    }
}
