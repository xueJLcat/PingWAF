use super::config::Config;
use anyhow::{bail, ensure, Context, Result};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use std::{io::Cursor, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    time::timeout,
};

#[derive(Default, Clone)]
pub struct Material {
    pub ca: String,
    pub cert: String,
    pub key: String,
}
pub type Tls = Option<Arc<ClientConfig>>;

pub fn tls(c: &Config, m: &Material) -> Result<Tls> {
    if c.transport != "tls" {
        return Ok(None);
    }
    let mut roots = RootCertStore::empty();
    if c.trust == "custom" {
        for cert in rustls_pemfile::certs(&mut Cursor::new(&m.ca)) {
            roots
                .add(cert.context("ca: invalid PEM")?)
                .context("ca: invalid certificate")?;
        }
    } else {
        roots.add_parsable_certificates(
            rustls_native_certs::load_native_certs().certs,
        );
    }
    ensure!(!roots.is_empty(), "ca: empty trust store");
    let builder = ClientConfig::builder_with_provider(
        crate::pki::tls::crypto_provider().clone(),
    )
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let cfg = if c.mtls {
        let chain = rustls_pemfile::certs(&mut Cursor::new(&m.cert))
            .collect::<std::io::Result<Vec<_>>>()?;
        let leaf = chain.first().context("cert: missing client certificate")?;
        use x509_parser::prelude::*;
        for cert in &chain {
            let (_, x) = X509Certificate::from_der(cert.as_ref())
                .map_err(|_| anyhow::anyhow!("cert: invalid X509"))?;
            ensure!(x.validity().is_valid(), "cert: outside validity period");
        }
        let (_, x) = X509Certificate::from_der(leaf.as_ref())
            .map_err(|_| anyhow::anyhow!("cert: invalid X509"))?;
        ensure!(
            x.extended_key_usage()?
                .is_none_or(|e| e.value.client_auth || e.value.any),
            "cert: client authentication not allowed"
        );
        let key = rustls_pemfile::private_key(&mut Cursor::new(&m.key))?
            .context("key: unencrypted PEM required")?;
        builder
            .with_client_auth_cert(chain, key)
            .context("key: key/certificate mismatch")?
    } else {
        builder.with_no_client_auth()
    };
    Ok(Some(Arc::new(cfg)))
}

pub enum Connection {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}
impl Connection {
    pub async fn connect(c: &Config, config: &Tls) -> Result<Self> {
        timeout(Duration::from_secs(c.connect_seconds), async {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((c.host.as_str(), c.port))
                    .await
                    .context("dns")?
                    .collect();
            ensure!(!addrs.is_empty(), "dns: no addresses");
            if c.transport == "udp" {
                for addr in addrs {
                    let local = if addr.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    if let Ok(socket) = UdpSocket::bind(local).await {
                        if socket.connect(addr).await.is_ok() {
                            return Ok(Self::Udp(socket));
                        }
                    }
                }
                bail!("udp: no usable destination")
            }
            let stream =
                TcpStream::connect(&addrs[..]).await.context("connect")?;
            if c.transport == "tcp" {
                return Ok(Self::Tcp(stream));
            }
            let name = if c.server_name.is_empty() {
                &c.host
            } else {
                &c.server_name
            };
            let name =
                ServerName::try_from(name.to_owned()).context("server_name")?;
            let tls = tokio_rustls::TlsConnector::from(
                config.clone().context("tls: missing configuration")?,
            );
            Ok(Self::Tls(Box::new(
                tls.connect(name, stream).await.context("tls handshake")?,
            )))
        })
        .await
        .context("connect/handshake timeout")?
    }
    pub async fn send(&mut self, c: &Config, msg: &[u8]) -> Result<()> {
        timeout(Duration::from_secs(c.write_seconds), async {
            if let Self::Udp(socket) = self {
                ensure!(
                    socket.send(msg).await? == msg.len(),
                    "udp: incomplete write"
                );
                return Ok(());
            }
            let mut buf = Vec::with_capacity(msg.len() + 12);
            if c.framing == "octet" {
                buf.extend_from_slice(format!("{} ", msg.len()).as_bytes());
            }
            buf.extend_from_slice(msg);
            if c.framing == "lf" {
                buf.push(b'\n');
            }
            let output: &mut (dyn tokio::io::AsyncWrite + Unpin + Send) =
                match self {
                    Self::Tcp(t) => t,
                    Self::Tls(t) => t.as_mut(),
                    Self::Udp(_) => unreachable!(),
                };
            output.write_all(&buf).await?;
            output.flush().await?;
            Ok(())
        })
        .await
        .context("write timeout")?
    }
    pub fn peer(&self) -> Option<SocketAddr> {
        match self {
            Self::Udp(s) => s.peer_addr(),
            Self::Tcp(s) => s.peer_addr(),
            Self::Tls(s) => s.get_ref().0.peer_addr(),
        }
        .ok()
    }
}
