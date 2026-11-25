//! TLS handshakes use the same listener identity and immutable view as HTTP.

use std::io::Cursor;
#[cfg(feature = "tls-rustls")]
use std::sync::Arc;

use anyhow::{Context, ensure};
use pingora::protocols::{ALPN, Ssl, Stream as Transport, l4::stream::Stream};
use pingwaf_agent::cache::SslConfig;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use super::View;

const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;

#[cfg(feature = "openssl")]
type Backend = pingora::tls::ssl::SslAcceptor;
#[cfg(feature = "tls-rustls")]
type Backend = pingora::listeners::tls::Acceptor;

pub(super) struct TlsSite {
    backend: Backend,
    http1: bool,
}

impl TlsSite {
    pub(super) fn build(ssl: &SslConfig) -> anyhow::Result<Self> {
        ensure!(ssl.enabled, "TLS is disabled for this HTTPS site");
        // Until issuance is integrated, require already-issued certificate
        // material. In particular, never borrow the legacy self-signed CA.
        ensure!(!ssl.self_signed, "managed self-signed TLS is not supported");
        let http1 = ssl.http1_enabled.unwrap_or(true);
        let http2 = ssl.http2_enabled.unwrap_or(true);
        ensure!(http1 || http2, "no HTTP protocol enabled on HTTPS site");
        let min = tls_version(&ssl.min_tls_version, 2)?;
        let max = tls_version(&ssl.max_tls_version, 3)?;
        ensure!(min <= max, "invalid TLS version range");
        let backend = build_backend(ssl, http1, http2, min, max)?;
        Ok(Self { backend, http1 })
    }
}

fn tls_version(value: &str, default: u8) -> anyhow::Result<u8> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "1.2" | "tls1.2" | "tlsv1.2" => Ok(2),
        "1.3" | "tls1.3" | "tlsv1.3" => Ok(3),
        _ => anyhow::bail!("managed HTTPS supports TLS 1.2 and 1.3 only"),
    }
}

/// Read just enough for the existing TLS parser to extract SNI, then replay
/// the exact bytes to the selected backend. The outer timeout also bounds
/// the backend handshake, and its verifier remains authoritative.
pub(super) async fn read_sni(stream: &mut Stream) -> anyhow::Result<Option<String>> {
    let mut parser = rustls::server::Acceptor::default();
    let mut buffered = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let room = (MAX_CLIENT_HELLO_BYTES - buffered.len()).min(chunk.len());
        ensure!(room > 0, "ClientHello exceeds ingress limit");
        let size = stream.read(&mut chunk[..room]).await?;
        ensure!(size > 0, "connection ended before ClientHello");
        let chunk = &chunk[..size];
        buffered.extend_from_slice(chunk);
        let mut input = Cursor::new(chunk);
        while (input.position() as usize) < size {
            ensure!(parser.read_tls(&mut input)? > 0, "invalid ClientHello");
            if let Some(accepted) =
                parser.accept().map_err(|(error, _)| error)?
            {
                let name = accepted
                    .client_hello()
                    .server_name()
                    .map(str::to_owned);
                stream.rewind(&buffered);
                return Ok(name);
            }
        }
    }
}

pub(super) async fn accept(
    stream: Stream,
    view: &View,
    id: Uuid,
    sni: &str,
) -> anyhow::Result<Transport> {
    let site = view.tls.get(&id).context("site has no TLS context")?;
    #[cfg(feature = "openssl")]
    let stream =
        pingora::protocols::tls::server::handshake(&site.backend, stream)
            .await?;
    #[cfg(feature = "openssl")]
    let negotiated_name = stream
        .ssl()
        .servername(pingora::tls::ssl::NameType::HOST_NAME);
    #[cfg(feature = "tls-rustls")]
    let stream = site.backend.tls_handshake(stream).await?;
    #[cfg(feature = "tls-rustls")]
    let negotiated_name = stream.get_ssl().and_then(|ssl| ssl.server_name());
    ensure!(
        negotiated_name.is_some_and(|name| name.eq_ignore_ascii_case(&sni)),
        "TLS backend did not verify the selected SNI"
    );
    ensure!(
        matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) || site.http1,
        "this ingress requires HTTP/2 ALPN"
    );
    Ok(Box::new(stream))
}

#[cfg(feature = "openssl")]
fn build_backend(
    ssl: &SslConfig,
    http1: bool,
    http2: bool,
    min: u8,
    max: u8,
) -> anyhow::Result<Backend> {
    use pingora::tls::{
        pkey::PKey,
        ssl::{
            AlpnError, SslAcceptor, SslMethod, SslOptions, SslSessionCacheMode,
            SslVerifyMode, SslVersion, select_next_proto,
        },
        x509::{X509, store::X509StoreBuilder},
    };

    let mut acceptor =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    let version = |v| {
        if v == 2 {
            SslVersion::TLS1_2
        } else {
            SslVersion::TLS1_3
        }
    };
    acceptor.set_min_proto_version(Some(version(min)))?;
    acceptor.set_max_proto_version(Some(version(max)))?;
    acceptor.set_options(SslOptions::NO_TICKET | SslOptions::NO_RENEGOTIATION);
    acceptor.set_session_cache_mode(SslSessionCacheMode::OFF);
    acceptor.set_num_tickets(0)?;
    acceptor.set_max_early_data(0)?;
    let chain = X509::stack_from_pem(ssl.cert_pem.as_bytes())?;
    let (leaf, chain) =
        chain.split_first().context("empty TLS certificate chain")?;
    acceptor.set_certificate(leaf)?;
    for cert in chain {
        acceptor.add_extra_chain_cert(cert.clone())?;
    }
    let key = PKey::private_key_from_pem(ssl.key_pem.as_bytes())?;
    acceptor.set_private_key(&key)?;
    acceptor.check_private_key()?;
    if ssl.mtls_enabled {
        let roots = X509::stack_from_pem(ssl.mtls_client_ca.as_bytes())?;
        ensure!(!roots.is_empty(), "missing CA for managed mTLS site");
        let mut trust = X509StoreBuilder::new()?;
        for cert in roots {
            acceptor.add_client_ca(&cert)?;
            trust.add_cert(cert)?;
        }
        acceptor.set_verify_cert_store(trust.build())?;
        let mut mode = SslVerifyMode::PEER;
        if ssl.mtls_requires_cert() {
            mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
        }
        acceptor.set_verify(mode);
    }
    let alpn: &'static [u8] = match (http1, http2) {
        (true, true) => b"\x02h2\x08http/1.1",
        (true, false) => b"\x08http/1.1",
        _ => b"\x02h2",
    };
    acceptor.set_alpn_select_callback(move |_, client| {
        select_next_proto(alpn, client).ok_or(AlpnError::ALERT_FATAL)
    });
    Ok(acceptor.build())
}

#[cfg(feature = "tls-rustls")]
fn build_backend(
    ssl: &SslConfig,
    http1: bool,
    http2: bool,
    min: u8,
    max: u8,
) -> anyhow::Result<Backend> {
    use rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        server::{NoServerSessionStorage, WebPkiClientVerifier},
        version::{TLS12, TLS13},
    };

    let versions = match (min, max) {
        (2, 2) => &[&TLS12][..],
        (3, 3) => &[&TLS13][..],
        _ => &[&TLS13, &TLS12][..],
    };
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)?;
    let builder = if ssl.mtls_enabled {
        let mut roots = RootCertStore::empty();
        for cert in
            CertificateDer::pem_slice_iter(ssl.mtls_client_ca.as_bytes())
        {
            roots.add(cert?)?;
        }
        let mut verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider,
        );
        if !ssl.mtls_requires_cert() {
            verifier = verifier.allow_unauthenticated();
        }
        builder.with_client_cert_verifier(verifier.build()?)
    } else {
        builder.with_no_client_auth()
    };
    let certs = CertificateDer::pem_slice_iter(ssl.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(ssl.key_pem.as_bytes())?;
    let mut config = builder.with_single_cert(certs, key)?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    if http2 {
        config.alpn_protocols.push(b"h2".to_vec());
    }
    if http1 {
        config.alpn_protocols.push(b"http/1.1".to_vec());
    }
    Ok(Backend::from_server_config(Arc::new(config)))
}
