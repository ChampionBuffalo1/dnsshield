use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};

use crate::dns::{self, Frame, Upstream};

pub fn acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?
        .collect::<Result<_, _>>()
        .context("failed to parse certificate PEM")?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;

    // RFC 7858 defines no ALPN for DoT.
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid certificate/key pair")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn serve(listeners: Vec<TcpListener>, acceptor: TlsAcceptor, upstream: Arc<Upstream>) {
    for listener in listeners {
        let acceptor = acceptor.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            accept_loop(listener, acceptor, upstream).await;
        });
    }
    std::future::pending::<()>().await;
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, upstream: Arc<Upstream>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("DoT TCP accept failed: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    debug!(%peer, "DoT TLS handshake failed: {e}");
                    return;
                }
            };
            if let Err(e) = connection(tls, &upstream).await {
                debug!(%peer, "DoT connection ended: {e:#}");
            }
        });
    }
}

async fn connection(mut stream: TlsStream<TcpStream>, upstream: &Upstream) -> Result<()> {
    stream.get_ref().0.set_nodelay(true)?;
    info!("DoT connection established");

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        loop {
            match dns::take_frame(&mut buf) {
                Frame::Complete(query) => answer(&mut stream, upstream, &query).await?,
                Frame::Invalid => bail!("invalid framing, closing connection"),
                Frame::Incomplete => break,
            }
        }

        let n = stream.read(&mut chunk).await.context("DoT read failed")?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn answer(
    stream: &mut TlsStream<TcpStream>,
    upstream: &Upstream,
    query: &[u8],
) -> Result<()> {
    let qdesc = dns::describe_query(query);
    let started = Instant::now();
    let response = match upstream.resolve(query).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("{qdesc}: upstream failed: {e:#}");
            dns::servfail(query).context("query too malformed to answer")?
        }
    };
    debug!("{qdesc}: answered in {:?}", started.elapsed());
    stream
        .write_all(&dns::encode_frame(&response))
        .await
        .context("DoT write failed")?;
    Ok(())
}
