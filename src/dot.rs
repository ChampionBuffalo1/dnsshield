use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{info, warn};

use crate::dns::Upstream;
use crate::limits::{ConnGuard, Governance};
use crate::metrics::Proto;
use crate::util::{Frame, describe_query, encode_frame, rcode_name, servfail, take_frame};

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

pub async fn serve(
    listeners: Vec<TcpListener>,
    acceptor: TlsAcceptor,
    upstream: Arc<Upstream>,
    gov: Arc<Governance>,
) {
    for listener in listeners {
        let acceptor = acceptor.clone();
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(async move {
            accept_loop(listener, acceptor, upstream, gov).await;
        });
    }
    std::future::pending::<()>().await;
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: Arc<Upstream>,
    gov: Arc<Governance>,
) {
    let idle = gov.limits.idle;
    let handshake_timeout = gov.limits.handshake_timeout;
    let max_session = gov.limits.max_session;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                let throttle = Arc::clone(&gov.throttle);
                throttle.warn("dot-accept", move || format!("DoT TCP accept failed: {e}"));
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        let guard = match gov.gate.try_acquire(peer, Proto::Dot) {
            Ok(guard) => guard,
            Err(_) => continue,
        };

        let acceptor = acceptor.clone();
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(async move {
            let _guard: ConnGuard = guard;

            let tls = match timeout(handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    let throttle = Arc::clone(&gov.throttle);
                    throttle.warn("dot-hs-failed", move || {
                        format!("DoT {peer}: TLS handshake failed: {e}")
                    });
                    return;
                }
                Err(_) => {
                    let throttle = Arc::clone(&gov.throttle);
                    throttle.warn("dot-hs-timeout", move || {
                        format!("DoT {peer}: TLS handshake exceeded {handshake_timeout:?}, closing")
                    });
                    return;
                }
            };

            if let Err(e) = connection(tls, &upstream, &gov, peer, idle, max_session).await {
                warn!(%peer, "DoT session error: {e:#}");
            }
        });
    }
}

async fn connection(
    mut stream: TlsStream<TcpStream>,
    upstream: &Upstream,
    gov: &Governance,
    peer: SocketAddr,
    idle: Duration,
    max_session: Option<Duration>,
) -> Result<()> {
    stream.get_ref().0.set_nodelay(true)?;
    session(&mut stream, upstream, gov, peer, idle, max_session).await
}

async fn session(
    stream: &mut TlsStream<TcpStream>,
    upstream: &Upstream,
    gov: &Governance,
    peer: SocketAddr,
    idle: Duration,
    max_session: Option<Duration>,
) -> Result<()> {
    let started = Instant::now();
    let deadline = max_session.map(|max| started + max);

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut partial_since: Option<Instant> = None;

    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            let throttle = Arc::clone(&gov.throttle);
            throttle.warn("dot-session", move || {
                format!("DoT {peer}: session exceeded {max_session:?}, closing")
            });
            return Ok(());
        }
        if let Some(since) = partial_since
            && since.elapsed() >= idle
        {
            let throttle = Arc::clone(&gov.throttle);
            throttle.warn("dot-framing", move || {
                format!("DoT {peer}: incomplete query after {idle:?}, closing")
            });
            bail!("slow query framing");
        }

        loop {
            match take_frame(&mut buf) {
                Frame::Complete(query) => {
                    answer(stream, upstream, gov, peer, idle, &query).await?;
                }
                Frame::Invalid => {
                    let throttle = Arc::clone(&gov.throttle);
                    throttle.warn("dot-framing", move || {
                        format!("DoT {peer}: invalid framing, closing connection")
                    });
                    bail!("invalid framing");
                }
                Frame::Incomplete => break,
            }
        }
        partial_since = if buf.is_empty() {
            None
        } else {
            Some(partial_since.unwrap_or_else(Instant::now))
        };

        let n = match timeout(idle, stream.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            // Clients that vanish without a TLS close_notify are a normal
            // disconnect, not an error.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e).context("DoT read failed"),
            Err(_) => {
                let throttle = Arc::clone(&gov.throttle);
                throttle.warn("dot-idle", move || {
                    format!("DoT {peer}: idle timeout after {idle:?}, closing")
                });
                return Ok(());
            }
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn answer(
    stream: &mut TlsStream<TcpStream>,
    upstream: &Upstream,
    gov: &Governance,
    peer: SocketAddr,
    idle: Duration,
    query: &[u8],
) -> Result<()> {
    let qdesc = describe_query(query);
    let started = Instant::now();
    let response = match upstream.resolve(Proto::Dot, query).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                %peer,
                "{qdesc}: upstream failed in {:?} (served SERVFAIL): {e:#}",
                started.elapsed()
            );
            servfail(query).context("query too malformed to answer")?
        }
    };
    info!(
        %peer,
        "{qdesc}: answered {} in {:?}",
        rcode_name(&response),
        started.elapsed()
    );

    let frame = encode_frame(&response);
    match timeout(idle, stream.write_all(&frame)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e).context("DoT write failed"),
        Err(_) => {
            // A client that stops reading would otherwise pin this task.
            let throttle = Arc::clone(&gov.throttle);
            throttle.warn("dot-write", move || {
                format!("DoT {peer}: client stopped reading, closing after {idle:?}")
            });
            bail!("DoT write timed out");
        }
    }
    Ok(())
}
