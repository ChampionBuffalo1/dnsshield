use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::header::{ALLOW, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use super::dot;
use crate::limits::{ConnGuard, Governance};
use crate::model::Proto;
use crate::upstream::Upstream;
use crate::util::{MIN_DNS_MESSAGE, describe_query, rcode_name, servfail};

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_REQUEST_BODY: usize = u16::MAX as usize;

pub fn acceptor(cert_path: &std::path::Path, key_path: &std::path::Path) -> Result<TlsAcceptor> {
    let config = dot::server_config(cert_path, key_path, &[b"h2", b"http/1.1"])?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: Arc<Upstream>,
    gov: Arc<Governance>,
) {
    accept_loop(listener, acceptor, upstream, gov).await;
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: Arc<Upstream>,
    gov: Arc<Governance>,
) {
    let handshake_timeout = gov.limits.handshake_timeout;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                let throttle = Arc::clone(&gov.throttle);
                throttle.warn("doh-accept", move || format!("DoH TCP accept failed: {e}"));
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        let guard = match gov.gate.try_acquire(peer, Proto::Doh) {
            Ok(guard) => guard,
            Err(_) => continue,
        };

        let acceptor = acceptor.clone();
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(async move {
            let _guard: ConnGuard = guard;

            stream.set_nodelay(true).ok();
            let tls = match timeout(handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    let throttle = Arc::clone(&gov.throttle);
                    throttle.warn("doh-hs-failed", move || {
                        format!("DoH {peer}: TLS handshake failed: {e}")
                    });
                    return;
                }
                Err(_) => {
                    let throttle = Arc::clone(&gov.throttle);
                    throttle.warn("doh-hs-timeout", move || {
                        format!("DoH {peer}: TLS handshake exceeded {handshake_timeout:?}, closing")
                    });
                    return;
                }
            };

            let upstream = Arc::clone(&upstream);
            let throttle = Arc::clone(&gov.throttle);
            let service = service_fn(move |req| {
                let upstream = Arc::clone(&upstream);
                async move { handle(req, upstream, peer).await }
            });

            if let Err(e) = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
            {
                throttle.warn("doh-conn", move || {
                    format!("DoH {peer}: connection failed: {e}")
                });
            }
        });
    }
}

type DohError = (StatusCode, &'static str);

async fn handle(
    req: Request<Incoming>,
    upstream: Arc<Upstream>,
    peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    Ok(match extract_query(req).await {
        Ok(query) => answer(query, &upstream, peer).await,
        Err(err) => error_response(err),
    })
}

async fn extract_query(req: Request<Incoming>) -> Result<Vec<u8>, DohError> {
    match *req.method() {
        Method::GET => {
            let query = req.uri().query().unwrap_or_default();
            let payload = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("dns="))
                .ok_or((StatusCode::BAD_REQUEST, "missing dns query parameter"))?;
            decode_dns_param(payload)
        }
        Method::POST => {
            let content_type = req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if !content_type.starts_with(DNS_MESSAGE) {
                return Err((
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "content-type must be application/dns-message",
                ));
            }
            let body = Limited::new(req.into_body(), MAX_REQUEST_BODY);
            let collected = body
                .collect()
                .await
                .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "request body too large"))?;
            let bytes = collected.to_bytes();
            if bytes.len() < MIN_DNS_MESSAGE {
                return Err((StatusCode::BAD_REQUEST, "request shorter than a DNS header"));
            }
            Ok(bytes.to_vec())
        }
        _ => Err((StatusCode::METHOD_NOT_ALLOWED, "use GET or POST")),
    }
}

fn decode_dns_param(value: &str) -> Result<Vec<u8>, DohError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "invalid base64url in dns parameter",
            )
        })?;
    if decoded.len() < MIN_DNS_MESSAGE {
        return Err((StatusCode::BAD_REQUEST, "request shorter than a DNS header"));
    }
    Ok(decoded)
}

async fn answer(query: Vec<u8>, upstream: &Upstream, peer: SocketAddr) -> Response<Full<Bytes>> {
    let qdesc = describe_query(&query);
    let started = Instant::now();
    let response = match upstream.resolve(Proto::Doh, &query).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                %peer,
                "{qdesc}: upstream failed in {:?} (served SERVFAIL): {e:#}",
                started.elapsed()
            );
            match servfail(&query) {
                Some(resp) => resp,
                None => return error_response((StatusCode::BAD_REQUEST, "malformed DNS query")),
            }
        }
    };
    info!(
        %peer,
        "{qdesc}: answered {} in {:?}",
        rcode_name(&response),
        started.elapsed()
    );
    dns_response(&response)
}

fn dns_response(msg: &[u8]) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::copy_from_slice(msg)));
    resp.headers_mut()
        .insert(CONTENT_TYPE, http::HeaderValue::from_static(DNS_MESSAGE));
    resp
}

fn error_response((status, message): DohError) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(message)));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, http::HeaderValue::from_static("text/plain"));
    if status == StatusCode::METHOD_NOT_ALLOWED {
        resp.headers_mut()
            .insert(ALLOW, http::HeaderValue::from_static("GET, POST"));
    }
    resp
}
