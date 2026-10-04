//! Upstream resolution: forwards parsed DNS queries to the configured
//! resolver over plain UDP/TCP, DoT, or DoH.

mod doh;
mod plain;
mod tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use rustls::RootCertStore;

use crate::limits::{Governance, Throttle};
use crate::metrics::Metrics;
use crate::model::{Proto, UpstreamSpec};

enum Kind {
    Udp(plain::PlainUpstream),
    Dot(tls::DotUpstream),
    Doh(Box<doh::DohUpstream>),
}

pub struct Upstream {
    kind: Kind,
    target: String,
    healthy: AtomicBool,
    metrics: Arc<Metrics>,
    throttle: Arc<Throttle>,
}

impl Upstream {
    pub fn new(spec: UpstreamSpec, gov: &Governance) -> Result<Self> {
        let kind =
            match spec {
                UpstreamSpec::Udp(addr) => Kind::Udp(plain::PlainUpstream::new(addr)),
                UpstreamSpec::Dot { host, port } => {
                    Kind::Dot(tls::DotUpstream::new(host, port, client_tls_config()?))
                }
                UpstreamSpec::Doh { host, port, path } => Kind::Doh(Box::new(
                    doh::DohUpstream::new(host, port, path, client_tls_config()?)?,
                )),
            };
        let target = match &kind {
            Kind::Udp(up) => up.describe(),
            Kind::Dot(up) => up.describe(),
            Kind::Doh(up) => up.describe(),
        };
        Ok(Self {
            kind,
            target,
            healthy: AtomicBool::new(true),
            metrics: Arc::clone(&gov.metrics),
            throttle: Arc::clone(&gov.throttle),
        })
    }

    pub fn describe(&self) -> &str {
        &self.target
    }

    pub async fn resolve(&self, proto: Proto, query: &[u8]) -> Result<Vec<u8>> {
        if query.len() < crate::util::MIN_DNS_MESSAGE {
            anyhow::bail!("query shorter than a DNS header");
        }
        self.metrics.note_query(proto);
        let started = Instant::now();
        let result = match &self.kind {
            Kind::Udp(up) => up.resolve(query).await,
            Kind::Dot(up) => up.resolve(query).await,
            Kind::Doh(up) => up.resolve(query).await,
        };
        self.note_health(proto, &result, started.elapsed());
        result
    }

    fn note_health(&self, proto: Proto, result: &Result<Vec<u8>>, latency: Duration) {
        self.metrics.note_answer(proto, latency, result.is_ok());
        let target = self.target.clone();
        let throttle = Arc::clone(&self.throttle);
        match result {
            Ok(_) => {
                if !self.healthy.swap(true, Ordering::Relaxed) {
                    throttle.info("upstream-recovered", move || {
                        format!("upstream {target} is healthy again")
                    });
                }
            }
            Err(e) => {
                if self.healthy.swap(false, Ordering::Relaxed) {
                    throttle.warn("upstream-down", move || {
                        format!("upstream {target} is failing: {e:#}")
                    });
                }
            }
        }
    }
}

/// TLS client settings for encrypted upstreams: certificates are always
/// verified against Mozilla's public roots.
fn client_tls_config() -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// How long a single upstream connection attempt / exchange may take.
pub(crate) const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
