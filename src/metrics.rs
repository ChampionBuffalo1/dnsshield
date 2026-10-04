use std::future::pending;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use prometheus_hyper::Server;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Dot,
    Doq,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Dot => "dot",
            Proto::Doq => "doq",
        }
    }
}

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

pub struct Metrics {
    registry: Arc<Registry>,
    pub(crate) queries: IntCounterVec,
    pub(crate) answered: IntCounterVec,
    pub(crate) servfails: IntCounterVec,
    pub(crate) rejected: IntCounterVec,
    active: IntGaugeVec,
    peak: IntGaugeVec,
    latency: HistogramVec,
}

impl Metrics {
    pub fn new() -> prometheus::Result<Self> {
        let registry = Arc::new(Registry::new());

        let queries = IntCounterVec::new(
            Opts::new(
                "dnsshield_queries_total",
                "DNS queries accepted for upstream resolution.",
            ),
            &["proto"],
        )?;
        let answered = IntCounterVec::new(
            Opts::new(
                "dnsshield_upstream_answers_total",
                "Queries answered by the upstream resolver.",
            ),
            &["proto"],
        )?;
        let servfails = IntCounterVec::new(
            Opts::new(
                "dnsshield_upstream_failures_total",
                "Queries the upstream failed to answer; clients got SERVFAIL.",
            ),
            &["proto"],
        )?;
        let rejected = IntCounterVec::new(
            Opts::new(
                "dnsshield_rejected_connections_total",
                "Connections refused by the connection caps.",
            ),
            &["proto"],
        )?;
        let active = IntGaugeVec::new(
            Opts::new(
                "dnsshield_active_connections",
                "Currently connected clients, handshakes included.",
            ),
            &["proto"],
        )?;
        let peak = IntGaugeVec::new(
            Opts::new(
                "dnsshield_peak_connections",
                "Highest simultaneous connection count.",
            ),
            &["proto"],
        )?;
        let latency = HistogramVec::new(
            HistogramOpts::new(
                "dnsshield_upstream_latency_seconds",
                "Upstream lookup latency.",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["proto"],
        )?;
        let up = IntGauge::new("dnsshield_up", "1 when dnsshield is running.")?;
        let build_info = IntGaugeVec::new(
            Opts::new("dnsshield_build_info", "Build information."),
            &["version"],
        )?;
        let start_time = IntGauge::new(
            "dnsshield_process_start_time_seconds",
            "Unix time the process started; uptime is time() minus this.",
        )?;

        registry.register(Box::new(queries.clone()))?;
        registry.register(Box::new(answered.clone()))?;
        registry.register(Box::new(servfails.clone()))?;
        registry.register(Box::new(rejected.clone()))?;
        registry.register(Box::new(active.clone()))?;
        registry.register(Box::new(peak.clone()))?;
        registry.register(Box::new(latency.clone()))?;
        registry.register(Box::new(up.clone()))?;
        registry.register(Box::new(build_info.clone()))?;
        registry.register(Box::new(start_time.clone()))?;

        up.set(1);
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
        start_time.set(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );

        for proto in ["dot", "doq"] {
            queries.with_label_values(&[proto]).get();
            answered.with_label_values(&[proto]).get();
            servfails.with_label_values(&[proto]).get();
            rejected.with_label_values(&[proto]).get();
            active.with_label_values(&[proto]).get();
            peak.with_label_values(&[proto]).get();
        }

        Ok(Self {
            registry,
            queries,
            answered,
            servfails,
            rejected,
            active,
            peak,
            latency,
        })
    }

    /// The registry to hand to the scrape server.
    pub fn registry(&self) -> Arc<Registry> {
        Arc::clone(&self.registry)
    }

    pub fn note_query(&self, proto: Proto) {
        self.queries.with_label_values(&[proto.as_str()]).inc();
    }

    pub fn note_answer(&self, proto: Proto, latency: std::time::Duration, ok: bool) {
        if ok {
            self.answered.with_label_values(&[proto.as_str()]).inc();
        } else {
            self.servfails.with_label_values(&[proto.as_str()]).inc();
        }
        self.latency
            .with_label_values(&[proto.as_str()])
            .observe(latency.as_secs_f64());
    }

    pub fn note_rejected(&self, proto: Proto) {
        self.rejected.with_label_values(&[proto.as_str()]).inc();
    }

    pub fn conn_opened(&self, proto: Proto) {
        let active = self.active.with_label_values(&[proto.as_str()]);
        let now = active.get() + 1;
        active.set(now);
        let peak = self.peak.with_label_values(&[proto.as_str()]);
        if now > peak.get() {
            peak.set(now);
        }
    }

    pub fn conn_closed(&self, proto: Proto) {
        let active = self.active.with_label_values(&[proto.as_str()]);
        active.set((active.get() - 1).max(0));
    }
}

pub async fn serve(registry: Arc<Registry>, addr: SocketAddr) -> std::io::Result<()> {
    Server::run(registry, addr, pending()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};
    use std::time::Duration;

    /// Render the registry to text, as the scrape endpoint would.
    fn render(metrics: &Metrics) -> String {
        let mut body = Vec::new();
        TextEncoder::new()
            .encode(&metrics.registry.gather(), &mut body)
            .unwrap();
        String::from_utf8(body).unwrap()
    }

    /// Pull one per-protocol gauge value out of the rendered text.
    fn gauge_value(body: &str, family: &str, proto: Proto) -> i64 {
        let needle = format!("{family}{{proto=\"{}\"}} ", proto.as_str());
        body.lines()
            .find_map(|l| l.strip_prefix(&needle))
            .unwrap_or_else(|| panic!("missing {needle} in:\n{body}"))
            .parse()
            .unwrap()
    }

    #[test]
    fn registered_families_render() {
        let metrics = Metrics::new().unwrap();
        metrics.note_query(Proto::Doq);
        metrics.note_answer(Proto::Doq, Duration::from_millis(4), true);
        metrics.note_rejected(Proto::Dot);
        metrics.conn_opened(Proto::Dot);
        let body = render(&metrics);

        for expected in [
            "# TYPE dnsshield_queries_total counter",
            "dnsshield_queries_total{proto=\"dot\"} 0",
            "dnsshield_queries_total{proto=\"doq\"} 1",
            "dnsshield_up 1",
            "dnsshield_build_info{version=\"0.1.0\"} 1",
            "dnsshield_active_connections{proto=\"dot\"} 1",
            "dnsshield_upstream_latency_seconds_bucket{proto=\"doq\"",
        ] {
            assert!(
                body.contains(expected),
                "metrics body missing {expected:?}:\n{body}"
            );
        }
    }

    #[test]
    fn active_gauge_tracks_open_and_close() {
        let metrics = Metrics::new().unwrap();
        metrics.conn_opened(Proto::Dot);
        metrics.conn_opened(Proto::Dot);
        metrics.conn_opened(Proto::Doq);
        let body = render(&metrics);
        assert_eq!(
            gauge_value(&body, "dnsshield_active_connections", Proto::Dot),
            2
        );
        assert_eq!(
            gauge_value(&body, "dnsshield_peak_connections", Proto::Dot),
            2
        );

        metrics.conn_closed(Proto::Dot);
        metrics.conn_closed(Proto::Dot);
        let body = render(&metrics);
        assert_eq!(
            gauge_value(&body, "dnsshield_active_connections", Proto::Dot),
            0
        );
        assert_eq!(
            gauge_value(&body, "dnsshield_peak_connections", Proto::Dot),
            2
        );
    }
}
