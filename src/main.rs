mod config;
mod limits;
mod metrics;
mod model;
mod server;
mod upstream;
mod util;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use clap::Parser;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Cli;
use crate::limits::{Governance, Limits};
use crate::model::Proto;
use crate::upstream::Upstream;

const LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if !LOG_LEVELS.contains(&cli.log_level.as_str()) {
        bail!(
            "invalid --log-level {:?}; expected one of {LOG_LEVELS:?}",
            cli.log_level
        );
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    for (path, what) in [(&cli.cert, "certificate"), (&cli.key, "private key")] {
        if !path.is_file() {
            bail!("{} file not found: {}", what, path.display());
        }
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let limits = Limits {
        idle: Duration::from_secs(cli.idle_timeout_secs),
        handshake_timeout: Duration::from_secs(cli.handshake_timeout_secs),
        max_session: if cli.max_session_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(cli.max_session_secs))
        },
        max_connections: cli.max_connections,
        max_connections_per_ip: cli.max_connections_per_ip,
    };
    let gov = Arc::new(Governance::new(limits));
    let upstream = Arc::new(Upstream::new(cli.upstream.clone(), &gov)?);

    info!(
        upstream = upstream.describe(),
        idle = ?limits.idle,
        handshake_timeout = ?limits.handshake_timeout,
        max_session = ?limits.max_session,
        max_connections = cli.max_connections,
        max_connections_per_ip = cli.max_connections_per_ip,
        "forwarding queries to upstream resolver"
    );

    let udp = if cli.doq_port != 0 {
        let addr = SocketAddr::new(cli.listen, cli.doq_port);
        match UdpSocket::bind(addr).await {
            Ok(socket) => {
                info!(%addr, "listening: DoQ (DNS-over-QUIC, UDP)");
                Some(socket)
            }
            Err(e) => bail!("could not bind DoQ (UDP) on {addr}: {e}"),
        }
    } else {
        None
    };

    let tcp = if cli.dot_port != 0 {
        let addr = SocketAddr::new(cli.listen, cli.dot_port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!(%addr, "listening: DoT (DNS-over-TLS, TCP)");
                Some(listener)
            }
            Err(e) => bail!("could not bind DoT (TCP) on {addr}: {e}"),
        }
    } else {
        None
    };

    let https = if cli.doh_port != 0 {
        let addr = SocketAddr::new(cli.listen, cli.doh_port);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!(%addr, "listening: DoH (DNS-over-HTTPS, TCP)");
                Some(listener)
            }
            Err(e) => bail!("could not bind DoH (HTTPS/TCP) on {addr}: {e}"),
        }
    } else {
        None
    };

    if udp.is_none() && tcp.is_none() && https.is_none() {
        bail!("all protocol ports are disabled; nothing to serve");
    }

    if cli.metrics_listen.eq_ignore_ascii_case("off") {
        info!("metrics endpoint disabled");
    } else {
        let addr = match cli.metrics_listen.parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                bail!(
                    "invalid --metrics-listen {:?}; expected a socket address or \"off\"",
                    cli.metrics_listen
                );
            }
        };
        let registry = gov.metrics.registry();
        info!(%addr, "metrics: http://{addr}/metrics");
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(registry, addr).await {
                warn!("metrics endpoint stopped: {e}");
            }
        });
    }

    if let Some(socket) = udp {
        let cert = cli.cert.clone();
        let key = cli.key.clone();
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(async move {
            if let Err(e) = server::doq::serve(vec![socket], cert, key, upstream, gov).await {
                warn!("DoQ server failed: {e:#}");
            }
        });
    }

    if let Some(listener) = tcp {
        let acceptor = server::dot::acceptor(&cli.cert, &cli.key)?;
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(server::dot::serve(listener, acceptor, upstream, gov));
    }

    if let Some(listener) = https {
        let acceptor = server::doh::acceptor(&cli.cert, &cli.key)?;
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(server::doh::serve(listener, acceptor, upstream, gov));
    }

    let serving = Proto::ALL
        .iter()
        .filter(|proto| match proto {
            Proto::Dot => cli.dot_port != 0,
            Proto::Doq => cli.doq_port != 0,
            Proto::Doh => cli.doh_port != 0,
        })
        .map(|proto| proto.label())
        .collect::<Vec<_>>()
        .join(" + ");
    info!(
        "dnsshield up — {serving} on {}. Built-in clients \
         (Android/iOS/Windows/systemd) use DoT; AdGuard/Unbound/dnsdist \
         use DoQ; browsers use DoH.",
        cli.listen
    );
    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
