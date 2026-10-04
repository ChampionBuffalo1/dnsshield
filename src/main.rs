mod config;
mod dns;
mod doq;
mod dot;
mod limits;
mod metrics;
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
use crate::dns::Upstream;
use crate::limits::{Governance, Limits};

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
    let upstream = Arc::new(Upstream::new(cli.upstream, &gov));

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    info!(
        upstream = %cli.upstream,
        idle = ?limits.idle,
        handshake_timeout = ?limits.handshake_timeout,
        max_session = ?limits.max_session,
        max_connections = cli.max_connections,
        max_connections_per_ip = cli.max_connections_per_ip,
        "forwarding queries to upstream resolver"
    );

    let mut udp = Vec::new();
    for addr in &cli.listen {
        match UdpSocket::bind(addr).await {
            Ok(socket) => {
                info!(%addr, "listening: DoQ (DNS-over-QUIC, UDP)");
                udp.push(socket);
            }
            Err(e) => warn!(%addr, "could not bind DoQ (UDP): {e}"),
        }
    }

    let mut tcp = Vec::new();
    for addr in &cli.listen {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!(%addr, "listening: DoT (DNS-over-TLS, TCP)");
                tcp.push(listener);
            }
            Err(e) => warn!(%addr, "could not bind DoT (TCP): {e}"),
        }
    }

    if udp.is_empty() && tcp.is_empty() {
        bail!("could not bind any listener on {:?}", cli.listen);
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

    if !udp.is_empty() {
        let cert = cli.cert.clone();
        let key = cli.key.clone();
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(async move {
            if let Err(e) = doq::serve(udp, cert, key, upstream, gov).await {
                warn!("DoQ server failed: {e:#}");
            }
        });
    }

    if !tcp.is_empty() {
        let acceptor = dot::acceptor(&cli.cert, &cli.key)?;
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(dot::serve(tcp, acceptor, upstream, gov));
    }

    info!(
        "dnsshield up — DoT (TCP) + DoQ (UDP) on {:?}. Built-in clients \
         (Android/iOS/Windows/systemd) use DoT; AdGuard/Unbound/dnsdist use DoQ.",
        cli.listen
    );
    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
