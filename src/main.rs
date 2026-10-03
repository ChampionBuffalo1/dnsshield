mod config;
mod dns;
mod doq;
mod dot;

use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use clap::Parser;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Cli;
use crate::dns::Upstream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    for (path, what) in [(&cli.cert, "certificate"), (&cli.key, "private key")] {
        if !path.is_file() {
            bail!("{} file not found: {}", what, path.display());
        }
    }

    let upstream = Arc::new(Upstream::new(cli.upstream));
    let idle = Duration::from_secs(cli.idle_timeout_secs);

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    info!(upstream = %cli.upstream, "forwarding queries to upstream resolver");

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

    if !udp.is_empty() {
        let cert = cli.cert.clone();
        let key = cli.key.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            if let Err(e) = doq::serve(udp, cert, key, upstream, idle).await {
                warn!("DoQ server failed: {e:#}");
            }
        });
    }

    if !tcp.is_empty() {
        let acceptor = dot::acceptor(&cli.cert, &cli.key)?;
        let upstream = upstream.clone();
        tokio::spawn(dot::serve(tcp, acceptor, upstream));
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
