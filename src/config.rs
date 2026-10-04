use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::model::UpstreamSpec;

#[derive(Debug, Parser)]
#[command(name = "dnsshield", version, about)]
pub struct Cli {
    #[arg(long, value_name = "IP", default_value = "0.0.0.0")]
    pub listen: IpAddr,

    #[arg(long, value_name = "PORT", default_value_t = 853)]
    pub dot_port: u16,

    #[arg(long, value_name = "PORT", default_value_t = 853)]
    pub doq_port: u16,

    #[arg(long, value_name = "PORT", default_value_t = 443)]
    pub doh_port: u16,

    #[arg(long, value_name = "URL", default_value = "1.1.1.1:53")]
    pub upstream: UpstreamSpec,

    #[arg(long, value_name = "FILE")]
    pub cert: PathBuf,

    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,

    #[arg(long, default_value_t = 30)]
    pub idle_timeout_secs: u64,

    #[arg(long, default_value_t = 1024)]
    pub max_connections: usize,

    #[arg(long, default_value_t = 64)]
    pub max_connections_per_ip: usize,

    #[arg(long, default_value_t = 5)]
    pub handshake_timeout_secs: u64,

    #[arg(long, default_value_t = 0)]
    pub max_session_secs: u64,

    #[arg(long, default_value = "info")]
    pub log_level: String,

    #[arg(long, default_value = "127.0.0.1:9153")]
    pub metrics_listen: String,
}
