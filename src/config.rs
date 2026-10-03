use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

fn default_listen() -> Vec<SocketAddr> {
    vec![
        SocketAddr::from(([0, 0, 0, 0], 853)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 853)),
    ]
}

#[derive(Debug, Parser)]
#[command(name = "dnsshield", version, about)]
pub struct Cli {
    #[arg(long, value_name = "ADDR", default_values_t = default_listen())]
    pub listen: Vec<SocketAddr>,

    #[arg(long, default_value = "1.1.1.1:53")]
    pub upstream: SocketAddr,

    #[arg(long, value_name = "FILE")]
    pub cert: PathBuf,

    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,

    #[arg(long, default_value_t = 30)]
    pub idle_timeout_secs: u64,
}
