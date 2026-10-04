use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

use crate::limits::{Governance, Throttle};
use crate::metrics::{Metrics, Proto};
use crate::util::{MAX_DNS_MESSAGE, MIN_DNS_MESSAGE, encode_frame, is_truncated, query_id};

const UDP_POOL_SIZE: usize = 64;

pub struct Upstream {
    addr: SocketAddr,
    udp_timeout: Duration,
    tcp_timeout: Duration,
    /// Already-connected UDP sockets to the upstream, ready for reuse.
    pool: Mutex<VecDeque<UdpSocket>>,
    healthy: AtomicBool,
    metrics: Arc<Metrics>,
    throttle: Arc<Throttle>,
}

impl Upstream {
    pub fn new(addr: SocketAddr, gov: &Governance) -> Self {
        Self {
            addr,
            udp_timeout: Duration::from_secs(1),
            tcp_timeout: Duration::from_secs(3),
            pool: Mutex::new(VecDeque::with_capacity(UDP_POOL_SIZE)),
            healthy: AtomicBool::new(true),
            metrics: Arc::clone(&gov.metrics),
            throttle: Arc::clone(&gov.throttle),
        }
    }

    pub async fn resolve(&self, proto: Proto, query: &[u8]) -> Result<Vec<u8>> {
        if query.len() < MIN_DNS_MESSAGE {
            bail!("query shorter than a DNS header");
        }
        self.metrics.note_query(proto);
        let started = Instant::now();
        let result = self.resolve_inner(query).await;
        self.note_health(proto, &result, started.elapsed());
        result
    }

    async fn resolve_inner(&self, query: &[u8]) -> Result<Vec<u8>> {
        for _ in 0..2 {
            match timeout(self.udp_timeout, self.resolve_udp(query)).await {
                Ok(Ok(resp)) if is_truncated(&resp) => break, // TC set: redo over TCP
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(e)) => debug!("upstream UDP attempt failed: {e}"),
                Err(_) => debug!("upstream UDP attempt timed out"),
            }
        }
        self.resolve_tcp(query).await
    }

    fn note_health(&self, proto: Proto, result: &Result<Vec<u8>>, latency: Duration) {
        self.metrics.note_answer(proto, latency, result.is_ok());
        let addr = self.addr;
        let throttle = &self.throttle;
        match result {
            Ok(_) => {
                if !self.healthy.swap(true, Ordering::Relaxed) {
                    throttle.info("upstream-recovered", move || {
                        format!("upstream {addr} is healthy again")
                    });
                }
            }
            Err(e) => {
                if self.healthy.swap(false, Ordering::Relaxed) {
                    throttle.warn("upstream-down", move || {
                        format!("upstream {addr} is failing: {e:#}")
                    });
                }
            }
        }
    }

    async fn resolve_udp(&self, query: &[u8]) -> Result<Vec<u8>> {
        let socket = self.checkout_udp().await?;
        // Only re-pool sockets that answered; a timed-out or errored socket
        // may still receive a late response, so it is dropped instead.
        let result = udp_exchange(&socket, query).await;
        if result.is_ok() {
            let mut pool = self.pool.lock().unwrap();
            if pool.len() < UDP_POOL_SIZE {
                pool.push_back(socket);
            }
        }
        result
    }

    async fn checkout_udp(&self) -> Result<UdpSocket> {
        if let Some(socket) = self.pool.lock().unwrap().pop_front() {
            // Discard anything queued for a previous query so a late
            // response can't be mistaken for this one's answer.
            let mut stale = [0u8; 4096];
            while socket.try_recv_from(&mut stale).is_ok() {}
            return Ok(socket);
        }
        let bind_addr = match self.addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(self.addr).await?;
        Ok(socket)
    }

    async fn resolve_tcp(&self, query: &[u8]) -> Result<Vec<u8>> {
        let connect = TcpStream::connect(self.addr);
        let mut stream = timeout(self.tcp_timeout, connect).await??;
        stream.set_nodelay(true)?;

        timeout(self.tcp_timeout, stream.write_all(&encode_frame(query))).await??;

        let mut len = [0u8; 2];
        timeout(self.tcp_timeout, stream.read_exact(&mut len)).await??;
        let n = u16::from_be_bytes(len) as usize;
        if n < MIN_DNS_MESSAGE {
            bail!("upstream sent a DNS message shorter than a header");
        }
        let mut resp = vec![0u8; n];
        timeout(self.tcp_timeout, stream.read_exact(&mut resp)).await??;
        Ok(resp)
    }
}

/// Send `query` on a connected socket and wait for the response with a
/// matching DNS ID, skipping stragglers from earlier queries.
async fn udp_exchange(socket: &UdpSocket, query: &[u8]) -> Result<Vec<u8>> {
    let id = query_id(query).context("query is not a parseable DNS message")?;
    socket.send(query).await?;

    let mut buf = vec![0u8; MAX_DNS_MESSAGE];
    loop {
        let n = socket.recv(&mut buf).await?;
        // Responses must carry the query's DNS ID; anything else is a
        // straggler from an earlier query still trickling in.
        if query_id(&buf[..n]) == Some(id) {
            return Ok(buf[..n].to_vec());
        }
        debug!("ignoring response with mismatched DNS ID");
    }
}
