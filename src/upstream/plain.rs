use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

use crate::util::{MAX_DNS_MESSAGE, MIN_DNS_MESSAGE, encode_frame, is_truncated, query_id};

const UDP_POOL_SIZE: usize = 64;
const UDP_TIMEOUT: Duration = Duration::from_secs(1);
const TCP_TIMEOUT: Duration = Duration::from_secs(3);

pub struct PlainUpstream {
    addr: SocketAddr,
    pool: Mutex<VecDeque<UdpSocket>>,
}

impl PlainUpstream {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            pool: Mutex::new(VecDeque::with_capacity(UDP_POOL_SIZE)),
        }
    }

    pub fn describe(&self) -> String {
        self.addr.to_string()
    }

    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        for _ in 0..2 {
            match timeout(UDP_TIMEOUT, self.resolve_udp(query)).await {
                Ok(Ok(resp)) if is_truncated(&resp) => break,
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(e)) => debug!("upstream UDP attempt failed: {e}"),
                Err(_) => debug!("upstream UDP attempt timed out"),
            }
        }
        self.resolve_tcp(query).await
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
        let mut stream = timeout(TCP_TIMEOUT, connect).await??;
        stream.set_nodelay(true)?;

        timeout(TCP_TIMEOUT, stream.write_all(&encode_frame(query))).await??;

        let mut len = [0u8; 2];
        timeout(TCP_TIMEOUT, stream.read_exact(&mut len)).await??;
        let n = u16::from_be_bytes(len) as usize;
        if n < MIN_DNS_MESSAGE {
            bail!("upstream sent a DNS message shorter than a header");
        }
        let mut resp = vec![0u8; n];
        timeout(TCP_TIMEOUT, stream.read_exact(&mut resp)).await??;
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
