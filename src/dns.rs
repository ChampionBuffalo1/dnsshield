use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, bail};
use hickory_proto::op::{Message, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

pub const MAX_DNS_MESSAGE: usize = u16::MAX as usize;
// A DNS header is fixed-size: ID, flags, and the four count fields
// (question/answer/authority/additional), 2 bytes each — 12 total.
const MIN_DNS_MESSAGE: usize = 12;

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Complete(Vec<u8>),
    Invalid,
    Incomplete,
}

pub fn take_frame(buf: &mut Vec<u8>) -> Frame {
    if buf.len() < 2 {
        return Frame::Incomplete;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len < MIN_DNS_MESSAGE {
        return Frame::Invalid;
    }
    if buf.len() < 2 + len {
        return Frame::Incomplete;
    }
    let msg = buf[2..2 + len].to_vec();
    buf.drain(..2 + len);
    Frame::Complete(msg)
}

pub fn encode_frame(msg: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + msg.len());
    frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    frame.extend_from_slice(msg);
    frame
}

pub fn describe_query(query: &[u8]) -> String {
    match Message::from_vec(query) {
        Ok(msg) => match msg.queries.first() {
            Some(q) => format!("{} {}", q.name(), q.query_type()),
            None => "<no question>".to_string(),
        },
        Err(_) => "<malformed query>".to_string(),
    }
}

pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let msg = Message::from_vec(query).ok()?;
    let mut resp = Message::error_msg(
        msg.metadata.id,
        msg.metadata.op_code,
        ResponseCode::ServFail,
    );
    for q in &msg.queries {
        resp.add_query(q.clone());
    }
    resp.to_vec().ok()
}

#[derive(Clone, Debug)]
pub struct Upstream {
    addr: SocketAddr,
    udp_timeout: Duration,
    tcp_timeout: Duration,
}

impl Upstream {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            udp_timeout: Duration::from_secs(1),
            tcp_timeout: Duration::from_secs(3),
        }
    }

    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        if query.len() < MIN_DNS_MESSAGE {
            bail!("query shorter than a DNS header");
        }

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

    async fn resolve_udp(&self, query: &[u8]) -> Result<Vec<u8>> {
        let bind_addr = match self.addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(self.addr).await?;
        socket.send(query).await?;

        let mut buf = vec![0u8; MAX_DNS_MESSAGE];
        loop {
            let n = socket.recv(&mut buf).await?;
            if n >= MIN_DNS_MESSAGE && buf[..2] == query[..2] {
                return Ok(buf[..n].to_vec());
            }
            debug!("ignoring response with mismatched DNS ID");
        }
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

fn is_truncated(resp: &[u8]) -> bool {
    resp.len() >= 3 && resp[2] & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let msg = vec![0xAB; 40];
        let framed = encode_frame(&msg);
        assert_eq!(framed.len(), 42);

        let mut buf = framed[..3].to_vec();
        assert_eq!(take_frame(&mut buf), Frame::Incomplete);

        let mut buf = framed.clone();
        match take_frame(&mut buf) {
            Frame::Complete(m) => assert_eq!(m, msg),
            other => panic!("expected complete frame, got {other:?}"),
        }
        assert!(buf.is_empty());

        let mut buf = [framed.as_slice(), framed.as_slice()].concat();
        assert_eq!(take_frame(&mut buf), Frame::Complete(msg.clone()));
        assert_eq!(take_frame(&mut buf), Frame::Complete(msg));
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_invalid_on_short_declared_length() {
        let mut buf = vec![0u8, 5, 9, 9, 9, 9, 9];
        assert_eq!(take_frame(&mut buf), Frame::Invalid);
    }

    #[test]
    fn truncated_flag_detection() {
        let resp = [0x12, 0x34, 0x82, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(is_truncated(&resp));
        let resp = [0x12, 0x34, 0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!is_truncated(&resp));
    }
}
