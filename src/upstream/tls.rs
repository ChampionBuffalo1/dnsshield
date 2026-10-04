use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::UPSTREAM_TIMEOUT;
use crate::util::{MIN_DNS_MESSAGE, encode_frame};

pub struct DotUpstream {
    host: String,
    port: u16,
    tls: Arc<ClientConfig>,
}

impl DotUpstream {
    pub fn new(host: String, port: u16, tls: Arc<ClientConfig>) -> Self {
        Self { host, port, tls }
    }

    pub fn describe(&self) -> String {
        format!("tls://{}:{}", self.host, self.port)
    }

    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        let server_name =
            ServerName::try_from(self.host.clone()).context("invalid upstream hostname for TLS")?;
        let connector = TlsConnector::from(Arc::clone(&self.tls));

        let connect = TcpStream::connect((self.host.as_str(), self.port));
        let stream = timeout(UPSTREAM_TIMEOUT, connect)
            .await
            .context("upstream connect timed out")?
            .context("upstream connect failed")?;
        stream.set_nodelay(true)?;

        let mut stream = timeout(UPSTREAM_TIMEOUT, connector.connect(server_name, stream))
            .await
            .context("upstream TLS handshake timed out")?
            .context("upstream TLS handshake failed")?;

        timeout(UPSTREAM_TIMEOUT, stream.write_all(&encode_frame(query))).await??;

        let mut len = [0u8; 2];
        timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut len)).await??;
        let n = u16::from_be_bytes(len) as usize;
        if n < MIN_DNS_MESSAGE {
            bail!("upstream sent a DNS message shorter than a header");
        }
        let mut resp = vec![0u8; n];
        timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut resp)).await??;
        Ok(resp)
    }
}
