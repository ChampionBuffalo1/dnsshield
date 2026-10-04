use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use http::{Method, Request, StatusCode, Uri, header::CONTENT_TYPE};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use tokio::time::timeout;

use crate::util::MIN_DNS_MESSAGE;

const DOH_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DohUpstream {
    url: Uri,
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl DohUpstream {
    pub fn new(host: String, port: u16, path: String, tls: Arc<ClientConfig>) -> Result<Self> {
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let url = Uri::builder()
            .scheme("https")
            .authority(authority.as_str())
            .path_and_query(path)
            .build()
            .context("invalid upstream DoH URL")?;

        let connector = HttpsConnectorBuilder::new()
            .with_tls_config((*tls).clone())
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);

        Ok(Self { url, client })
    }

    pub fn describe(&self) -> String {
        self.url.to_string()
    }

    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(self.url.clone())
            .header(CONTENT_TYPE, "application/dns-message")
            .body(Full::new(Bytes::copy_from_slice(query)))
            .context("failed to build DoH request")?;

        let response = timeout(DOH_TIMEOUT, self.client.request(request))
            .await
            .context("DoH upstream timed out")?
            .context("DoH upstream request failed")?;
        if response.status() != StatusCode::OK {
            bail!("DoH upstream returned {}", response.status());
        }
        let body = timeout(DOH_TIMEOUT, response.collect())
            .await
            .context("DoH upstream timed out reading the response")?
            .context("DoH upstream response failed")?
            .to_bytes();
        if body.len() < MIN_DNS_MESSAGE {
            bail!("DoH upstream sent a DNS message shorter than a header");
        }
        Ok(body.to_vec())
    }
}
