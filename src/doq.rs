use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use futures::StreamExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::{HandshakeInfo, QuicheConnection};
use tokio_quiche::quiche;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{ApplicationOverQuic, ConnectionParams, QuicConnectionStream, QuicResult};
use tracing::{debug, info, warn};

use crate::dns::{self, Frame, Upstream};

const DOQ_ALPN: &[u8] = b"doq";

const RECV_CHUNK: usize = 4096;

pub async fn serve(
    sockets: Vec<UdpSocket>,
    cert_path: PathBuf,
    key_path: PathBuf,
    upstream: Arc<Upstream>,
    idle: Duration,
) -> anyhow::Result<()> {
    let cert = cert_path
        .to_str()
        .context("certificate path is not valid UTF-8")?;
    let key = key_path.to_str().context("key path is not valid UTF-8")?;

    let mut settings = QuicSettings::default();
    settings.alpn = vec![DOQ_ALPN.to_vec()];
    settings.max_idle_timeout = Some(idle);
    settings.handshake_timeout = Some(Duration::from_secs(5));
    settings.initial_max_streams_bidi = 100;

    let params = ConnectionParams::new_server(
        settings,
        TlsCertificatePaths {
            cert,
            private_key: key,
            kind: CertificateKind::X509,
        },
        Hooks::default(),
    );

    let listeners = tokio_quiche::listen(sockets, params, DefaultMetrics)?;
    for mut listener in listeners {
        let upstream = upstream.clone();
        tokio::spawn(async move {
            accept_loop(&mut listener, upstream).await;
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}

async fn accept_loop(listener: &mut QuicConnectionStream<DefaultMetrics>, upstream: Arc<Upstream>) {
    while let Some(conn) = listener.next().await {
        match conn {
            Ok(initial) => {
                initial.start(DoqConnection::new(upstream.clone()));
            }
            Err(e) => debug!("DoQ connection attempt failed: {e}"),
        }
    }
}

struct Finished {
    stream_id: u64,
    response: Option<Vec<u8>>,
}

#[derive(Default)]
struct StreamState {
    buf: Vec<u8>,
    client_fin: bool,
    outstanding: usize,
}

pub struct DoqConnection {
    upstream: Arc<Upstream>,
    tx: mpsc::UnboundedSender<Finished>,
    rx: mpsc::UnboundedReceiver<Finished>,
    notify: Arc<tokio::sync::Notify>,
    streams: HashMap<u64, StreamState>,
    outbound: VecDeque<(u64, usize, Vec<u8>, bool)>,
}

impl DoqConnection {
    pub fn new(upstream: Arc<Upstream>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            upstream,
            tx,
            rx,
            notify: Arc::new(tokio::sync::Notify::new()),
            streams: HashMap::new(),
            outbound: VecDeque::new(),
        }
    }

    fn send_frame(
        &mut self,
        qconn: &mut QuicheConnection,
        stream_id: u64,
        frame: Vec<u8>,
        fin: bool,
    ) {
        match qconn.stream_send(stream_id, &frame, fin) {
            Ok(n) if n == frame.len() => {
                if fin {
                    self.streams.remove(&stream_id);
                }
            }
            Ok(n) => self.outbound.push_back((stream_id, n, frame, fin)),
            Err(quiche::Error::Done) => {
                self.outbound.push_back((stream_id, 0, frame, fin));
            }
            Err(e) => {
                debug!("DoQ stream {stream_id}: send failed: {e}");
                let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                self.streams.remove(&stream_id);
            }
        }
    }
}

impl ApplicationOverQuic for DoqConnection {
    fn on_conn_established(
        &mut self,
        _qconn: &mut QuicheConnection,
        _handshake: &HandshakeInfo,
    ) -> QuicResult<()> {
        info!("DoQ connection established");
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.notify.notified().await;
        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        for stream_id in qconn.readable() {
            let mut reset = false; // framing violated: reset the stream
            let mut close = false; // client FIN + nothing pending: close cleanly
            {
                let state = self.streams.entry(stream_id).or_default();
                let mut chunk = [0u8; RECV_CHUNK];
                loop {
                    match qconn.stream_recv(stream_id, &mut chunk) {
                        Ok((0, false)) => break,
                        Ok((n, fin)) => {
                            state.buf.extend_from_slice(&chunk[..n]);
                            if fin {
                                state.client_fin = true;
                            }
                            loop {
                                match dns::take_frame(&mut state.buf) {
                                    Frame::Complete(query) => {
                                        state.outstanding += 1;
                                        let tx = self.tx.clone();
                                        let notify = self.notify.clone();
                                        let upstream = self.upstream.clone();
                                        let qdesc = dns::describe_query(&query);
                                        tokio::spawn(async move {
                                            let started = Instant::now();
                                            let response = upstream
                                                .resolve(&query)
                                                .await
                                                .map(Some)
                                                .unwrap_or_else(|e| {
                                                    warn!("{qdesc}: upstream failed: {e:#}");
                                                    dns::servfail(&query)
                                                });
                                            debug!("{qdesc}: answered in {:?}", started.elapsed());
                                            let _ = tx.send(Finished {
                                                stream_id,
                                                response,
                                            });
                                            notify.notify_one();
                                        });
                                    }
                                    Frame::Invalid => {
                                        warn!("DoQ stream {stream_id}: invalid framing, resetting");
                                        reset = true;
                                        break;
                                    }
                                    Frame::Incomplete => break,
                                }
                            }
                            if reset {
                                break;
                            }
                            if n == 0 {
                                break;
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            debug!("DoQ stream {stream_id}: receive failed: {e}");
                            reset = true;
                            break;
                        }
                    }
                }
                if !reset && state.client_fin {
                    if !state.buf.is_empty() {
                        // FIN arrived mid-frame: truncated query.
                        debug!("DoQ stream {stream_id}: truncated query at FIN, resetting");
                        reset = true;
                    } else if state.outstanding == 0 {
                        close = true;
                    }
                }
            }

            if reset {
                let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                self.streams.remove(&stream_id);
            } else if close {
                let _ = qconn.stream_send(stream_id, &[], true);
                self.streams.remove(&stream_id);
            }
        }
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut still_blocked = VecDeque::new();
        while let Some((stream_id, offset, frame, fin)) = self.outbound.pop_front() {
            match qconn.stream_send(stream_id, &frame[offset..], false) {
                Ok(n) if offset + n == frame.len() => {
                    if fin {
                        let _ = qconn.stream_send(stream_id, &[], true);
                        self.streams.remove(&stream_id);
                    }
                }
                Ok(n) => still_blocked.push_back((stream_id, offset + n, frame, fin)),
                Err(quiche::Error::Done) => {
                    still_blocked.push_back((stream_id, offset, frame, fin))
                }
                Err(e) => {
                    debug!("DoQ stream {stream_id}: flush failed: {e}");
                    let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                    self.streams.remove(&stream_id);
                }
            }
        }
        self.outbound = still_blocked;

        while let Ok(Finished {
            stream_id,
            response,
        }) = self.rx.try_recv()
        {
            let Some(state) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            state.outstanding = state.outstanding.saturating_sub(1);

            let Some(resp) = response else {
                if state.client_fin && state.outstanding == 0 {
                    let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                    self.streams.remove(&stream_id);
                }
                continue;
            };

            let fin = state.client_fin && state.outstanding == 0;
            let frame = dns::encode_frame(&resp);
            self.send_frame(qconn, stream_id, frame, fin);
        }
        Ok(())
    }
}
