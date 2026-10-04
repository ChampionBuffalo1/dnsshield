use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use futures::StreamExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::{HandshakeInfo, QuicheConnection};
use tokio_quiche::quiche;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{ApplicationOverQuic, ConnectionParams, QuicConnectionStream, QuicResult};
use tracing::{debug, info, warn};

use crate::limits::{ConnGuard, Governance};
use crate::model::Proto;
use crate::upstream::Upstream;
use crate::util::{Frame, describe_query, encode_frame, rcode_name, servfail, take_frame};

const DOQ_ALPN: &[u8] = b"doq";

const RECV_CHUNK: usize = 4096;

/// Per-connection cap on queries in flight towards the upstream. RFC 9250
/// clients send one query per stream, so this only trips on pipelining
/// abuse; the offending stream is reset rather than buffering more work.
const MAX_OUTSTANDING_PER_CONN: usize = 128;

pub async fn serve(
    sockets: Vec<UdpSocket>,
    cert_path: PathBuf,
    key_path: PathBuf,
    upstream: Arc<Upstream>,
    gov: Arc<Governance>,
) -> anyhow::Result<()> {
    let cert = cert_path
        .to_str()
        .context("certificate path is not valid UTF-8")?;
    let key = key_path.to_str().context("key path is not valid UTF-8")?;

    let mut settings = QuicSettings::default();
    settings.alpn = vec![DOQ_ALPN.to_vec()];
    settings.max_idle_timeout = Some(gov.limits.idle);
    settings.handshake_timeout = Some(gov.limits.handshake_timeout);
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
        let upstream = Arc::clone(&upstream);
        let gov = Arc::clone(&gov);
        tokio::spawn(async move {
            accept_loop(&mut listener, upstream, gov).await;
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}

async fn accept_loop(
    listener: &mut QuicConnectionStream<DefaultMetrics>,
    upstream: Arc<Upstream>,
    gov: Arc<Governance>,
) {
    while let Some(conn) = listener.next().await {
        match conn {
            Ok(initial) => {
                let peer = initial.peer_addr();
                match gov.gate.try_acquire(peer, Proto::Doq) {
                    Ok(guard) => {
                        initial.start(DoqConnection::new(
                            Arc::clone(&upstream),
                            Arc::clone(&gov),
                            guard,
                            peer,
                        ));
                    }
                    Err(_) => {
                        // At a cap: dropping the connection before
                        // start() skips the handshake entirely. The gate
                        // already counted and logged (throttled).
                        let _ = initial;
                    }
                }
            }
            Err(e) => {
                let throttle = Arc::clone(&gov.throttle);
                throttle.warn("doq-accept", move || {
                    format!("DoQ connection attempt failed: {e}")
                });
            }
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
    partial_since: Option<Instant>,
}

pub struct DoqConnection {
    upstream: Arc<Upstream>,
    gov: Arc<Governance>,
    _guard: ConnGuard,
    peer: SocketAddr,
    started: Instant,
    streams: HashMap<u64, StreamState>,
    outstanding_total: usize,
    outbound: VecDeque<(u64, usize, Vec<u8>, bool)>,
    tx: mpsc::UnboundedSender<Finished>,
    rx: mpsc::UnboundedReceiver<Finished>,
    notify: Arc<tokio::sync::Notify>,
}

impl DoqConnection {
    pub fn new(
        upstream: Arc<Upstream>,
        gov: Arc<Governance>,
        guard: ConnGuard,
        peer: SocketAddr,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            upstream,
            gov,
            _guard: guard,
            peer,
            started: Instant::now(),
            streams: HashMap::new(),
            outstanding_total: 0,
            outbound: VecDeque::new(),
            tx,
            rx,
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn remove_stream(&mut self, stream_id: u64) {
        if let Some(state) = self.streams.remove(&stream_id) {
            self.outstanding_total = self.outstanding_total.saturating_sub(state.outstanding);
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
                    self.remove_stream(stream_id);
                }
            }
            Ok(n) => self.outbound.push_back((stream_id, n, frame, fin)),
            Err(quiche::Error::Done) => self.outbound.push_back((stream_id, 0, frame, fin)),
            Err(e) => {
                debug!("DoQ stream {stream_id}: send failed: {e}");
                let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                self.remove_stream(stream_id);
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
                                match take_frame(&mut state.buf) {
                                    Frame::Complete(query) => {
                                        if self.outstanding_total >= MAX_OUTSTANDING_PER_CONN {
                                            let throttle = Arc::clone(&self.gov.throttle);
                                            let peer = self.peer;
                                            throttle.warn("doq-outstanding", move || {
                                                format!(
                                                    "DoQ {peer}: over \
                                                     {MAX_OUTSTANDING_PER_CONN} queries in \
                                                     flight, resetting stream {stream_id}"
                                                )
                                            });
                                            reset = true;
                                            break;
                                        }
                                        state.outstanding += 1;
                                        self.outstanding_total += 1;
                                        let tx = self.tx.clone();
                                        let notify = Arc::clone(&self.notify);
                                        let upstream = Arc::clone(&self.upstream);
                                        let peer = self.peer;
                                        let qdesc = describe_query(&query);
                                        tokio::spawn(async move {
                                            let started = Instant::now();
                                            let response =
                                                match upstream.resolve(Proto::Doq, &query).await {
                                                    Ok(resp) => {
                                                        info!(
                                                            %peer,
                                                            "{qdesc}: answered {} in {:?}",
                                                            rcode_name(&resp),
                                                            started.elapsed()
                                                        );
                                                        Some(resp)
                                                    }
                                                    Err(e) => {
                                                        warn!(
                                                            %peer,
                                                            "{qdesc}: upstream failed in {:?} \
                                                             (served SERVFAIL): {e:#}",
                                                            started.elapsed()
                                                        );
                                                        servfail(&query)
                                                    }
                                                };
                                            let _ = tx.send(Finished {
                                                stream_id,
                                                response,
                                            });
                                            notify.notify_one();
                                        });
                                    }
                                    Frame::Invalid => {
                                        let throttle = Arc::clone(&self.gov.throttle);
                                        let peer = self.peer;
                                        throttle.warn("doq-framing", move || {
                                            format!(
                                                "DoQ {peer}: invalid framing on stream \
                                                 {stream_id}, resetting"
                                            )
                                        });
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
                state.partial_since = if state.buf.is_empty() {
                    None
                } else {
                    Some(state.partial_since.unwrap_or_else(Instant::now))
                };
            }

            if reset {
                let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                self.remove_stream(stream_id);
            } else if close {
                let _ = qconn.stream_send(stream_id, &[], true);
                self.remove_stream(stream_id);
            }
        }
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if let Some(max) = self.gov.limits.max_session
            && self.started.elapsed() >= max
        {
            let throttle = Arc::clone(&self.gov.throttle);
            let peer = self.peer;
            throttle.warn("doq-session", move || {
                format!("DoQ {peer}: session exceeded {max:?}, closing")
            });
            let _ = qconn.close(true, 1, b"max session");
            return Ok(());
        }

        let idle = self.gov.limits.idle;
        let stale: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, state)| {
                state
                    .partial_since
                    .is_some_and(|since| since.elapsed() >= idle)
            })
            .map(|(id, _)| *id)
            .collect();
        for stream_id in stale {
            let throttle = Arc::clone(&self.gov.throttle);
            let peer = self.peer;
            throttle.warn("doq-framing", move || {
                format!("DoQ {peer}: incomplete query after {idle:?}, resetting stream {stream_id}")
            });
            let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
            self.remove_stream(stream_id);
        }

        let mut still_blocked = VecDeque::new();
        while let Some((stream_id, offset, frame, fin)) = self.outbound.pop_front() {
            match qconn.stream_send(stream_id, &frame[offset..], false) {
                Ok(n) if offset + n == frame.len() => {
                    if fin {
                        let _ = qconn.stream_send(stream_id, &[], true);
                        self.remove_stream(stream_id);
                    }
                }
                Ok(n) => still_blocked.push_back((stream_id, offset + n, frame, fin)),
                Err(quiche::Error::Done) => {
                    still_blocked.push_back((stream_id, offset, frame, fin))
                }
                Err(e) => {
                    debug!("DoQ stream {stream_id}: flush failed: {e}");
                    let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                    self.remove_stream(stream_id);
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
            self.outstanding_total = self.outstanding_total.saturating_sub(1);

            let Some(resp) = response else {
                if state.client_fin && state.outstanding == 0 {
                    let _ = qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, 1);
                    self.remove_stream(stream_id);
                }
                continue;
            };

            let fin = state.client_fin && state.outstanding == 0;
            let frame = encode_frame(&resp);
            self.send_frame(qconn, stream_id, frame, fin);
        }
        Ok(())
    }

    fn on_conn_close<M: Metrics>(
        &mut self,
        _qconn: &mut QuicheConnection,
        _metrics: &M,
        _connection_result: &QuicResult<()>,
    ) {
    }
}
