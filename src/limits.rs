//! Runtime governance: connection admission control and log throttling.
//!
//! Observability (counters, gauges, latency, the periodic log summary)
//! lives in [`crate::metrics`]; this module is the control plane that
//! decides what gets in, plus the [`Throttle`] the observability side
//! borrows to keep its own logging quiet.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::info;

use crate::metrics::{Metrics, Proto};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// How long a connection may go without traffic before it is closed.
    pub idle: Duration,
    /// How long a TLS/QUIC handshake may take.
    pub handshake_timeout: Duration,
    /// Hard wall-clock cap on one client session (`None` = unlimited).
    pub max_session: Option<Duration>,
    /// Global concurrent connection cap (`0` = unlimited).
    pub max_connections: usize,
    /// Per-client-IP concurrent connection cap (`0` = unlimited).
    pub max_connections_per_ip: usize,
}

pub struct Throttle {
    window: Duration,
    entries: Mutex<HashMap<&'static str, Entry>>,
}

#[derive(Default)]
struct Entry {
    suppressed: u64,
    until: Option<Instant>,
}

impl Throttle {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn gate(&self, key: &'static str) -> Option<u64> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key).or_default();
        if matches!(entry.until, Some(until) if until > now) {
            entry.suppressed += 1;
            return None;
        }
        let suppressed = std::mem::take(&mut entry.suppressed);
        entry.until = Some(now + self.window);
        Some(suppressed)
    }

    pub fn warn(&self, key: &'static str, message: impl FnOnce() -> String) {
        if let Some(suppressed) = self.gate(key) {
            let suffix = if suppressed > 0 {
                format!(" [+{suppressed} suppressed]")
            } else {
                String::new()
            };
            tracing::warn!("{}{}", message(), suffix);
        }
    }

    pub fn info(&self, key: &'static str, message: impl FnOnce() -> String) {
        if let Some(suppressed) = self.gate(key) {
            let suffix = if suppressed > 0 {
                format!(" [+{suppressed} suppressed]")
            } else {
                String::new()
            };
            info!("{}{}", message(), suffix);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    Total,
    PerIp,
}

/// Admission control for client connections: a global cap plus a per-IP cap,
/// enforced before any TLS/QUIC handshake work, with RAII guards
/// ([`ConnGuard`]) so the counts come back down on every exit path — task
/// panic, handshake failure, idle timeout, clean close.
pub struct Gatekeeper {
    max_connections: usize,
    max_connections_per_ip: usize,
    state: Mutex<LimiterState>,
    metrics: Arc<Metrics>,
    throttle: Arc<Throttle>,
}

#[derive(Default)]
struct LimiterState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl Gatekeeper {
    pub fn new(limits: &Limits, metrics: Arc<Metrics>, throttle: Arc<Throttle>) -> Self {
        Self {
            max_connections: limits.max_connections,
            max_connections_per_ip: limits.max_connections_per_ip,
            state: Mutex::new(LimiterState::default()),
            metrics,
            throttle,
        }
    }

    /// Reserve a connection slot for `peer` or reject it. Rejections are
    /// counted and logged (throttled) here, so callers only need to drop the
    /// connection.
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: SocketAddr,
        proto: Proto,
    ) -> Result<ConnGuard, Rejection> {
        let ip = peer.ip();
        let rejection = {
            let mut state = self.state.lock().unwrap();
            if self.max_connections != 0 && state.total >= self.max_connections {
                Some(Rejection::Total)
            } else if self.max_connections_per_ip != 0
                && state.per_ip.get(&ip).copied().unwrap_or(0) >= self.max_connections_per_ip
            {
                Some(Rejection::PerIp)
            } else {
                state.total += 1;
                *state.per_ip.entry(ip).or_insert(0) += 1;
                None
            }
        };
        match rejection {
            None => {
                self.metrics.conn_opened(proto);
                Ok(ConnGuard {
                    gate: Arc::clone(self),
                    peer: ip,
                    proto,
                })
            }
            Some(reason) => {
                self.metrics.note_rejected(proto);
                let throttle = Arc::clone(&self.throttle);
                match reason {
                    Rejection::Total => throttle.warn("reject-total", move || {
                        format!(
                            "{} connection from {peer} rejected: at --max-connections ({})",
                            proto.as_str(),
                            self.max_connections
                        )
                    }),
                    Rejection::PerIp => throttle.warn("reject-per-ip", move || {
                        format!(
                            "{} connection from {peer} rejected: at \
                             --max-connections-per-ip ({})",
                            proto.as_str(),
                            self.max_connections_per_ip
                        )
                    }),
                }
                Err(reason)
            }
        }
    }

    fn release(&self, peer: IpAddr, proto: Proto) {
        {
            let mut state = self.state.lock().unwrap();
            state.total = state.total.saturating_sub(1);
            match state.per_ip.get_mut(&peer) {
                Some(count) if *count <= 1 => {
                    state.per_ip.remove(&peer);
                }
                Some(count) => *count -= 1,
                None => {}
            }
        }
        self.metrics.conn_closed(proto);
    }
}

/// Releases a connection slot when dropped. Hold it for exactly as long as
/// the connection occupies server resources.
pub struct ConnGuard {
    gate: Arc<Gatekeeper>,
    peer: IpAddr,
    proto: Proto,
}

impl std::fmt::Debug for ConnGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnGuard")
            .field("peer", &self.peer)
            .field("proto", &self.proto.as_str())
            .finish()
    }
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.gate.release(self.peer, self.proto);
    }
}

/// Everything both servers and the upstream need to police the system,
/// bundled so it can be handed around as one `Arc`.
pub struct Governance {
    pub limits: Limits,
    pub metrics: Arc<Metrics>,
    pub throttle: Arc<Throttle>,
    pub gate: Arc<Gatekeeper>,
}

impl Governance {
    pub fn new(limits: Limits) -> Self {
        let metrics = Arc::new(Metrics::new().expect("metric definitions are static and valid"));
        let throttle = Arc::new(Throttle::new(Duration::from_secs(10)));
        let gate = Arc::new(Gatekeeper::new(
            &limits,
            Arc::clone(&metrics),
            Arc::clone(&throttle),
        ));
        Self {
            limits,
            metrics,
            throttle,
            gate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(max_total: usize, max_per_ip: usize) -> Arc<Gatekeeper> {
        let limits = Limits {
            idle: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(5),
            max_session: None,
            max_connections: max_total,
            max_connections_per_ip: max_per_ip,
        };
        Governance::new(limits).gate
    }

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }

    #[test]
    fn total_cap_enforced_and_released() {
        let gate = gate(2, 0);
        let g1 = gate.try_acquire(peer(1), Proto::Dot).unwrap();
        let _g2 = gate.try_acquire(peer(2), Proto::Doq).unwrap();
        assert_eq!(
            gate.try_acquire(peer(3), Proto::Dot).unwrap_err(),
            Rejection::Total
        );

        drop(g1);
        assert!(gate.try_acquire(peer(3), Proto::Doq).is_ok());
    }

    #[test]
    fn per_ip_cap_enforced_across_protocols() {
        let gate = gate(0, 1);
        // Hold the guard: dropping it would release the slot immediately.
        let _held = gate.try_acquire(peer(1), Proto::Dot).unwrap();
        // The cap is per client, not per listener.
        assert_eq!(
            gate.try_acquire(peer(1), Proto::Doq).unwrap_err(),
            Rejection::PerIp
        );
        // A different client is unaffected.
        let other_ip = SocketAddr::from(([203, 0, 113, 8], 9));
        assert!(gate.try_acquire(other_ip, Proto::Doq).is_ok());
    }

    #[test]
    fn zero_means_unlimited() {
        let gate = gate(0, 0);
        for i in 0..64 {
            let proto = if i % 2 == 0 { Proto::Dot } else { Proto::Doq };
            assert!(gate.try_acquire(peer(i), proto).is_ok());
        }
    }

    #[test]
    fn throttle_suppresses_within_window() {
        let throttle = Throttle::new(Duration::from_secs(600));
        assert_eq!(throttle.gate("k"), Some(0));
        assert_eq!(throttle.gate("k"), None);
        assert_eq!(throttle.gate("k"), None);
        // Different keys are independent.
        assert_eq!(throttle.gate("other"), Some(0));
    }
}
