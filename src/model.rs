use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Dot,
    Doq,
    Doh,
}

impl Proto {
    pub const ALL: [Proto; 3] = [Proto::Dot, Proto::Doq, Proto::Doh];

    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Dot => "dot",
            Proto::Doq => "doq",
            Proto::Doh => "doh",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Proto::Dot => "DoT (TCP)",
            Proto::Doq => "DoQ (UDP)",
            Proto::Doh => "DoH (HTTPS/TCP)",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamSpec {
    Udp(SocketAddr),
    Dot { host: String, port: u16 },
    Doh {
        host: String,
        port: u16,
        path: String,
    },
}

impl UpstreamSpec {
    fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("unterminated '[' in {s:?}"))?;
            let port = match after.strip_prefix(':') {
                Some(p) => p
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port in {s:?}"))?,
                None => default_port,
            };
            (host.to_string(), port)
        } else if let Some((host, port)) = s.rsplit_once(':') {
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("invalid port in {s:?}"))?;
            (host.to_string(), port)
        } else {
            (s.to_string(), default_port)
        };
        if host.is_empty() {
            return Err(format!("empty host in {s:?}"));
        }
        Ok((host, port))
    }
}

impl std::str::FromStr for UpstreamSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("udp://") {
            let addr = rest.parse::<SocketAddr>().map_err(|_| {
                "udp:// upstream must be an IP literal with port, e.g. udp://1.1.1.1:53".to_string()
            })?;
            return Ok(Self::Udp(addr));
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            let (host, port) = Self::split_host_port(rest, 853)?;
            return Ok(Self::Dot { host, port });
        }
        if let Some(rest) = s.strip_prefix("https://") {
            let (authority, mut path) = match rest.split_once('/') {
                Some((authority, path)) => (authority, format!("/{path}")),
                None => (rest, "/dns-query".to_string()),
            };
            if let Some(pos) = path.find("{?") {
                path.truncate(pos);
            }
            let (host, port) = Self::split_host_port(authority, 443)?;
            return Ok(Self::Doh { host, port, path });
        }
        if s.starts_with("http://") {
            return Err("plaintext http:// upstream is not supported; use https://".into());
        }
        if let Some((scheme, _)) = s.split_once("://") {
            return Err(format!(
                "unknown upstream scheme {scheme:?}; expected udp://, tls://, or https://"
            ));
        }
        let addr = s.parse::<SocketAddr>().map_err(|_| {
            "upstream must be IP:PORT, udp://IP:PORT, tls://HOST:PORT, or https://HOST/PATH \
             (the bare form requires an IP literal)"
                .to_string()
        })?;
        Ok(Self::Udp(addr))
    }
}

impl std::fmt::Display for UpstreamSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "udp://{addr}"),
            Self::Dot { host, port } => write!(f, "tls://{host}:{port}"),
            Self::Doh { host, port, path } => write!(f, "https://{host}:{port}{path}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_spec_parses_all_schemes() {
        let bare: UpstreamSpec = "1.1.1.1:53".parse().unwrap();
        assert_eq!(
            bare,
            UpstreamSpec::Udp(SocketAddr::from(([1, 1, 1, 1], 53)))
        );

        let udp: UpstreamSpec = "udp://[::1]:5353".parse().unwrap();
        assert_eq!(
            udp,
            UpstreamSpec::Udp(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 5353)))
        );

        let dot: UpstreamSpec = "tls://dns.example.com".parse().unwrap();
        assert_eq!(
            dot,
            UpstreamSpec::Dot {
                host: "dns.example.com".into(),
                port: 853
            }
        );

        let dot_port: UpstreamSpec = "tls://[2001:db8::1]:9953".parse().unwrap();
        assert_eq!(
            dot_port,
            UpstreamSpec::Dot {
                host: "2001:db8::1".into(),
                port: 9953
            }
        );

        let doh: UpstreamSpec = "https://dns.example.com/dns-query".parse().unwrap();
        assert_eq!(
            doh,
            UpstreamSpec::Doh {
                host: "dns.example.com".into(),
                port: 443,
                path: "/dns-query".into()
            }
        );

        let doh_default: UpstreamSpec = "https://dns.example.com".parse().unwrap();
        assert_eq!(
            doh_default,
            UpstreamSpec::Doh {
                host: "dns.example.com".into(),
                port: 443,
                path: "/dns-query".into()
            }
        );
        let doh_template: UpstreamSpec = "https://dns.example.com/dns-query{?dns}".parse().unwrap();
        assert_eq!(
            doh_template,
            UpstreamSpec::Doh {
                host: "dns.example.com".into(),
                port: 443,
                path: "/dns-query".into()
            }
        );
        let doh_port: UpstreamSpec = "https://dns.example.com:8443/dns-query".parse().unwrap();
        assert_eq!(
            doh_port,
            UpstreamSpec::Doh {
                host: "dns.example.com".into(),
                port: 8443,
                path: "/dns-query".into()
            }
        );
    }

    #[test]
    fn upstream_spec_rejects_garbage() {
        assert!("foo://1.1.1.1".parse::<UpstreamSpec>().is_err());
        assert!("http://1.1.1.1:53".parse::<UpstreamSpec>().is_err());
        assert!("udp://dns.example.com:53".parse::<UpstreamSpec>().is_err());
        assert!("1.2.3.4".parse::<UpstreamSpec>().is_err());
        assert!("tls://".parse::<UpstreamSpec>().is_err());
        assert!("tls://host:notaport".parse::<UpstreamSpec>().is_err());
    }
}
