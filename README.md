# dnsshield

A small encrypted DNS forwarding server. It speaks DNS-over-TLS (DoT) and
DNS-over-QUIC (DoQ) on port 853 and forwards queries to a plain-DNS
resolver like 1.1.1.1. Anything the upstream can't answer gets a SERVFAIL
instead of a timeout.

## Building

Needs Rust, cmake, and a C compiler (the QUIC and TLS libraries build C
code).

```
cargo build --release
```

## Running

```
./target/release/dnsshield \
    --cert fullchain.pem \
    --key privkey.pem \
    --upstream 9.9.9.9:53 \
    --listen 0.0.0.0:853 --listen '[::]:853'
```

Options:

- `--listen ADDR` — addresses to bind, repeatable. Defaults to
  `0.0.0.0:853` and `[::]:853`. TCP is DoT, UDP is DoQ.
- `--upstream IP:PORT` — plain-DNS resolver to forward to. Default
  `1.1.1.1:53`, must be an IP literal.
- `--cert FILE` / `--key FILE` — TLS certificate and key in PEM format,
  required.
- `--idle-timeout-secs N` — QUIC idle timeout for DoQ, default 30.

## Docker

```
docker pull ghcr.io/championbuffalo1/dnsshield:latest

docker run -d --name dnsshield \
    -p 853:853/tcp -p 853:853/udp \
    -v /etc/letsencrypt/live/dns.example.com:/certs:ro \
    ghcr.io/championbuffalo1/dnsshield:latest \
    --cert /certs/fullchain.pem --key /certs/privkey.pem
```

Or build it locally instead of pulling:

```
docker build -t dnsshield .
```

The container runs as an unprivileged user with just
`cap_net_bind_service` added so it can bind 853. Make sure the cert
files it mounts are readable by that user. On rootless Docker the
capability gets dropped, so listen on a high port instead:
`-p 853:8853/tcp -p 853:8853/udp` plus `--listen 0.0.0.0:8853`.
