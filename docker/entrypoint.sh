#!/bin/sh
set -ef

if [ -n "${DNSSHIELD_LISTEN:-}" ]; then
    set -- --listen "${DNSSHIELD_LISTEN}" "$@"
fi

if [ -n "${DNSSHIELD_DOT_PORT:-}" ]; then
    set -- --dot-port "${DNSSHIELD_DOT_PORT}" "$@"
fi

if [ -n "${DNSSHIELD_DOQ_PORT:-}" ]; then
    set -- --doq-port "${DNSSHIELD_DOQ_PORT}" "$@"
fi

if [ -n "${DNSSHIELD_DOH_PORT:-}" ]; then
    set -- --doh-port "${DNSSHIELD_DOH_PORT}" "$@"
fi

if [ -n "${DNSSHIELD_PROTO:-}" ]; then
    set -- --proto "${DNSSHIELD_PROTO}" "$@"
fi

if [ -n "${DNSSHIELD_UPSTREAM:-}" ]; then
    set -- --upstream "${DNSSHIELD_UPSTREAM}" "$@"
fi

if [ -n "${DNSSHIELD_CERT:-}" ]; then
    set -- --cert "${DNSSHIELD_CERT}" "$@"
fi

if [ -n "${DNSSHIELD_KEY:-}" ]; then
    set -- --key "${DNSSHIELD_KEY}" "$@"
fi

if [ -n "${DNSSHIELD_IDLE_TIMEOUT_SECS:-}" ]; then
    set -- --idle-timeout-secs "${DNSSHIELD_IDLE_TIMEOUT_SECS}" "$@"
fi

if [ -n "${DNSSHIELD_MAX_CONNECTIONS:-}" ]; then
    set -- --max-connections "${DNSSHIELD_MAX_CONNECTIONS}" "$@"
fi

if [ -n "${DNSSHIELD_MAX_CONNECTIONS_PER_IP:-}" ]; then
    set -- --max-connections-per-ip "${DNSSHIELD_MAX_CONNECTIONS_PER_IP}" "$@"
fi

if [ -n "${DNSSHIELD_HANDSHAKE_TIMEOUT_SECS:-}" ]; then
    set -- --handshake-timeout-secs "${DNSSHIELD_HANDSHAKE_TIMEOUT_SECS}" "$@"
fi

if [ -n "${DNSSHIELD_MAX_SESSION_SECS:-}" ]; then
    set -- --max-session-secs "${DNSSHIELD_MAX_SESSION_SECS}" "$@"
fi

if [ -n "${DNSSHIELD_LOG_LEVEL:-}" ]; then
    set -- --log-level "${DNSSHIELD_LOG_LEVEL}" "$@"
fi

if [ -n "${DNSSHIELD_METRICS_LISTEN:-}" ]; then
    set -- --metrics-listen "${DNSSHIELD_METRICS_LISTEN}" "$@"
fi

exec dnsshield "$@"
