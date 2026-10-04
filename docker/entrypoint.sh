#!/bin/sh
set -ef

if [ -n "${DNSSHIELD_LISTEN:-}" ]; then
    for addr in ${DNSSHIELD_LISTEN}; do
        set -- --listen "$addr" "$@"
    done
fi

if [ -n "${DNSSHIELD_HTTPS_LISTEN:-}" ]; then
    for addr in ${DNSSHIELD_HTTPS_LISTEN}; do
        set -- --https-listen "$addr" "$@"
    done
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
