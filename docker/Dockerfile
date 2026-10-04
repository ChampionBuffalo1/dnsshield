# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential clang cmake git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release \
    && strip target/release/dnsshield

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home dnsshield

COPY --from=build /src/target/release/dnsshield /usr/local/bin/dnsshield
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh \
    && setcap cap_net_bind_service=+ep /usr/local/bin/dnsshield

USER dnsshield

EXPOSE 853/tcp 853/udp 443/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
