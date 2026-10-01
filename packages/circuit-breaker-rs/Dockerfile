# Multi-stage build — no Rust toolchain needed on the host, same principle
# as this repo already uses for Envoy (packages/proxy builds FROM the
# envoyproxy/envoy image rather than needing Envoy installed locally).
FROM rust:slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.toml
COPY src src
RUN cargo build --release

FROM debian:bookworm-slim
# reqwest with rustls-tls (see Cargo.toml) needs no OpenSSL/CA-cert package,
# but ca-certificates is still worth having for any future TLS upstream.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/circuit-breaker-rs /usr/local/bin/circuit-breaker-rs
CMD ["circuit-breaker-rs"]
