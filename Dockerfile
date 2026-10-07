# syntax=docker/dockerfile:1.6

FROM rust:1-bookworm AS build

WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
COPY vendor ./vendor
COPY src ./src
COPY migrations ./migrations

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=rust-attester-target,target=/build/target \
    cargo build --release \
 && cp /build/target/release/rust-attester /usr/local/bin/rust-attester

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --user-group --create-home --system --home-dir /app attester
WORKDIR /app

COPY --from=build /usr/local/bin/rust-attester /app/rust-attester

USER attester:attester
EXPOSE 1993

ENTRYPOINT ["./rust-attester"]
