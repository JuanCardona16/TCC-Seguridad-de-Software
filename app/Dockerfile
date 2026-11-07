# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/minigestor /tmp/minigestor

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data app \
 && mkdir -p /data/docs \
 && chown -R app:app /data

COPY --from=builder /tmp/minigestor /usr/local/bin/minigestor

USER app
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["minigestor"]
