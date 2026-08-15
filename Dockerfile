FROM rust:1-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY config ./config

RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/data

COPY --from=builder /app/target/release/api_firewall /usr/local/bin/api_firewall
COPY config ./config

ENV APP_CONFIG_PATH=/app/config/production.yaml
EXPOSE 8080

CMD ["api_firewall"]
