# ---------- STAGE 1: CHEF ----------
FROM rust:1.88-slim-bookworm AS chef

WORKDIR /app

RUN cargo install cargo-chef --locked

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps ./apps
COPY services ./services

RUN cargo chef prepare --recipe-path recipe.json


# ---------- STAGE 2: BUILDER ----------
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

RUN cargo install cargo-chef --locked

# Copy dependency graph
COPY --from=chef /app/recipe.json recipe.json

# Build dependencies (cached 🔥)
RUN cargo chef cook --release --recipe-path recipe.json

# Copy full source AFTER caching
COPY . .

# Build binary (strip for smaller size 🔥)
RUN cargo build --release -p sast-cli && \
    strip target/release/sast-cli


# ---------- STAGE 3: MINIMAL RUNTIME ----------
FROM debian:bookworm-slim

# Install minimal runtime deps (optional but safe)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /scan

# Non-root user 🔐
RUN useradd -m appuser

# Copy only binary
COPY --from=builder /app/target/release/sast-cli /usr/local/bin/sast-cli

RUN chmod +x /usr/local/bin/sast-cli

USER appuser

ENTRYPOINT ["sast-cli"]
