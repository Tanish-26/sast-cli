# ---------- STAGE 1: DEPENDENCY CACHE ----------
FROM rust:latest as chef

WORKDIR /app

# Install cargo-chef for caching
RUN cargo install cargo-chef

COPY . .

RUN cargo chef prepare --recipe-path recipe.json


# ---------- STAGE 2: BUILD ----------
FROM rust:latest as builder

WORKDIR /app

RUN cargo install cargo-chef

# Copy dependency recipe
COPY --from=chef /app/recipe.json recipe.json

# Build dependencies (cached layer 🔥)
RUN cargo chef cook --release --recipe-path recipe.json

# Copy actual source
COPY . .

# Build final binary
RUN cargo build --release -p sast-cli


# ---------- STAGE 3: MINIMAL RUNTIME ----------
FROM debian:bookworm-slim

WORKDIR /app

# Create non-root user (security 🔐)
RUN useradd -m appuser

# Copy binary only (THIS is why image is small 🔥)
COPY --from=builder /app/target/release/sast-cli /usr/local/bin/sast-cli

RUN chmod +x /usr/local/bin/sast-cli

USER appuser

ENTRYPOINT ["sast-cli"]
