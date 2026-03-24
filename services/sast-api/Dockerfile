FROM rust:1.85-slim-bookworm AS builder
WORKDIR /work
COPY . .
RUN cargo build -p sast-api --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /work/target/release/sast-api /usr/local/bin/sast-api
ENV SAST_API_ADDR=0.0.0.0:8080
EXPOSE 8080
CMD ["/usr/local/bin/sast-api"]

