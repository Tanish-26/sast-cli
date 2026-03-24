FROM rust:1.85-slim-bookworm AS builder
WORKDIR /work
COPY . .
RUN cargo build -p rbom-api --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /work/target/release/rbom-api /usr/local/bin/rbom-api
ENV RBOM_API_ADDR=0.0.0.0:8081
EXPOSE 8081
CMD ["/usr/local/bin/rbom-api"]

