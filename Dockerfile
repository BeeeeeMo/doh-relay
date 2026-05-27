# --- Stage 1: Builder ---
FROM rust:1.85-alpine AS builder

# Install build dependencies for musl and crypto libraries
RUN apk add --no-cache \
    musl-dev \
    gcc \
    make \
    cmake \
    perl \
    build-base \
    ca-certificates

WORKDIR /usr/src/doh-relay

# Add the musl target
RUN rustup target add x86_64-unknown-linux-musl

# Copy Cargo files and build dependencies to cache them
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -f target/x86_64-unknown-linux-musl/release/deps/doh_relay*

# Build the actual application
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-musl

# --- Stage 2: Runtime (Scratch) ---
FROM scratch

# Copy CA certificates for HTTPS support
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically linked binary
COPY --from=builder /usr/src/doh-relay/target/x86_64-unknown-linux-musl/release/doh-relay /doh-relay

# Default environment variables
ENV NUMA_URL=""
ENV DEBUG="false"

# Expose the relay port
EXPOSE 5381

# Run the application
ENTRYPOINT ["/doh-relay"]
