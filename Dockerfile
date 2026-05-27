# --- Stage 1: Builder ---
# Use the official Rust Alpine image for static musl compilation
FROM --platform=$BUILDPLATFORM rust:1.85-alpine AS builder

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

# 1. Copy Cargo files to cache dependencies
COPY Cargo.toml Cargo.lock ./

# 2. Build dependencies only (cached if Cargo files don't change)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/doh_relay*

# 3. Build the actual application
COPY src ./src
RUN cargo build --release

# --- Stage 2: Runtime (Scratch) ---
FROM scratch

# Copy root CA certificates for HTTPS support
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically linked binary
COPY --from=builder /usr/src/doh-relay/target/release/doh-relay /doh-relay

# Default environment variables
ENV NUMA_URL=""
ENV DEBUG="false"

# Expose the relay port
EXPOSE 5381

# Run the binary
ENTRYPOINT ["/doh-relay"]
