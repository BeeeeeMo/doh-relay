# --- Stage 1: Builder ---
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies for crates like ring / aws-lc-sys
RUN apt-get update && apt-get install -y \
    cmake \
    perl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/doh-relay

# Copy Cargo files first to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies only
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/doh_relay*

# Copy the actual source code and build the application
COPY src ./src
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

# Install CA certificates (Required for HTTPS upstream connections)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/doh-relay/target/release/doh-relay /app/doh-relay

# Default environment variable
ENV NUMA_URL=""

# Expose the relay port
EXPOSE 5381

# Run the application
CMD ["./doh-relay"]
