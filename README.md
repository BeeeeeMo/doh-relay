# DoH Relay

A lightweight DNS-over-HTTPS (DoH) relay server written in Rust. This tool listens for DNS queries over HTTP (via the `?dns=` query parameter) and forwards them to a designated upstream DoH server using the POST method.

## Features

- **Modern Tech Stack**: Built with [Hyper 1.0](https://hyper.rs/), [Tokio](https://tokio.rs/), and [Rustls 0.23](https://github.com/rustls/rustls).
- **High Performance**: Asynchronous I/O powered by Tokio for handling multiple concurrent requests efficiently.
- **Base64URL Support**: Automatically handles Base64URL padding and decoding for DNS queries.
- **Upstream Forwarding**: Forwards decapsulated DNS messages to a DoH upstream (e.g., Google, Cloudflare, or a private Numa node).
- **Insecure Mode**: Bypasses TLS verification for the upstream connection (similar to Python's `ssl._create_unverified_context`), useful for development or internal relays.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)
- `cargo` (comes with Rust)

## Installation

Clone the repository and build the project:

```bash
git clone <repository-url>
cd doh-relay
cargo build --release
```

The binary will be available at `target/release/doh-relay`.

## Usage

### Environment Variables

- `NUMA_URL`: The URL of the upstream DoH server. (Default: empty string, please set this before running).

### Running the Relay

```bash
# Set the upstream URL
export NUMA_URL="https://dns.google/dns-query"

# Run the relay
cargo run
```

The server will listen on `0.0.0.0:5381`.

### Testing the Relay

You can test the relay using `curl`. A DNS query for `google.com` (Type A) encoded in Base64URL is `q80BAAABAAAAAAAAA3d3dwdnb29nbGUDY29tAAABAAE`:

```bash
curl "http://127.0.0.1:5381/?dns=q80BAAABAAAAAAAAA3d3dwdnb29nbGUDY29tAAABAAE"
```

## Configuration Note

This relay currently skips TLS certificate verification for the upstream server. This is intended for specific use cases (like mirroring certain Python relay behaviors) and should be used with caution in public production environments.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (if applicable).
