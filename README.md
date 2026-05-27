# DoH Relay

A lightweight DNS-over-HTTPS (DoH) relay server written in Rust. 

**Motivation:** This tool was created specifically to solve compatibility issues with [Numa](https://github.com/razvandimescu/numa). Numa currently does not support processing DoH queries via HTTP `GET` requests. This relay bridges that gap by listening for HTTP `GET` DNS queries (via the `?dns=` query parameter), decoding them, and forwarding them to the Numa upstream server using the `POST` method.

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
- `DEBUG`: Set to `true` to enable detailed access logging (client IP, request method, URI, and headers). (Default: `false`).

### Running the Relay

```bash
# Set the upstream URL and enable debug logging
export NUMA_URL="https://dns.google/dns-query"
export DEBUG="true"

# Run the relay
cargo run
```

The server will listen on `0.0.0.0:5381`.

### Testing the Relay

You can test the relay using `curl`. A DNS query for `google.com` (Type A) encoded in Base64URL is `q80BAAABAAAAAAAAA3d3dwdnb29nbGUDY29tAAABAAE`:

```bash
curl "http://127.0.0.1:5381/?dns=q80BAAABAAAAAAAAA3d3dwdnb29nbGUDY29tAAABAAE"
```

## Real Client IP Preservation (PROXY Protocol v2)

Since Numa's internal DNS-over-HTTPS (DoH) engine processes client IP addresses purely at the L4 connection layer (completely ignoring HTTP headers like `X-Forwarded-For` or `X-Real-IP`), **PROXY Protocol v2 is required** for Numa to see the original client IP in its query logs and ad-blocking controls.

This relay automatically prepends the PROXY Protocol v2 binary header to the upstream TLS connection. 

### 1. Configure Numa (`numa.toml`)
You must enable PROXY Protocol in your `numa.toml` configuration on the Numa server. Add the following block, making sure to trust the IP ranges corresponding to your Docker container networks (typically `172.16.0.0/12`):

```toml
[proxy.proxy_protocol]
# Trust Docker's private bridge networks to send the PROXY header
from = ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
header_timeout_ms = 5000
```

### 2. TLS Certification Note
This relay intentionally skips TLS certificate verification for the upstream server. This is designed to facilitate secure, local inter-container communication without requiring strict, public CA verification for internal hostnames like `https://numa/...`.

---

## Docker Compose

The recommended way to deploy both `doh-relay` and `numa` together is using Docker Compose. Create a `docker-compose.yml` file and mount your custom `numa.toml` configuration:

```yaml
services:
  numa:
    image: ghcr.io/razvandimescu/numa
    container_name: numa
    restart: unless-stopped
    ports:
      - "53:53"
      - "53:53/udp"
      - "5380:5380"
    volumes:
      # Bind mount your custom numa.toml configuration file
      - ./numa.toml:/root/.config/numa/numa.toml

  doh-relay:
    image: ghcr.io/beeeeemo/doh-relay:latest
    container_name: doh-relay
    ports:
      - "5381:5381"
    environment:
      - NUMA_URL=https://numa/dns-query
      - DEBUG=true
    restart: unless-stopped

networks:
  default:
    external: true
    name: ferron_net
```

Then deploy the services:
```bash
docker compose up -d
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
