use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

// ─── PROXY Protocol v2 ───────────────────────────────────────────────────────

/// Write a PROXY Protocol v2 binary header into the provided stack buffer.
///
/// `client_ip`   – the real end-user IP to advertise to the upstream.
/// `server_addr` – the SocketAddr we connected to (from `TcpStream::peer_addr`).
/// `buf`         – a mutable stack buffer (must be at least 52 bytes).
///
/// Returns the number of bytes written to the buffer.
/// The header is written onto the raw TCP socket **before** the TLS handshake,
/// so the upstream server sees the real client IP at the L4 layer.
fn write_pp2(client_ip: IpAddr, server_addr: SocketAddr, buf: &mut [u8; 52]) -> usize {
    const SIG: [u8; 12] = [
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a,
        0x51, 0x55, 0x49, 0x54, 0x0a,
    ];
    buf[..12].copy_from_slice(&SIG);

    match (client_ip, server_addr.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            buf[12] = 0x21; // version=2, command=PROXY
            buf[13] = 0x11; // TCP/IPv4
            buf[14..16].copy_from_slice(&12u16.to_be_bytes()); // address block length
            buf[16..20].copy_from_slice(&src.octets()); // src (real client)
            buf[20..24].copy_from_slice(&dst.octets()); // dst (Numa)
            buf[24..26].copy_from_slice(&0u16.to_be_bytes()); // src port (arbitrary)
            buf[26..28].copy_from_slice(&server_addr.port().to_be_bytes()); // dst port
            28
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            buf[12] = 0x21; // version=2, command=PROXY
            buf[13] = 0x21; // TCP/IPv6
            buf[14..16].copy_from_slice(&36u16.to_be_bytes());
            buf[16..32].copy_from_slice(&src.octets());
            buf[32..48].copy_from_slice(&dst.octets());
            buf[48..50].copy_from_slice(&0u16.to_be_bytes());
            buf[50..52].copy_from_slice(&server_addr.port().to_be_bytes());
            52
        }
        _ => {
            // Mixed AF (v4 client → v6 server or vice-versa).
            // Send LOCAL command; upstream falls back to the TCP peer address.
            buf[12] = 0x20; // version=2, command=LOCAL
            buf[13] = 0x00;
            buf[14..16].copy_from_slice(&0u16.to_be_bytes()); // no address block
            16
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the real client IP from proxy headers, falling back to the raw TCP
/// remote address.
///
/// Priority (highest first):
///   1. `CF-Connecting-IP`  (set by Cloudflare)
///   2. `X-Real-IP`         (set by Ferron / Nginx)
///   3. `X-Forwarded-For`   (first entry in the chain)
///   4. TCP `remote_addr`
fn real_client_ip(req: &Request<Incoming>, remote_addr: SocketAddr) -> IpAddr {
    req.headers()
        .get("cf-connecting-ip")
        .or_else(|| req.headers().get("x-real-ip"))
        .or_else(|| req.headers().get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| remote_addr.ip())
}

fn full_body(chunk: Bytes) -> BoxBody {
    Full::new(chunk).map_err(|never| match never {}).boxed()
}

fn into_box_response(resp: Response<Incoming>) -> Response<BoxBody> {
    let (parts, body) = resp.into_parts();
    let data_len = parts
        .headers
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());

    let mut builder = Response::builder()
        .status(parts.status)
        .header("Content-Type", "application/dns-message");
    if let Some(len) = data_len {
        builder = builder.header("Content-Length", len);
    }
    builder
        .body(body.map_err(hyper::Error::from).boxed())
        .unwrap()
}

// ─── Core forwarding logic ────────────────────────────────────────────────────

/// Open a fresh TCP connection to the upstream DoH server and forward the DNS
/// query as an HTTP/1.1 POST request.
///
/// When the upstream uses HTTPS this function:
///   1. Connects via TCP
///   2. Writes the PROXY Protocol v2 header onto the raw socket
///   3. Performs the TLS handshake (Numa reads PP2 before the TLS ClientHello)
///   4. Sends the HTTP POST via hyper's low-level http1 connector
///
/// Connection pooling is intentionally absent: DNS is stateless, and each
/// request must carry its own PP2 header with the correct client IP.
async fn forward_with_pp2(
    dns_body: Bytes,
    req_headers: &hyper::HeaderMap,
    client_ip: IpAddr,
    upstream_url: &str,
    tls_config: Arc<rustls::ClientConfig>,
    debug_mode: bool,
) -> Result<Response<BoxBody>, Box<dyn std::error::Error + Send + Sync>> {
    // ── Parse upstream URL ────────────────────────────────────────────────────
    let uri: hyper::Uri = upstream_url.parse()?;
    let host = uri.host().ok_or("NUMA_URL is missing a host")?.to_string();
    let use_tls = uri.scheme_str() == Some("https");
    let port = uri.port_u16().unwrap_or(if use_tls { 443 } else { 80 });
    // Preserve the full path+query string (e.g. /dns-query or /dns-query?foo=bar)
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // ── Build the upstream HTTP request ──────────────────────────────────────
    let upstream_req = {
        let mut builder = Request::builder()
            .method("POST")
            .uri(&path)
            .header("Host", &host)
            .header("Content-Type", "application/dns-message");

        let mut has_xff = false;
        for (name, value) in req_headers {
            let n = name.as_str();
            if n.starts_with("cf-") || n.starts_with("x-") || n == "forwarded" || n == "via" {
                if n == "x-forwarded-for" {
                    has_xff = true;
                }
                builder = builder.header(name.clone(), value.clone());
            }
        }
        if !has_xff {
            builder = builder.header("x-forwarded-for", client_ip.to_string());
        }
        builder.body(Full::new(dns_body))?
    };

    // ── TCP connect (async DNS resolution built in) ───────────────────────────
    let mut tcp = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    tcp.set_nodelay(true)?;
    let peer_addr = tcp.peer_addr()?;

    if use_tls {
        // ── Write PP2 header BEFORE TLS ──────────────────────────────────────
        // Numa's accept loop reads it from the raw TCP stream, then calls
        // TlsAcceptor::accept — so the ordering must be PP2 → TLS ClientHello.
        let mut pp2_buf = [0u8; 52];
        let len = write_pp2(client_ip, peer_addr, &mut pp2_buf);
        tcp.write_all(&pp2_buf[..len]).await?;

        // ── TLS handshake ─────────────────────────────────────────────────────
        let connector = TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| format!("invalid TLS server name: {e}"))?;
        let tls_stream = connector.connect(server_name, tcp).await?;

        // ── HTTP/1.1 over TLS ─────────────────────────────────────────────────
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
        tokio::spawn(conn); // drive the connection; outlives this fn for body streaming

        let resp = sender.send_request(upstream_req).await?;
        if debug_mode {
            info!("Upstream response [PP2+TLS]: {}", resp.status());
        }
        Ok(into_box_response(resp))
    } else {
        // ── Plain HTTP (no PP2; proxy headers still forwarded) ────────────────
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(conn);

        let resp = sender.send_request(upstream_req).await?;
        if debug_mode {
            info!("Upstream response [HTTP]: {}", resp.status());
        }
        Ok(into_box_response(resp))
    }
}

// ─── Request handler ──────────────────────────────────────────────────────────

async fn handle(
    req: Request<Incoming>,
    tls_config: Arc<rustls::ClientConfig>,
    upstream_url: Arc<String>,
    debug_mode: bool,
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody>, hyper::Error> {
    if debug_mode {
        info!(
            "Access Log: {} -> {} {}",
            remote_addr,
            req.method(),
            req.uri()
        );
        for (name, value) in req.headers() {
            info!("  Header: {}: {:?}", name, value);
        }
    }

    // ── Parse ?dns= query param ───────────────────────────────────────────────
    let dns_b64 = req.uri().query().and_then(|q| {
        q.split('&')
            .find(|p| p.starts_with("dns="))
            .map(|p| &p[4..])
    });

    let dns_b64 = match dns_b64 {
        Some(v) => v,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full_body(Bytes::new()))
                .unwrap());
        }
    };

    // ── Decode base64url ──────────────────────────────────────────────────────
    // Dynamically select the engine based on padding to avoid any heap-allocated string padding!
    let body_bytes = {
        let decode_res = if dns_b64.contains('=') {
            base64::engine::general_purpose::URL_SAFE.decode(dns_b64)
        } else {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_b64)
        };
        match decode_res {
            Ok(b) => Bytes::from(b),
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(full_body(Bytes::new()))
                    .unwrap());
            }
        }
    };

    // ── Real client IP for the PP2 header ─────────────────────────────────────
    let client_ip = real_client_ip(&req, remote_addr);

    // ── Forward with 5 s timeout ──────────────────────────────────────────────
    match timeout(
        Duration::from_secs(5),
        forward_with_pp2(
            body_bytes,
            req.headers(),
            client_ip,
            &upstream_url,
            tls_config,
            debug_mode,
        ),
    )
    .await
    {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => {
            error!("upstream error: {e}");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body(Bytes::new()))
                .unwrap())
        }
        Err(_) => {
            warn!("upstream request timed out");
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(full_body(Bytes::new()))
                .unwrap())
        }
    }
}

// ─── TLS: skip certificate verification for internal Numa node ───────────────

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let upstream_url = Arc::new(env::var("NUMA_URL").unwrap_or_default());
    let debug_mode = env::var("DEBUG").map(|v| v == "true").unwrap_or(false);

    let addr: SocketAddr = ([0, 0, 0, 0], 5381).into();
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Build the TLS client config once and share it via Arc (cheap clone).
    // NoVerifier is intentional: Numa uses an internal self-signed cert.
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
    );

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("failed to listen for ctrl-c");
        info!("Shutdown signal received");
        let _ = tx.send(()).await;
    });

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, remote_addr)) => {
                        let tls_config = tls_config.clone();
                        let upstream_url = upstream_url.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection(
                                    TokioIo::new(stream),
                                    service_fn(move |req| {
                                        handle(
                                            req,
                                            tls_config.clone(),
                                            upstream_url.clone(),
                                            debug_mode,
                                            remote_addr,
                                        )
                                    }),
                                )
                                .await
                            {
                                error!("Error serving connection: {:?}", err);
                            }
                        });
                    }
                    Err(e) => error!("Accept error: {:?}", e),
                }
            }
            _ = rx.recv() => {
                info!("Stopping server loop...");
                break;
            }
        }
    }

    info!("Server shut down gracefully");
    Ok(())
}
