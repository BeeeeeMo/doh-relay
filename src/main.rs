use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::timeout;
use tracing::{error, info, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

async fn handle(
    req: Request<Incoming>,
    client: Arc<
        Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            Full<Bytes>,
        >,
    >,
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody>, hyper::Error> {
    let upstream = env::var("NUMA_URL").unwrap_or_default();
    let debug_mode = env::var("DEBUG").map(|v| v == "true").unwrap_or(false);

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

    // Parse ?dns= query param
    let dns_b64 = req.uri().query().and_then(|q| {
        q.split('&')
            .find(|p| p.starts_with("dns="))
            .map(|p| &p[4..])
    });

    let dns_b64 = match dns_b64 {
        Some(v) => v.to_string(),
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full_body(Bytes::new()))
                .unwrap());
        }
    };

    // Decode base64url (pad to multiple of 4)
    let padded = format!("{:=<width$}", dns_b64, width = (dns_b64.len() + 3) / 4 * 4);
    let body_bytes = match URL_SAFE.decode(&padded) {
        Ok(b) => b,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full_body(Bytes::new()))
                .unwrap());
        }
    };

    let mut upstream_req = Request::post(&upstream)
        .header("Content-Type", "application/dns-message")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();

    // Transparently forward identity-related headers
    {
        let headers = upstream_req.headers_mut();
        for (name, value) in req.headers() {
            let name_str = name.as_str();
            if name_str
                .get(..3)
                .map(|s| s.eq_ignore_ascii_case("cf-"))
                .unwrap_or(false)
                || name_str
                    .get(..2)
                    .map(|s| s.eq_ignore_ascii_case("x-"))
                    .unwrap_or(false)
                || name_str.eq_ignore_ascii_case("forwarded")
                || name_str.eq_ignore_ascii_case("via")
            {
                headers.insert(name.clone(), value.clone());
            }
        }

        // Fallback: If X-Forwarded-For is missing, add the remote_addr
        if !headers.contains_key("X-Forwarded-For") {
            if let Ok(value) = remote_addr.ip().to_string().parse() {
                headers.insert("X-Forwarded-For", value);
            }
        }
    }

    // Upstream request with 5-second timeout
    match timeout(Duration::from_secs(5), client.request(upstream_req)).await {
        Ok(Ok(upstream_resp)) => {
            if debug_mode {
                info!("Upstream Response: {}", upstream_resp.status());
            }

            let (parts, body) = upstream_resp.into_parts();
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

            // Stream body back to client for memory efficiency
            let streamed_body = body.map_err(|e| hyper::Error::from(e)).boxed();

            Ok(builder.body(streamed_body).unwrap())
        }
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

fn full_body(chunk: Bytes) -> BoxBody {
    Full::new(chunk).map_err(|never| match never {}).boxed()
}

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = ([0, 0, 0, 0], 5381).into();
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();

    let client = Arc::new(Client::builder(TokioExecutor::new()).build(https));

    // Create a cancellation token or a way to signal shutdown
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

    // Spawn signal handler
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("failed to listen for event");
        info!("Shutdown signal received");
        let _ = tx.send(()).await;
    });

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, remote_addr)) => {
                        let io = TokioIo::new(stream);
                        let client = client.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service_fn(move |req| handle(req, client.clone(), remote_addr)))
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
