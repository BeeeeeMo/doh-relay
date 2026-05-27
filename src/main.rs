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
use tokio::net::TcpListener;

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
        .header("X-Forwarded-For", remote_addr.ip().to_string())
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();

    // Copy other relevant headers if needed, or just forward X-Real-IP
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        upstream_req
            .headers_mut()
            .insert("X-Real-IP", real_ip.clone());
    }

    match client.request(upstream_req).await {
        Ok(upstream_resp) => {
            let data = upstream_resp.into_body().collect().await?.to_bytes();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/dns-message")
                .header("Content-Length", data.len())
                .body(full_body(data))
                .unwrap())
        }
        Err(e) => {
            eprintln!("upstream error: {e}");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body(Bytes::new()))
                .unwrap())
        }
    }
}

fn full_body(chunk: Bytes) -> BoxBody {
    Full::new(chunk).map_err(|never| match never {}).boxed()
}

// Skip TLS cert verification (mirrors Python's ssl._create_unverified_context)
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
    let addr: SocketAddr = ([0, 0, 0, 0], 5381).into();
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    // TLS config with ring crypto provider
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

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let client = client.clone();

        tokio::task::spawn(async move {
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(
                    io,
                    service_fn(move |req| handle(req, client.clone(), remote_addr)),
                )
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
