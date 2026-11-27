//! Certificate pinning against a tiny HTTPS server with a self-signed ECDSA P-256 certificate.
#![cfg(feature = "webdav")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use pass_core::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct Server {
    url: String,
    pin: String,
}

/// Serves one vault file over HTTPS (GET / HEAD / PUT with `If-None-Match` / `If-Match`).
fn serve() -> Server {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let pin = spki_pin(&cert).unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store: Arc<Mutex<(Option<Vec<u8>>, u64)>> = Arc::default();
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let stream = rustls::StreamOwned::new(conn, tcp);
            // A client that rejects the certificate aborts the handshake: just move on.
            let _ = handle(stream, &store);
        }
    });
    // An IP address, not the certificate's name: pinned connections don't check names.
    Server {
        url: format!("https://{addr}/dav/me/pass.vault"),
        pin,
    }
}

fn handle<S: Read + Write>(
    stream: S,
    store: &Mutex<(Option<Vec<u8>>, u64)>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let method = line.split_whitespace().next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h)?;
        if h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let header = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    let mut body = vec![0; header("content-length").map_or(0, |l| l.parse().unwrap())];
    reader.read_exact(&mut body)?;
    let mut store = store.lock().unwrap();
    let etag = format!("\"v{}\"", store.1);
    let (status, extra, payload) = match method.as_str() {
        "GET" | "HEAD" => match &store.0 {
            Some(b) => (
                "200 OK",
                format!("ETag: {etag}\r\n"),
                if method == "GET" {
                    b.clone()
                } else {
                    Vec::new()
                },
            ),
            None => ("404 Not Found", String::new(), Vec::new()),
        },
        "PUT" => {
            let ok = match (header("if-match"), header("if-none-match")) {
                (Some(m), _) => store.0.is_some() && m == etag,
                (_, Some(_)) => store.0.is_none(),
                _ => true,
            };
            if ok {
                store.0 = Some(body);
                store.1 += 1;
                ("201 Created", String::new(), Vec::new())
            } else {
                ("412 Precondition Failed", String::new(), Vec::new())
            }
        }
        _ => ("405 Method Not Allowed", String::new(), Vec::new()),
    };
    let stream = reader.get_mut();
    write!(
        stream,
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        if method == "HEAD" { 0 } else { payload.len() }
    )?;
    stream.write_all(&payload)?;
    stream.flush()
}

fn config(server: &Server, pins: Vec<String>) -> WebDavConfig {
    WebDavConfig {
        url: server.url.clone(),
        username: "me".into(),
        password: "pst_secret".into(),
        pins,
    }
}

fn small_vault(device: &str) -> Arc<Vault> {
    let kdf = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    };
    Vault::create_with_kdf("pw", device, kdf).unwrap()
}

#[test]
fn pinned_server_syncs() {
    let server = serve();
    let pinned = config(&server, vec![server.pin.clone()]);
    assert!(!webdav_exists(pinned.clone()).unwrap());

    let laptop = small_vault("laptop");
    laptop
        .upsert(Item {
            title: "A".into(),
            ..Default::default()
        })
        .unwrap();
    let r = webdav_sync(laptop.clone(), pinned.clone()).unwrap();
    assert!(r.uploaded && r.created_remote);
    assert!(webdav_exists(pinned.clone()).unwrap());

    let phone = Vault::unlock(
        webdav_download(pinned.clone()).unwrap(),
        "pw".into(),
        "phone".into(),
    )
    .unwrap();
    assert_eq!(phone.items().len(), 1);

    // Another pin next to the right one (e.g. a key rotation) still connects.
    let two = config(
        &server,
        vec![
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            server.pin.clone(),
        ],
    );
    assert!(webdav_exists(two).unwrap());
}

#[test]
fn wrong_pin_is_certificate_changed() {
    let server = serve();
    let wrong = config(
        &server,
        vec!["sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
    );
    for err in [
        webdav_exists(wrong.clone()).unwrap_err(),
        webdav_download(wrong.clone()).unwrap_err(),
        webdav_sync(small_vault("a"), wrong).unwrap_err(),
    ] {
        match err {
            PassError::CertificateChanged(msg) => assert!(msg.contains(&server.pin), "{msg}"),
            other => panic!("expected CertificateChanged, got {other:?}"),
        }
    }
}

#[test]
fn without_pins_the_self_signed_certificate_is_rejected() {
    let server = serve();
    match webdav_exists(config(&server, Vec::new())) {
        Err(PassError::Network(msg)) => assert!(msg.contains("connect"), "{msg}"),
        other => panic!("expected a network error, got {other:?}"),
    }
}

#[test]
fn malformed_pins_are_invalid_input() {
    let server = serve();
    assert!(matches!(
        webdav_exists(config(&server, vec!["sha256:nope".into()])),
        Err(PassError::InvalidInput(_))
    ));
}

#[test]
fn fetch_server_pin_reads_the_unverified_key() {
    let server = serve();
    // From a full URL with a path, and from a bare `host:port`.
    assert_eq!(fetch_server_pin(server.url.clone()).unwrap(), server.pin);
    let host_port = server
        .url
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(fetch_server_pin(host_port).unwrap(), server.pin);
    assert!(!webdav_exists(config(&server, vec![server.pin.clone()])).unwrap());
}

#[test]
fn fetch_server_pin_errors() {
    assert!(matches!(
        fetch_server_pin("http://127.0.0.1:1".into()),
        Err(PassError::InvalidInput(_))
    ));
    assert!(matches!(
        fetch_server_pin("".into()),
        Err(PassError::InvalidInput(_))
    ));
    // Nothing listens there (a port just released).
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert!(matches!(
        fetch_server_pin(format!("https://127.0.0.1:{port}")),
        Err(PassError::Network(_))
    ));
}
