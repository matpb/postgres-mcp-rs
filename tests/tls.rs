//! TLS paths of the wire client against an in-process server with certificates made at test time.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use postgres_mcp::config::Config;
use postgres_mcp::pg::pool::Pool;
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{AuthPolicy, ConnectConfig, Connection, WireError};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const PASSWORD: &str = "tls-fake-pw-4c1";

/// How the fake server answers the SSLRequest.
#[derive(Clone, Copy)]
enum Answer {
    /// `S`, then a TLS handshake.
    Tls,
    /// `N`, then plaintext.
    Plain,
    /// `S`, then bytes that are not a TLS handshake.
    BrokenTls,
}

/// What the fake server saw on the connection.
#[derive(Debug, Default)]
struct Served {
    handshake_done: bool,
    /// Body of the PasswordMessage the client sent, when it sent one.
    password: Option<Vec<u8>>,
}

struct Certs {
    ca_pem: String,
    leaf_chain: Vec<CertificateDer<'static>>,
    leaf_key: PrivateKeyDer<'static>,
    self_chain: Vec<CertificateDer<'static>>,
    self_key: PrivateKeyDer<'static>,
}

/// A CA, a leaf for `localhost` signed by it, and an unrelated self-signed leaf for `localhost`.
fn make_certs() -> Certs {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "pgmcp test ca");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    let self_key = KeyPair::generate().expect("self key");
    let self_params = CertificateParams::new(vec!["localhost".to_string()]).expect("self params");
    let self_cert = self_params.self_signed(&self_key).expect("self cert");

    Certs {
        ca_pem,
        leaf_chain: vec![leaf.der().clone()],
        leaf_key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        self_chain: vec![self_cert.der().clone()],
        self_key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self_key.serialize_der())),
    }
}

fn acceptor(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> TlsAcceptor {
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server cert");
    TlsAcceptor::from(Arc::new(config))
}

/// A PEM file under the temp dir, removed when dropped.
struct TempPem(PathBuf);

impl TempPem {
    fn write(name: &str, pem: &str) -> TempPem {
        let path =
            std::env::temp_dir().join(format!("pgmcp-tls-test-{}-{name}.pem", std::process::id()));
        std::fs::write(&path, pem).expect("write temp pem");
        TempPem(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S, tagged: bool) -> Option<(u8, Vec<u8>)> {
    let tag = if tagged {
        let mut t = [0u8; 1];
        stream.read_exact(&mut t).await.ok()?;
        t[0]
    } else {
        0
    };
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
    stream.read_exact(&mut body).await.ok()?;
    Some((tag, body))
}

/// Startup packet, optional cleartext challenge, then trust-style success.
async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cleartext: bool,
    served: &mut Served,
) {
    if read_frame(stream, false).await.is_none() {
        return;
    }
    if cleartext {
        let mut challenge = vec![b'R'];
        challenge.extend_from_slice(&8u32.to_be_bytes());
        challenge.extend_from_slice(&3u32.to_be_bytes());
        if stream.write_all(&challenge).await.is_err() {
            return;
        }
        match read_frame(stream, true).await {
            Some((b'p', body)) => served.password = Some(body),
            _ => return,
        }
    }
    let mut reply = vec![b'R', 0, 0, 0, 8, 0, 0, 0, 0];
    reply.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
    let _ = stream.write_all(&reply).await;
}

/// Serves one connection and reports what the client sent.
async fn spawn_server(
    answer: Answer,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    cleartext: bool,
) -> (u16, JoinHandle<Served>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let tls = acceptor(chain, key);
    let task = tokio::spawn(async move {
        let mut served = Served::default();
        let Ok((mut tcp, _)) = listener.accept().await else {
            return served;
        };
        let mut ssl_request = [0u8; 8];
        if tcp.read_exact(&mut ssl_request).await.is_err() {
            return served;
        }
        match answer {
            Answer::Plain => {
                if tcp.write_all(b"N").await.is_ok() {
                    session(&mut tcp, cleartext, &mut served).await;
                }
            }
            Answer::BrokenTls => {
                let _ = tcp.write_all(b"S not a tls handshake at all").await;
            }
            Answer::Tls => {
                if tcp.write_all(b"S").await.is_err() {
                    return served;
                }
                if let Ok(mut stream) = tls.accept(tcp).await {
                    served.handshake_done = true;
                    session(&mut stream, cleartext, &mut served).await;
                }
            }
        }
        served
    });
    (port, task)
}

/// The error of a failed connect or query; panics with `what` when the call succeeded.
trait ExpectErr {
    fn expect_err_with(self, what: &str) -> WireError;
}

impl<T> ExpectErr for Result<T, WireError> {
    fn expect_err_with(self, what: &str) -> WireError {
        match self {
            Ok(_) => panic!("{what}"),
            Err(e) => e,
        }
    }
}

/// Compares errors by their Debug text, since WireError has no PartialEq.
#[track_caller]
fn assert_same(actual: &WireError, expected: WireError) {
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

fn cfg(port: u16, host: &str, mode: SslMode, root: Option<&Path>) -> ConnectConfig {
    ConnectConfig {
        host: host.into(),
        port,
        database: "appdb".into(),
        user: "app".into(),
        password: Some(PASSWORD.into()),
        ssl_mode: mode,
        ssl_root_cert: root.map(Path::to_path_buf),
        connect_timeout: Duration::from_secs(5),
        startup_params: Vec::new(),
    }
}

/// Accepts every connection in turn and serves each with the TLS handshake and the session script.
async fn spawn_server_for_all(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let tls = acceptor(chain, key);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let tls = tls.clone();
            tokio::spawn(async move {
                let mut ssl_request = [0u8; 8];
                if tcp.read_exact(&mut ssl_request).await.is_err() {
                    return;
                }
                if tcp.write_all(b"S").await.is_err() {
                    return;
                }
                if let Ok(mut stream) = tls.accept(tcp).await {
                    let mut served = Served::default();
                    session(&mut stream, false, &mut served).await;
                }
            });
        }
    });
    port
}

/// Two connections of one pool after the root file is gone: both use the configuration read at startup.
#[tokio::test]
async fn pool_connections_do_not_reread_the_root_certificate() {
    let certs = make_certs();
    let ca = TempPem::write("pool-shared", &certs.ca_pem);
    let port = spawn_server_for_all(certs.leaf_chain.clone(), certs.leaf_key.clone_key()).await;
    let entry = serde_json::json!({
        "name": "appdb",
        "host": "127.0.0.1",
        "port": port,
        "database": "appdb",
        "user": "app",
        "password": PASSWORD,
        "sslmode": "verify-ca",
        "sslrootcert": ca.path().to_string_lossy(),
        "max_connections": 2,
    });
    let databases = serde_json::json!([entry]).to_string();
    let mut config =
        Config::from_lookup(&|name| (name == "PG_DATABASES").then(|| databases.clone()))
            .expect("configuration is valid");
    config
        .prepare_tls()
        .expect("the root file is read at startup");
    let db = config.database(None).expect("one database").clone();
    let pool = Pool::with_auth(db.connect.clone(), db.max_connections, db.auth.clone())
        .with_tls(db.tls.clone());
    let first = pool
        .checkout(Duration::from_secs(5))
        .await
        .expect("first connection");
    drop(ca);
    let second = pool
        .checkout(Duration::from_secs(5))
        .await
        .expect("second connection needs no root file");
    drop((first, second));
}

#[tokio::test]
async fn require_accepts_self_signed_leaf() {
    let certs = make_certs();
    let (port, task) = spawn_server(Answer::Tls, certs.self_chain, certs.self_key, false).await;
    let conn = Connection::connect(&cfg(port, "localhost", SslMode::Require, None)).await;
    assert!(conn.is_ok(), "{:?}", conn.err());
    let served = task.await.expect("server");
    assert!(served.handshake_done);
}

#[tokio::test]
async fn verify_ca_accepts_ca_signed_leaf_by_ip_name_is_not_checked() {
    let certs = make_certs();
    let ca = TempPem::write("ok", &certs.ca_pem);
    let (port, _task) = spawn_server(Answer::Tls, certs.leaf_chain, certs.leaf_key, false).await;
    let conn =
        Connection::connect(&cfg(port, "127.0.0.1", SslMode::VerifyCa, Some(ca.path()))).await;
    assert!(conn.is_ok(), "{:?}", conn.err());
}

#[tokio::test]
async fn verify_ca_rejects_unrelated_self_signed_leaf() {
    let certs = make_certs();
    let ca = TempPem::write("unrelated", &certs.ca_pem);
    let (port, _task) = spawn_server(Answer::Tls, certs.self_chain, certs.self_key, false).await;
    let err = Connection::connect(&cfg(port, "localhost", SslMode::VerifyCa, Some(ca.path())))
        .await
        .expect_err_with("unrelated certificate must be rejected");
    assert!(matches!(err, WireError::Tls(_)), "{err:?}");
    assert_eq!(
        err.to_string(),
        "TLS error: invalid peer certificate: UnknownIssuer"
    );
}

#[tokio::test]
async fn verify_full_accepts_dns_name_and_rejects_ip_when_only_dns_name_is_certified() {
    let certs = make_certs();
    let ca = TempPem::write("full", &certs.ca_pem);
    let (port, _task) = spawn_server(
        Answer::Tls,
        certs.leaf_chain.clone(),
        certs.leaf_key.clone_key(),
        false,
    )
    .await;
    let conn = Connection::connect(&cfg(
        port,
        "localhost",
        SslMode::VerifyFull,
        Some(ca.path()),
    ))
    .await;
    assert!(conn.is_ok(), "{:?}", conn.err());

    let (port, _task) = spawn_server(Answer::Tls, certs.leaf_chain, certs.leaf_key, false).await;
    let err = Connection::connect(&cfg(
        port,
        "127.0.0.1",
        SslMode::VerifyFull,
        Some(ca.path()),
    ))
    .await
    .expect_err_with("IP host must not match a DNS-only certificate");
    assert!(matches!(err, WireError::Tls(_)), "{err:?}");
}

#[tokio::test]
async fn verify_ca_without_root_cert_is_refused_before_connecting() {
    let certs = make_certs();
    let (port, task) = spawn_server(Answer::Tls, certs.leaf_chain, certs.leaf_key, false).await;
    let err = Connection::connect(&cfg(port, "localhost", SslMode::VerifyCa, None))
        .await
        .expect_err_with("verify-ca without a root must fail");
    assert_same(
        &err,
        WireError::Tls("sslmode=verify-ca needs sslrootcert".into()),
    );
    task.abort();
}

#[tokio::test]
async fn cleartext_over_tls_is_sent_only_when_policy_allows_password() {
    let certs = make_certs();
    let (port, task) = spawn_server(
        Answer::Tls,
        certs.self_chain.clone(),
        certs.self_key.clone_key(),
        true,
    )
    .await;
    let policy = AuthPolicy {
        scram: true,
        md5: false,
        password: true,
        trust: true,
    };
    let conn =
        Connection::connect_with(&cfg(port, "localhost", SslMode::Require, None), &policy).await;
    assert!(conn.is_ok(), "{:?}", conn.err());
    let served = task.await.expect("server");
    let mut want = PASSWORD.as_bytes().to_vec();
    want.push(0);
    assert_eq!(served.password, Some(want));

    let (port, task) = spawn_server(Answer::Tls, certs.self_chain, certs.self_key, true).await;
    let err = Connection::connect(&cfg(port, "localhost", SslMode::Require, None))
        .await
        .expect_err_with("default policy refuses cleartext");
    assert_eq!(
        err.to_string(),
        "authentication failed: the server asked for cleartext password authentication, which is not allowed here (require_auth)"
    );
    let served = task.await.expect("server");
    assert_eq!(served.password, None);
}

#[tokio::test]
async fn server_answers_s_then_breaks_handshake_is_tls_error() {
    let certs = make_certs();
    let (port, _task) =
        spawn_server(Answer::BrokenTls, certs.self_chain, certs.self_key, false).await;
    let err = Connection::connect(&cfg(port, "localhost", SslMode::Require, None))
        .await
        .expect_err_with("broken handshake must fail");
    assert!(matches!(err, WireError::Tls(_)), "{err:?}");
}

#[tokio::test]
async fn prefer_falls_back_to_plain_when_server_answers_n() {
    let certs = make_certs();
    let (port, task) = spawn_server(Answer::Plain, certs.self_chain, certs.self_key, false).await;
    let conn = Connection::connect(&cfg(port, "localhost", SslMode::Prefer, None)).await;
    assert!(conn.is_ok(), "{:?}", conn.err());
    let served = task.await.expect("server");
    assert!(!served.handshake_done);
}

#[tokio::test]
async fn prefer_uses_tls_when_server_answers_s() {
    let certs = make_certs();
    let (port, task) = spawn_server(Answer::Tls, certs.self_chain, certs.self_key, false).await;
    let conn = Connection::connect(&cfg(port, "localhost", SslMode::Prefer, None)).await;
    assert!(conn.is_ok(), "{:?}", conn.err());
    let served = task.await.expect("server");
    assert!(served.handshake_done);
}
