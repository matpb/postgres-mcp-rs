//! SSL modes and the rustls client configuration used for PostgreSQL connections.
// WireError::Db holds DbError by value (fixed by the interface), so Result<_, WireError> is large.
#![allow(clippy::result_large_err)]

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_cert_signed_by_trust_anchor};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::pg::wire::WireError;

/// libpq-style SSL modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl FromStr for SslMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disable" => Ok(SslMode::Disable),
            "prefer" => Ok(SslMode::Prefer),
            "require" => Ok(SslMode::Require),
            "verify-ca" => Ok(SslMode::VerifyCa),
            "verify-full" => Ok(SslMode::VerifyFull),
            other => Err(format!("invalid ssl mode \"{other}\"")),
        }
    }
}

/// Builds the rustls client configuration for `mode`.
///
/// Roots come from `root_cert` (PEM) when given, otherwise from webpki-roots.
pub fn client_config(
    mode: SslMode,
    root_cert: Option<&Path>,
) -> Result<Arc<ClientConfig>, WireError> {
    if mode == SslMode::VerifyCa && root_cert.is_none() {
        return Err(WireError::Tls("sslmode=verify-ca needs sslrootcert".into()));
    }
    let roots = match root_cert {
        Some(path) => read_roots(path).map_err(|e| e.wire(path))?,
        None => bundled_roots(),
    };
    build_config(mode, roots)
}

/// The configuration for a database at startup, read once and then shared. The error text names the
/// cause only, never the path or the file contents: it follows `cannot read sslrootcert: ` or is `sslrootcert holds no certificate`.
pub fn startup_client_config(
    mode: SslMode,
    root_cert: Option<&Path>,
) -> Result<Arc<ClientConfig>, String> {
    let roots = match root_cert {
        Some(path) => read_roots(path).map_err(RootsError::startup)?,
        None => bundled_roots(),
    };
    build_config(mode, roots).map_err(|e| match e {
        WireError::Tls(message) => message,
        other => other.to_string(),
    })
}

fn bundled_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Why a root certificate file cannot be used. The variants hold the cause, never the file contents.
enum RootsError {
    Open(std::io::Error),
    Read(String),
    Empty,
    Add(String),
}

impl RootsError {
    /// The text the wire client reports for a connection that cannot load its roots.
    fn wire(self, path: &Path) -> WireError {
        let shown = path.display();
        WireError::Tls(match self {
            RootsError::Open(e) => format!("cannot open {shown}: {e}"),
            RootsError::Read(m) => format!("cannot read {shown}: {m}"),
            RootsError::Empty => format!("no certificates found in {shown}"),
            RootsError::Add(m) => m,
        })
    }

    /// The text the startup check reports; the caller prefixes the database name or variable.
    fn startup(self) -> String {
        match self {
            RootsError::Open(e) => format!("cannot read sslrootcert: {e}"),
            RootsError::Read(m) | RootsError::Add(m) => format!("cannot read sslrootcert: {m}"),
            RootsError::Empty => "sslrootcert holds no certificate".to_owned(),
        }
    }
}

fn read_roots(path: &Path) -> Result<RootCertStore, RootsError> {
    let file = std::fs::File::open(path).map_err(RootsError::Open)?;
    let reader = std::io::BufReader::new(file);
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(reader) {
        let cert = cert.map_err(|e| RootsError::Read(e.to_string()))?;
        roots
            .add(cert)
            .map_err(|e| RootsError::Add(e.to_string()))?;
    }
    if roots.is_empty() {
        return Err(RootsError::Empty);
    }
    Ok(roots)
}

fn build_config(mode: SslMode, roots: RootCertStore) -> Result<Arc<ClientConfig>, WireError> {
    let roots = Arc::new(roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let webpki = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(|e| WireError::Tls(e.to_string()))?;
    let verifier = Verifier {
        mode,
        provider: provider.clone(),
        roots,
        webpki,
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| WireError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Certificate verifier: Require/Prefer accept any certificate, VerifyCa checks the chain only,
/// VerifyFull also checks the server name. Handshake signatures are always checked.
#[derive(Debug)]
struct Verifier {
    mode: SslMode,
    provider: Arc<CryptoProvider>,
    roots: Arc<RootCertStore>,
    webpki: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.mode {
            SslMode::VerifyFull => self.webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
            SslMode::VerifyCa => {
                let parsed = end_entity.try_into()?;
                verify_server_cert_signed_by_trust_anchor(
                    &parsed,
                    &self.roots,
                    intermediates,
                    now,
                    self.provider.signature_verification_algorithms.all,
                )?;
                Ok(ServerCertVerified::assertion())
            }
            SslMode::Disable | SslMode::Prefer | SslMode::Require => {
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}
