//! SSL modes and the rustls client configuration used for PostgreSQL connections.
// WireError::Db holds DbError by value (fixed by the interface), so Result<_, WireError> is large.
#![allow(clippy::result_large_err)]

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_cert_signed_by_trust_anchor};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, InconsistentKeys, RootCertStore,
    SignatureScheme,
};

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

impl SslMode {
    /// The libpq name of the mode, as the configuration spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Prefer => "prefer",
            SslMode::Require => "require",
            SslMode::VerifyCa => "verify-ca",
            SslMode::VerifyFull => "verify-full",
        }
    }
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

/// Where one PEM item comes from: a file read at startup, or PEM text given inline. Inline text is never printed.
#[derive(Clone)]
pub enum PemSource {
    File(PathBuf),
    Inline(String),
}

impl fmt::Debug for PemSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PemSource::File(path) => f.debug_tuple("File").field(path).finish(),
            PemSource::Inline(_) => f.write_str("Inline(<redacted>)"),
        }
    }
}

/// The TLS items of one database: the trusted roots, and a client certificate chain with its key.
#[derive(Clone, Debug, Default)]
pub struct TlsSources {
    pub root: Option<PemSource>,
    pub client_cert: Option<PemSource>,
    pub client_key: Option<PemSource>,
}

/// A client certificate chain (leaf first) and its private key.
type Identity = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// Builds the rustls client configuration for `mode`, with roots from `root_cert` (a PEM file) when given.
pub fn client_config(
    mode: SslMode,
    root_cert: Option<&Path>,
) -> Result<Arc<ClientConfig>, WireError> {
    if mode == SslMode::VerifyCa && root_cert.is_none() {
        return Err(WireError::Tls("sslmode=verify-ca needs sslrootcert".into()));
    }
    let roots = match root_cert {
        Some(path) => read_roots_file(path).map_err(|e| e.wire(path))?,
        None => bundled_roots(),
    };
    build_config(mode, roots, None).map_err(WireError::Tls)
}

/// The configuration for a database at startup, read once and then shared. Every error names the setting
/// (`sslrootcert`, `sslcert_pem` and so on) and never the file path's contents or any key material.
pub fn startup_client_config(
    mode: SslMode,
    sources: &TlsSources,
) -> Result<Arc<ClientConfig>, String> {
    if mode == SslMode::VerifyCa && sources.root.is_none() {
        return Err("sslmode=verify-ca needs sslrootcert".to_owned());
    }
    let roots = match &sources.root {
        Some(source) => startup_roots(source)?,
        None => bundled_roots(),
    };
    let identity = client_identity(sources)?;
    build_config(mode, roots, identity)
}

fn bundled_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// The setting name in a message: `base` for a file, `base_pem` for inline text.
fn item_name(source: &PemSource, base: &str) -> String {
    match source {
        PemSource::File(_) => base.to_owned(),
        PemSource::Inline(_) => format!("{base}_pem"),
    }
}

/// The PEM bytes of one item. A file that cannot be read gives `cannot read <item>: <io reason>`.
fn pem_bytes<'a>(source: &'a PemSource, item: &str) -> Result<Cow<'a, [u8]>, String> {
    match source {
        PemSource::File(path) => std::fs::read(path)
            .map(Cow::Owned)
            .map_err(|e| format!("cannot read {item}: {e}")),
        PemSource::Inline(text) => Ok(Cow::Borrowed(text.as_bytes())),
    }
}

/// Why a root certificate cannot be used. The variants hold the cause, never the file contents.
enum RootsError {
    Open(io::Error),
    Read(String),
    Empty,
    Add(String),
}

impl RootsError {
    /// The text the wire client reports for a connection that cannot load its root file.
    fn wire(self, path: &Path) -> WireError {
        let shown = path.display();
        WireError::Tls(match self {
            RootsError::Open(e) => format!("cannot open {shown}: {e}"),
            RootsError::Read(m) => format!("cannot read {shown}: {m}"),
            RootsError::Empty => format!("no certificates found in {shown}"),
            RootsError::Add(m) => m,
        })
    }

    /// The text the startup check reports for the setting `item`; PEM syntax errors are not echoed.
    fn startup(self, item: &str) -> String {
        match self {
            RootsError::Open(e) => format!("cannot read {item}: {e}"),
            RootsError::Read(_) => format!("{item} is not valid PEM"),
            RootsError::Empty => format!("{item} holds no certificate"),
            RootsError::Add(m) => format!("cannot read {item}: {m}"),
        }
    }
}

fn read_roots_file(path: &Path) -> Result<RootCertStore, RootsError> {
    let bytes = std::fs::read(path).map_err(RootsError::Open)?;
    roots_from_pem(&bytes)
}

fn startup_roots(source: &PemSource) -> Result<RootCertStore, String> {
    let item = item_name(source, "sslrootcert");
    let bytes = pem_bytes(source, &item)?;
    roots_from_pem(&bytes).map_err(|e| e.startup(&item))
}

fn roots_from_pem(bytes: &[u8]) -> Result<RootCertStore, RootsError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(bytes) {
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

/// The client identity from the certificate and key sources: both or neither. None when neither is set.
fn client_identity(sources: &TlsSources) -> Result<Option<Identity>, String> {
    let (cert_source, key_source) = match (&sources.client_cert, &sources.client_key) {
        (None, None) => return Ok(None),
        (Some(cert), Some(key)) => (cert, key),
        _ => return Err("sslcert and sslkey must be set together".to_owned()),
    };
    let cert_item = item_name(cert_source, "sslcert");
    let chain = {
        let bytes = pem_bytes(cert_source, &cert_item)?;
        CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| format!("{cert_item} is not valid PEM"))?
    };
    if chain.is_empty() {
        return Err(format!("{cert_item} holds no certificate"));
    }
    let key_item = item_name(key_source, "sslkey");
    let key = {
        let bytes = pem_bytes(key_source, &key_item)?;
        if is_encrypted_pem(&bytes) {
            return Err(format!(
                "{key_item} is encrypted; provide an unencrypted PEM key"
            ));
        }
        match PrivateKeyDer::pem_slice_iter(&bytes).next() {
            None => return Err(format!("{key_item} holds no private key")),
            Some(Err(_)) => return Err(format!("{key_item} is not valid PEM")),
            Some(Ok(key)) => key,
        }
    };
    Ok(Some((chain, key)))
}

/// True for PKCS#8 encrypted armour and for the PEM `Proc-Type: 4,ENCRYPTED` header. Only the labels are read.
fn is_encrypted_pem(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).lines().any(|line| {
        let line = line.trim();
        line == "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            || (line.starts_with("Proc-Type:") && line.contains("ENCRYPTED"))
    })
}

fn build_config(
    mode: SslMode,
    roots: RootCertStore,
    identity: Option<Identity>,
) -> Result<Arc<ClientConfig>, String> {
    let roots = Arc::new(roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let webpki = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(|e| e.to_string())?;
    let verifier = Verifier {
        mode,
        provider: provider.clone(),
        roots,
        webpki,
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    let config = match identity {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(client_key_error)?,
    };
    Ok(Arc::new(config))
}

/// rustls refuses a key that does not belong to the certificate; any other refusal means the key is unusable.
fn client_key_error(error: TlsError) -> String {
    match error {
        TlsError::InconsistentKeys(InconsistentKeys::KeyMismatch) => {
            "sslkey does not match sslcert".to_owned()
        }
        _ => "sslkey is not a supported private key".to_owned(),
    }
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
