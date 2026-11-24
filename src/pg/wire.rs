//! PostgreSQL client over the frontend/backend protocol: connect, auth, simple and extended queries.
// WireError::Db holds DbError by value (fixed by the interface), so Result<_, WireError> is large.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use fallible_iterator::FallibleIterator;
use postgres_protocol::IsNull;
use postgres_protocol::authentication::md5_hash;
use postgres_protocol::authentication::sasl::{self, ChannelBinding, ScramSha256};
use postgres_protocol::message::backend::{
    DataRowBody, ErrorResponseBody, Header, Message, RowDescriptionBody,
};
use postgres_protocol::message::frontend::{self, BindError};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::trace;

use crate::pg::tls::{self, SslMode};

const MAX_DATA_ROW_LEN: u64 = (1 << 30) + 16;
const MAX_OTHER_LEN: u64 = 64 << 20;
const DISCARD_TIMEOUT: Duration = Duration::from_secs(5);
const DISCARD_MAX_BYTES: usize = 64 << 20;
const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);
/// Read size used when a DataRow is discarded without being buffered.
const SKIP_CHUNK: usize = 64 << 10;
const ROW_CAP_FLOOR: usize = 64 << 10;
const ROW_CAP_HEADROOM: usize = 1 << 20;
const ROW_CAP_CEILING: usize = 256 << 20;

/// Largest DataRow buffered for one query: 4 x max_bytes plus 1 MiB, within 64 KiB to 256 MiB.
fn row_cap(limits: &FetchLimits) -> usize {
    limits
        .max_bytes
        .saturating_mul(4)
        .saturating_add(ROW_CAP_HEADROOM)
        .clamp(ROW_CAP_FLOOR, ROW_CAP_CEILING)
}

/// What `recv_frame` may skip instead of failing.
#[derive(Clone, Copy)]
enum Skip {
    Nothing,
    /// Query rows: DataRows over `row_cap` are discarded unbuffered, NotificationResponse is ignored.
    Rows {
        row_cap: usize,
    },
}

/// One received frame: a whole message, or a DataRow discarded unbuffered.
enum Frame {
    Message(Incoming),
    SkippedRow { len: usize },
}

#[derive(Clone)]
pub struct ConnectConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: Option<String>,
    pub ssl_mode: SslMode,
    pub ssl_root_cert: Option<std::path::PathBuf>,
    pub connect_timeout: Duration,
    /// Sent in the startup packet after user/database (e.g. ("application_name","x"), ("DateStyle","ISO")).
    pub startup_params: Vec<(String, String)>,
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let password = if self.password.is_some() {
            "<redacted>"
        } else {
            "None"
        };
        f.debug_struct("ConnectConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &password)
            .field("ssl_mode", &self.ssl_mode)
            .field("ssl_root_cert", &self.ssl_root_cert)
            .field("connect_timeout", &self.connect_timeout)
            .field("startup_params", &self.startup_params)
            .finish()
    }
}

/// Which authentication methods the server may use. Refused methods are never answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPolicy {
    pub scram: bool,
    pub md5: bool,
    pub password: bool,
    pub trust: bool,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        AuthPolicy {
            scram: true,
            md5: false,
            password: false,
            trust: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("connection failed: {0}")]
    Io(#[from] io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("{}", .0.message)]
    Db(DbError),
    #[error("timed out")]
    Timeout,
    #[error("statement was refused: {0}")]
    Refused(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Idle,
    InTransaction,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub type_oid: u32,
    pub type_modifier: i32,
}

/// One result value in text format. `data` holds at most `max_value_bytes` leading bytes; `full_len` is the real length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub data: Bytes,
    pub full_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truncation {
    Rows,
    Bytes,
}

#[derive(Debug, Clone, Copy)]
pub struct FetchLimits {
    pub max_rows: usize,
    pub max_bytes: usize,
    pub max_value_bytes: usize,
}

#[derive(Debug)]
pub struct QueryResult {
    pub columns: Vec<Column>,
    /// None = SQL NULL; never more than max_rows rows.
    pub rows: Vec<Vec<Option<Field>>>,
    pub truncated: Option<Truncation>,
    /// None when the fetch was cut short.
    pub command_tag: Option<String>,
    pub status: TxStatus,
}

#[derive(Debug)]
pub struct SimpleResult {
    /// Rows of the LAST result set that had a RowDescription.
    pub rows: Vec<Vec<Option<String>>>,
    pub tags: Vec<String>,
    pub status: TxStatus,
}

/// Sends a CancelRequest for one connection. Uses TLS when that connection does.
#[derive(Clone)]
pub struct CancelHandle {
    host: String,
    port: u16,
    tls: Option<Arc<ClientConfig>>,
    process_id: i32,
    secret_key: i32,
}

impl CancelHandle {
    pub async fn cancel(&self) -> Result<(), WireError> {
        tokio::time::timeout(CANCEL_TIMEOUT, self.send_cancel())
            .await
            .map_err(|_| WireError::Timeout)?
    }

    async fn send_cancel(&self) -> Result<(), WireError> {
        let mut tcp = TcpStream::connect((self.host.as_str(), self.port)).await?;
        let mut stream: Box<dyn Transport> = match &self.tls {
            None => Box::new(tcp),
            Some(config) => {
                let (answer, rest) = ssl_request(&mut tcp).await?;
                if answer != b'S' || !rest.is_empty() {
                    return Err(WireError::Tls(
                        "TLS was not accepted for the cancel request".into(),
                    ));
                }
                start_tls(tcp, &self.host, config.clone()).await?
            }
        };
        let mut out = BytesMut::new();
        frontend::cancel_request(self.process_id, self.secret_key, &mut out);
        stream.write_all(&out).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        Ok(())
    }
}

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

pub struct Connection {
    stream: Box<dyn Transport>,
    buf: BytesMut,
    parameters: HashMap<String, String>,
    cancel: CancelHandle,
    poisoned: bool,
    peak_message_bytes: usize,
}

/// One backend message with its tag and total length (header included).
struct Incoming {
    tag: u8,
    len: usize,
    message: Message,
}

impl Connection {
    pub async fn connect(cfg: &ConnectConfig) -> Result<Connection, WireError> {
        Connection::connect_with(cfg, &AuthPolicy::default()).await
    }

    /// Connects and authenticates; only the methods in `policy` are answered.
    pub async fn connect_with(
        cfg: &ConnectConfig,
        policy: &AuthPolicy,
    ) -> Result<Connection, WireError> {
        tokio::time::timeout(cfg.connect_timeout, connect_inner(cfg, policy))
            .await
            .map_err(|_| WireError::Timeout)?
    }

    /// Largest message this connection has buffered so far, header included.
    pub fn peak_message_bytes(&self) -> usize {
        self.peak_message_bytes
    }

    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(String::as_str)
    }

    pub fn server_version_num(&self) -> u32 {
        self.parameter("server_version")
            .map_or(0, parse_server_version_num)
    }

    pub fn cancel_handle(&self) -> CancelHandle {
        self.cancel.clone()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub async fn simple_query(&mut self, sql: &str) -> Result<SimpleResult, WireError> {
        self.ensure_usable()?;
        let result = self.simple_inner(sql).await;
        self.note(&result);
        result
    }

    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Option<&str>],
        user_sql: bool,
        limits: &FetchLimits,
    ) -> Result<QueryResult, WireError> {
        self.ensure_usable()?;
        let result = self.query_inner(sql, params, user_sql, limits).await;
        self.note(&result);
        result
    }

    /// Sends Terminate and closes the socket. Errors are logged at debug level only.
    pub async fn close(mut self) {
        let mut out = BytesMut::new();
        frontend::terminate(&mut out);
        let result = async {
            self.stream.write_all(&out).await?;
            self.stream.flush().await?;
            self.stream.shutdown().await
        }
        .await;
        if let Err(e) = result {
            tracing::debug!(error = %e, "connection close was not clean");
        }
    }

    fn ensure_usable(&self) -> Result<(), WireError> {
        if self.poisoned {
            return Err(WireError::Protocol("connection is poisoned".into()));
        }
        Ok(())
    }

    /// Marks the connection poisoned after any error that leaves the protocol state unknown.
    fn note<T>(&mut self, result: &Result<T, WireError>) {
        if let Err(e) = result
            && poisons(e)
        {
            self.poisoned = true;
        }
    }

    async fn send(&mut self, out: &mut BytesMut) -> Result<(), WireError> {
        self.stream.write_all(out).await?;
        self.stream.flush().await?;
        out.clear();
        Ok(())
    }

    /// Reads one backend message. ParameterStatus and NoticeResponse are consumed here.
    async fn recv(&mut self) -> Result<Incoming, WireError> {
        match self.recv_frame(Skip::Nothing).await? {
            Frame::Message(incoming) => Ok(incoming),
            Frame::SkippedRow { .. } => Err(protocol("DataRow is too large")),
        }
    }

    /// Reads one backend frame, discarding what `skip` allows without buffering it.
    async fn recv_frame(&mut self, skip: Skip) -> Result<Frame, WireError> {
        loop {
            if let Some(header) = Header::parse(&self.buf).map_err(protocol)? {
                let (tag, len) = (header.tag(), header.len());
                let rows = matches!(skip, Skip::Rows { .. });
                if matches!(tag, b'G' | b'H' | b'W' | b'd' | b'c') || (tag == b'A' && !rows) {
                    return Err(unexpected(tag));
                }
                let limit = if tag == b'D' {
                    MAX_DATA_ROW_LEN
                } else {
                    MAX_OTHER_LEN
                };
                let len = u64::try_from(len).map_err(protocol)?;
                if len > limit {
                    return Err(protocol(format!(
                        "message '{}' of {len} bytes is too large",
                        char::from(tag)
                    )));
                }
                let total = usize::try_from(len).map_err(protocol)? + 1;
                if let Skip::Rows { row_cap } = skip
                    && tag == b'D'
                    && total > row_cap
                {
                    self.discard_message(total).await?;
                    return Ok(Frame::SkippedRow { len: total });
                }
                if self.buf.len() >= total {
                    self.peak_message_bytes = self.peak_message_bytes.max(total);
                    let message = Message::parse(&mut self.buf)
                        .map_err(protocol)?
                        .ok_or_else(|| protocol("incomplete message"))?;
                    match message {
                        Message::NoticeResponse(_) => {
                            trace!("ignoring NoticeResponse");
                            continue;
                        }
                        Message::NotificationResponse(_) if rows => continue,
                        Message::ParameterStatus(body) => {
                            let name = body.name().map_err(protocol)?.to_owned();
                            let value = body.value().map_err(protocol)?.to_owned();
                            check_session_parameter(&name, &value)?;
                            self.parameters.insert(name, value);
                            continue;
                        }
                        message => {
                            return Ok(Frame::Message(Incoming {
                                tag,
                                len: total,
                                message,
                            }));
                        }
                    }
                }
            }
            let read = self.stream.read_buf(&mut self.buf).await?;
            if read == 0 {
                return Err(eof());
            }
        }
    }

    /// Drops the next `total` bytes of the stream in SKIP_CHUNK steps, using buffered bytes first.
    async fn discard_message(&mut self, total: usize) -> Result<(), WireError> {
        let mut remaining = total;
        let buffered = remaining.min(self.buf.len());
        self.buf.advance(buffered);
        remaining -= buffered;
        let mut chunk = vec![0u8; SKIP_CHUNK];
        while remaining > 0 {
            let want = remaining.min(SKIP_CHUNK);
            let read = self.stream.read(&mut chunk[..want]).await?;
            if read == 0 {
                return Err(eof());
            }
            remaining -= read;
        }
        Ok(())
    }

    async fn simple_inner(&mut self, sql: &str) -> Result<SimpleResult, WireError> {
        if sql.contains('\0') {
            return Err(nul_refusal());
        }
        let mut out = BytesMut::new();
        frontend::query(sql, &mut out).map_err(protocol)?;
        self.send(&mut out).await?;

        let mut rows = Vec::new();
        let mut tags = Vec::new();
        let mut error = None;
        let status = loop {
            let incoming = self.recv().await?;
            match incoming.message {
                Message::RowDescription(_) => rows = Vec::new(),
                Message::DataRow(body) => rows.push(text_row(&body)?),
                Message::CommandComplete(body) => {
                    tags.push(body.tag().map_err(protocol)?.to_owned());
                }
                Message::EmptyQueryResponse => {}
                Message::ErrorResponse(body) => {
                    if error.is_none() {
                        error = Some(db_error(&body)?);
                    }
                }
                Message::ReadyForQuery(body) => break tx_status(body.status())?,
                _ => return Err(unexpected(incoming.tag)),
            }
        };
        match error {
            Some(e) => Err(WireError::Db(e)),
            None => Ok(SimpleResult { rows, tags, status }),
        }
    }

    async fn query_inner(
        &mut self,
        sql: &str,
        params: &[Option<&str>],
        user_sql: bool,
        limits: &FetchLimits,
    ) -> Result<QueryResult, WireError> {
        if sql.contains('\0') {
            return Err(nul_refusal());
        }
        let (columns, param_count) = self.describe(sql).await?;
        let columns =
            columns.ok_or_else(|| WireError::Refused("statement does not return rows".into()))?;
        if user_sql && param_count != 0 {
            return Err(WireError::Refused(
                "parameter placeholders are not supported".into(),
            ));
        }
        if param_count != params.len() {
            return Err(WireError::Refused(format!(
                "statement takes {param_count} parameters, {} given",
                params.len()
            )));
        }
        self.execute(params, limits, columns).await
    }

    /// Parse + Describe on the unnamed statement. Returns the columns (None for NoData) and the parameter count.
    async fn describe(&mut self, sql: &str) -> Result<(Option<Vec<Column>>, usize), WireError> {
        let mut out = BytesMut::new();
        frontend::parse("", sql, std::iter::empty(), &mut out).map_err(protocol)?;
        frontend::describe(b'S', "", &mut out).map_err(protocol)?;
        frontend::sync(&mut out);
        self.send(&mut out).await?;

        let mut parsed = false;
        let mut param_count = None;
        let mut columns = None;
        let mut error = None;
        loop {
            let incoming = self.recv().await?;
            match incoming.message {
                Message::ParseComplete => parsed = true,
                Message::ParameterDescription(body) => {
                    param_count = Some(body.parameters().count().map_err(protocol)?);
                }
                Message::RowDescription(body) => columns = Some(Some(column_list(&body)?)),
                Message::NoData => columns = Some(None),
                Message::ErrorResponse(body) => {
                    if error.is_none() {
                        error = Some(db_error(&body)?);
                    }
                }
                Message::ReadyForQuery(_) => break,
                _ => return Err(unexpected(incoming.tag)),
            }
        }
        if let Some(e) = error {
            return Err(WireError::Db(e));
        }
        match (parsed, param_count, columns) {
            (true, Some(count), Some(columns)) => Ok((columns, count)),
            _ => Err(protocol("incomplete describe response")),
        }
    }

    async fn execute(
        &mut self,
        params: &[Option<&str>],
        limits: &FetchLimits,
        columns: Vec<Column>,
    ) -> Result<QueryResult, WireError> {
        let mut out = BytesMut::new();
        frontend::bind(
            "",
            "",
            std::iter::once(0),
            params.iter().copied(),
            |value, buf| match value {
                Some(text) => {
                    buf.put_slice(text.as_bytes());
                    Ok(IsNull::No)
                }
                None => Ok(IsNull::Yes),
            },
            std::iter::once(0),
            &mut out,
        )
        .map_err(|e| match e {
            BindError::Conversion(e) => protocol(e),
            BindError::Serialization(e) => protocol(e),
        })?;
        frontend::execute("", 0, &mut out).map_err(protocol)?;
        frontend::sync(&mut out);
        self.send(&mut out).await?;
        self.stream_rows(columns, limits).await
    }

    async fn stream_rows(
        &mut self,
        columns: Vec<Column>,
        limits: &FetchLimits,
    ) -> Result<QueryResult, WireError> {
        let mut rows = Vec::new();
        let mut kept = 0usize;
        let mut truncated = None;
        let mut bound = false;
        let mut command_tag = None;
        let mut error = None;
        let mut status = None;
        let skip = Skip::Rows {
            row_cap: row_cap(limits),
        };
        loop {
            let incoming = match self.recv_frame(skip).await? {
                Frame::Message(incoming) => incoming,
                Frame::SkippedRow { .. } if bound => {
                    truncated = Some(Truncation::Bytes);
                    break;
                }
                Frame::SkippedRow { .. } => return Err(unexpected(b'D')),
            };
            match incoming.message {
                Message::BindComplete if !bound => bound = true,
                Message::DataRow(body) if bound => {
                    if let Some(t) = keep_row(&body, &mut rows, &mut kept, limits)? {
                        truncated = Some(t);
                        break;
                    }
                }
                Message::CommandComplete(body) => {
                    command_tag = Some(body.tag().map_err(protocol)?.to_owned());
                }
                Message::ErrorResponse(body) => {
                    if error.is_none() {
                        error = Some(db_error(&body)?);
                    }
                }
                Message::ReadyForQuery(body) => {
                    status = Some(tx_status(body.status())?);
                    break;
                }
                _ => return Err(unexpected(incoming.tag)),
            }
        }

        if let Some(t) = truncated {
            self.cancel.cancel().await?;
            let (tx_status, other) = self.discard_until_ready(skip).await?;
            if let Some(e) = other {
                return Err(WireError::Db(e));
            }
            return Ok(QueryResult {
                columns,
                rows,
                truncated: Some(t),
                command_tag: None,
                status: tx_status,
            });
        }
        if let Some(e) = error {
            return Err(WireError::Db(e));
        }
        let command_tag =
            command_tag.ok_or_else(|| protocol("no CommandComplete before ReadyForQuery"))?;
        let status = status.ok_or_else(|| protocol("no ReadyForQuery"))?;
        Ok(QueryResult {
            columns,
            rows,
            truncated: None,
            command_tag: Some(command_tag),
            status,
        })
    }

    /// Reads and drops messages until ReadyForQuery, bounded by DISCARD_TIMEOUT and DISCARD_MAX_BYTES.
    async fn discard_until_ready(
        &mut self,
        skip: Skip,
    ) -> Result<(TxStatus, Option<DbError>), WireError> {
        tokio::time::timeout(DISCARD_TIMEOUT, self.discard_loop(skip))
            .await
            .map_err(|_| WireError::Timeout)?
    }

    async fn discard_loop(&mut self, skip: Skip) -> Result<(TxStatus, Option<DbError>), WireError> {
        let mut discarded = 0usize;
        let mut other_error = None;
        loop {
            let frame = self.recv_frame(skip).await?;
            let len = match &frame {
                Frame::Message(incoming) => incoming.len,
                Frame::SkippedRow { len } => *len,
            };
            discarded = discarded.saturating_add(len);
            if discarded > DISCARD_MAX_BYTES {
                return Err(protocol("too much data while cancelling the query"));
            }
            let Frame::Message(incoming) = frame else {
                continue;
            };
            match incoming.message {
                Message::ErrorResponse(body) => {
                    let e = db_error(&body)?;
                    if e.code != "57014" && other_error.is_none() {
                        other_error = Some(e);
                    }
                }
                Message::ReadyForQuery(body) => {
                    return Ok((tx_status(body.status())?, other_error));
                }
                _ => {}
            }
        }
    }

    /// Reads the startup, auth and parameter messages until the first ReadyForQuery.
    async fn authenticate(
        &mut self,
        cfg: &ConnectConfig,
        policy: &AuthPolicy,
    ) -> Result<(), WireError> {
        let mut out = BytesMut::new();
        let mut scram: Option<ScramSha256> = None;
        let mut scram_proved = false;
        // A password exchange (cleartext, MD5 or SASL) has started.
        let mut challenged = false;
        let mut authenticated = false;
        loop {
            let incoming = self.recv().await?;
            if authenticated && incoming.tag == b'R' {
                return Err(protocol("authentication request after AuthenticationOk"));
            }
            match incoming.message {
                Message::AuthenticationOk => {
                    if scram.is_some() && !scram_proved {
                        return Err(WireError::Auth(
                            "the server ended SCRAM authentication without proving its identity"
                                .into(),
                        ));
                    }
                    if !challenged && !policy.trust {
                        return Err(refused("trust"));
                    }
                    authenticated = true;
                }
                Message::AuthenticationCleartextPassword => {
                    if self.cancel.tls.is_none() {
                        return Err(WireError::Auth(
                            "server asked for a cleartext password on an unencrypted connection"
                                .into(),
                        ));
                    }
                    if !policy.password {
                        return Err(refused("cleartext password"));
                    }
                    let password = configured_password(cfg)?;
                    frontend::password_message(password.as_bytes(), &mut out).map_err(protocol)?;
                    challenged = true;
                }
                Message::AuthenticationMd5Password(body) => {
                    if !policy.md5 {
                        return Err(refused("MD5"));
                    }
                    let password = configured_password(cfg)?;
                    let hashed = md5_hash(cfg.user.as_bytes(), password.as_bytes(), body.salt());
                    frontend::password_message(hashed.as_bytes(), &mut out).map_err(protocol)?;
                    challenged = true;
                }
                Message::AuthenticationSasl(body) => {
                    if !policy.scram {
                        return Err(refused("SCRAM-SHA-256"));
                    }
                    if scram.is_some() {
                        return Err(protocol("SASL start received twice"));
                    }
                    let mut mechanisms = body.mechanisms();
                    let mut offered = false;
                    while let Some(name) = mechanisms.next().map_err(protocol)? {
                        offered |= name == sasl::SCRAM_SHA_256;
                    }
                    if !offered {
                        return Err(WireError::Auth(
                            "server offered no supported SASL mechanism (SCRAM-SHA-256 required)"
                                .into(),
                        ));
                    }
                    let password = configured_password(cfg)?;
                    let client =
                        ScramSha256::new(password.as_bytes(), ChannelBinding::unsupported());
                    frontend::sasl_initial_response(
                        sasl::SCRAM_SHA_256,
                        client.message(),
                        &mut out,
                    )
                    .map_err(protocol)?;
                    scram = Some(client);
                    challenged = true;
                }
                Message::AuthenticationSaslContinue(body) => {
                    let client = scram
                        .as_mut()
                        .ok_or_else(|| protocol("SASL continue without SASL start"))?;
                    client
                        .update(body.data())
                        .map_err(|e| WireError::Auth(e.to_string()))?;
                    frontend::sasl_response(client.message(), &mut out).map_err(protocol)?;
                }
                Message::AuthenticationSaslFinal(body) => {
                    let client = scram
                        .as_mut()
                        .ok_or_else(|| protocol("SASL final without SASL start"))?;
                    client
                        .finish(body.data())
                        .map_err(|e| WireError::Auth(e.to_string()))?;
                    scram_proved = true;
                }
                Message::AuthenticationGss | Message::AuthenticationGssContinue(_) => {
                    return Err(WireError::Auth(
                        "server requested GSSAPI authentication, which is not supported".into(),
                    ));
                }
                Message::AuthenticationKerberosV5 => {
                    return Err(WireError::Auth(
                        "server requested Kerberos V5 authentication, which is not supported"
                            .into(),
                    ));
                }
                Message::AuthenticationSspi => {
                    return Err(WireError::Auth(
                        "server requested SSPI authentication, which is not supported".into(),
                    ));
                }
                Message::AuthenticationScmCredential => {
                    return Err(WireError::Auth(
                        "server requested SCM credential authentication, which is not supported"
                            .into(),
                    ));
                }
                Message::BackendKeyData(body) => {
                    self.cancel.process_id = body.process_id();
                    self.cancel.secret_key = body.secret_key();
                }
                Message::ReadyForQuery(_) => {
                    if !authenticated {
                        return Err(protocol("ReadyForQuery before AuthenticationOk"));
                    }
                    return Ok(());
                }
                Message::ErrorResponse(body) => return Err(WireError::Db(db_error(&body)?)),
                _ => return Err(unexpected(incoming.tag)),
            }
            if !out.is_empty() {
                self.send(&mut out).await?;
            }
        }
    }
}

async fn connect_inner(cfg: &ConnectConfig, policy: &AuthPolicy) -> Result<Connection, WireError> {
    if cfg.ssl_mode == SslMode::VerifyCa && cfg.ssl_root_cert.is_none() {
        return Err(WireError::Tls("sslmode=verify-ca needs sslrootcert".into()));
    }
    let mut tcp = TcpStream::connect((cfg.host.as_str(), cfg.port)).await?;
    tcp.set_nodelay(true)?;
    let mut buf = BytesMut::new();
    let mut tls = None;
    let stream: Box<dyn Transport> = if cfg.ssl_mode == SslMode::Disable {
        Box::new(tcp)
    } else {
        let (answer, rest) = ssl_request(&mut tcp).await?;
        match answer {
            b'S' => {
                if !rest.is_empty() {
                    return Err(WireError::Tls(
                        "unexpected data after the SSL response".into(),
                    ));
                }
                let config = tls::client_config(cfg.ssl_mode, cfg.ssl_root_cert.as_deref())?;
                tls = Some(config.clone());
                start_tls(tcp, &cfg.host, config).await?
            }
            b'N' if cfg.ssl_mode == SslMode::Prefer => {
                buf = rest;
                Box::new(tcp)
            }
            b'N' => return Err(WireError::Tls("server does not support TLS".into())),
            other => {
                return Err(protocol(format!(
                    "unexpected answer to SSLRequest '{}'",
                    char::from(other)
                )));
            }
        }
    };

    let mut conn = Connection {
        stream,
        buf,
        parameters: HashMap::new(),
        cancel: CancelHandle {
            host: cfg.host.clone(),
            port: cfg.port,
            tls,
            process_id: 0,
            secret_key: 0,
        },
        poisoned: false,
        peak_message_bytes: 0,
    };
    let mut params = vec![
        ("user", cfg.user.as_str()),
        ("database", cfg.database.as_str()),
        ("client_encoding", "UTF8"),
    ];
    params.extend(
        cfg.startup_params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
    );
    let mut out = BytesMut::new();
    frontend::startup_message(params, &mut out).map_err(protocol)?;
    conn.send(&mut out).await?;
    conn.authenticate(cfg, policy).await?;
    Ok(conn)
}

/// Writes an SSLRequest and returns the one-byte answer plus any bytes that arrived with it.
async fn ssl_request(tcp: &mut TcpStream) -> Result<(u8, BytesMut), WireError> {
    let mut out = BytesMut::new();
    frontend::ssl_request(&mut out);
    tcp.write_all(&out).await?;
    tcp.flush().await?;
    let mut buf = BytesMut::new();
    while buf.is_empty() {
        if tcp.read_buf(&mut buf).await? == 0 {
            return Err(WireError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed the connection",
            )));
        }
    }
    let answer = buf[0];
    buf.advance(1);
    Ok((answer, buf))
}

async fn start_tls(
    tcp: TcpStream,
    host: &str,
    config: Arc<ClientConfig>,
) -> Result<Box<dyn Transport>, WireError> {
    let name = ServerName::try_from(host.to_owned()).map_err(|e| WireError::Tls(e.to_string()))?;
    let stream = TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|e| WireError::Tls(e.to_string()))?;
    Ok(Box::new(stream))
}

fn configured_password(cfg: &ConnectConfig) -> Result<&str, WireError> {
    cfg.password
        .as_deref()
        .ok_or_else(|| WireError::Auth("server requires a password, but none is configured".into()))
}

fn protocol(e: impl fmt::Display) -> WireError {
    WireError::Protocol(e.to_string())
}

fn unexpected(tag: u8) -> WireError {
    WireError::Protocol(format!("unexpected message '{}'", char::from(tag)))
}

fn nul_refusal() -> WireError {
    WireError::Refused("SQL contains a NUL byte".into())
}

fn utf8(bytes: &[u8]) -> Result<String, WireError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| WireError::Protocol("server sent invalid UTF-8".into()))
}

fn tx_status(byte: u8) -> Result<TxStatus, WireError> {
    match byte {
        b'I' => Ok(TxStatus::Idle),
        b'T' => Ok(TxStatus::InTransaction),
        b'E' => Ok(TxStatus::Failed),
        other => Err(protocol(format!("unknown transaction status {other}"))),
    }
}

/// Errors that leave the protocol state unknown. Server errors and refusals do not.
fn poisons(e: &WireError) -> bool {
    !matches!(e, WireError::Db(_) | WireError::Refused(_))
}

fn db_error(body: &ErrorResponseBody) -> Result<DbError, WireError> {
    let mut error = DbError {
        severity: String::new(),
        code: String::new(),
        message: String::new(),
        detail: None,
        hint: None,
        position: None,
    };
    let mut fields = body.fields();
    while let Some(field) = fields.next().map_err(protocol)? {
        let value = utf8(field.value_bytes())?;
        match field.type_() {
            b'S' => error.severity = value,
            b'C' => error.code = value,
            b'M' => error.message = value,
            b'D' => error.detail = Some(value),
            b'H' => error.hint = Some(value),
            b'P' => {
                error.position = Some(
                    value
                        .parse()
                        .map_err(|_| protocol(format!("invalid error position \"{value}\"")))?,
                );
            }
            _ => {}
        }
    }
    Ok(error)
}

fn column_list(body: &RowDescriptionBody) -> Result<Vec<Column>, WireError> {
    let mut columns = Vec::new();
    let mut fields = body.fields();
    while let Some(field) = fields.next().map_err(protocol)? {
        columns.push(Column {
            name: field.name().to_owned(),
            type_oid: field.type_oid(),
            type_modifier: field.type_modifier(),
        });
    }
    Ok(columns)
}

/// Borrowed field values of a DataRow, None for SQL NULL.
fn field_slices(body: &DataRowBody) -> Result<Vec<Option<&[u8]>>, WireError> {
    let bytes = body.buffer();
    let mut ranges = body.ranges();
    let mut values = Vec::new();
    while let Some(range) = ranges.next().map_err(protocol)? {
        values.push(match range {
            None => None,
            Some(r) => Some(
                bytes
                    .get(r)
                    .ok_or_else(|| protocol("data row field out of range"))?,
            ),
        });
    }
    Ok(values)
}

fn text_row(body: &DataRowBody) -> Result<Vec<Option<String>>, WireError> {
    let mut row = Vec::new();
    for value in field_slices(body)? {
        row.push(match value {
            Some(bytes) => Some(utf8(bytes)?),
            None => None,
        });
    }
    Ok(row)
}

/// Keeps one DataRow within the limits. Returns the truncation when this row must not be kept.
fn keep_row(
    body: &DataRowBody,
    rows: &mut Vec<Vec<Option<Field>>>,
    kept: &mut usize,
    limits: &FetchLimits,
) -> Result<Option<Truncation>, WireError> {
    if rows.len() >= limits.max_rows {
        return Ok(Some(Truncation::Rows));
    }
    let mut fields = Vec::new();
    let mut row_bytes = 0usize;
    for value in field_slices(body)? {
        fields.push(value.map(|bytes| {
            let keep = bytes.len().min(limits.max_value_bytes);
            row_bytes += keep;
            Field {
                data: Bytes::copy_from_slice(&bytes[..keep]),
                full_len: bytes.len(),
            }
        }));
    }
    if *kept + row_bytes > limits.max_bytes {
        if rows.is_empty() {
            *kept += row_bytes;
            rows.push(fields);
        }
        return Ok(Some(Truncation::Bytes));
    }
    *kept += row_bytes;
    rows.push(fields);
    Ok(None)
}

fn eof() -> WireError {
    WireError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "server closed the connection",
    ))
}

/// The error for an authentication method that `require_auth` does not allow.
fn refused(method: &str) -> WireError {
    WireError::Auth(format!(
        "the server asked for {method} authentication, which is not allowed here (require_auth)"
    ))
}

/// Rejects a session parameter whose value the read-only recipe depends on.
fn check_session_parameter(name: &str, value: &str) -> Result<(), WireError> {
    match (name, value) {
        ("standard_conforming_strings", "on") | ("client_encoding", "UTF8") => Ok(()),
        ("standard_conforming_strings", other) => Err(protocol(format!(
            "server changed standard_conforming_strings to \"{other}\""
        ))),
        ("client_encoding", other) => Err(protocol(format!(
            "server changed client_encoding to \"{other}\""
        ))),
        _ => Ok(()),
    }
}

/// Parses a server_version string such as "19.0" or "15.20 (...)" into PG_VERSION_NUM form.
pub fn parse_server_version_num(text: &str) -> u32 {
    let (major, rest) = leading_number(text);
    let (minor, rest) = after_dot(rest);
    if major >= 10 {
        return major.saturating_mul(10_000).saturating_add(minor);
    }
    let (patch, _) = after_dot(rest);
    major
        .saturating_mul(10_000)
        .saturating_add(minor.saturating_mul(100))
        .saturating_add(patch)
}

fn after_dot(s: &str) -> (u32, &str) {
    match s.strip_prefix('.') {
        Some(rest) => leading_number(rest),
        None => (0, s),
    }
}

fn leading_number(s: &str) -> (u32, &str) {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    (s[..end].parse().unwrap_or(0), &s[end..])
}
