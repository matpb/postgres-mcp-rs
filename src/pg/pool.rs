//! Connection pool: a semaphore bounds the connections in use, and clean idle connections are reused.
// PoolError holds WireError, which is large (fixed by the wire interface).
#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::ClientConfig;
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::pg::wire::{AuthPolicy, ConnectConfig, Connection, WireError};
use crate::typeinfo::TypeCache;

/// Bounded pool of connections to one server. Opens nothing until the first checkout.
pub struct Pool {
    /// The configured connection name, used in the failure log.
    name: String,
    connect: ConnectConfig,
    auth: AuthPolicy,
    /// Built once at startup and shared by every connection and cancel request of the pool, when set.
    tls: Option<Arc<ClientConfig>>,
    permits: Semaphore,
    idle: Mutex<Vec<Connection>>,
    types: TypeCache,
    closed: AtomicBool,
}

impl Pool {
    /// Lazy: opens nothing until first use. Authenticates with the default policy.
    pub fn new(connect: ConnectConfig, max_connections: usize) -> Pool {
        Pool::with_auth(connect, max_connections, AuthPolicy::default())
    }

    /// Like `new`, with the authentication methods every new connection may use.
    pub fn with_auth(connect: ConnectConfig, max_connections: usize, auth: AuthPolicy) -> Pool {
        Pool {
            name: String::new(),
            connect,
            auth,
            tls: None,
            permits: Semaphore::new(max_connections),
            idle: Mutex::new(Vec::new()),
            types: TypeCache::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// Sets the configured connection name that the failure log reports.
    pub fn with_name(mut self, name: &str) -> Pool {
        self.name = name.to_owned();
        self
    }

    /// Uses `tls` for every new connection instead of reading the root file again.
    pub fn with_tls(mut self, tls: Option<Arc<ClientConfig>>) -> Pool {
        self.tls = tls;
        self
    }

    /// Waits for a permit (at most `wait`), then reuses an idle connection or opens a new one.
    pub async fn checkout(&self, wait: Duration) -> Result<Lease<'_>, PoolError> {
        let permit = self.acquire(wait).await?;
        let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
        match idle {
            Some(conn) => Ok(Lease {
                pool: self,
                _permit: permit,
                conn,
                reused: true,
            }),
            None => self.open(permit).await,
        }
    }

    /// Like `checkout`, but never reuses an idle connection.
    pub(crate) async fn checkout_fresh(&self, wait: Duration) -> Result<Lease<'_>, PoolError> {
        let permit = self.acquire(wait).await?;
        self.open(permit).await
    }

    pub fn type_cache(&self) -> &TypeCache {
        &self.types
    }

    pub fn idle_count(&self) -> usize {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Closes idle connections; later checkouts fail with PoolError::Closed.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.permits.close();
        let idle = std::mem::take(&mut *self.idle.lock().unwrap_or_else(|e| e.into_inner()));
        for conn in idle {
            conn.close().await;
        }
    }

    async fn acquire(&self, wait: Duration) -> Result<SemaphorePermit<'_>, PoolError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(PoolError::Closed);
        }
        match tokio::time::timeout(wait, self.permits.acquire()).await {
            Err(_elapsed) => Err(PoolError::Busy),
            Ok(Err(_closed)) => Err(PoolError::Closed),
            Ok(Ok(permit)) => Ok(permit),
        }
    }

    async fn open<'a>(&'a self, permit: SemaphorePermit<'a>) -> Result<Lease<'a>, PoolError> {
        let conn =
            match Connection::connect_with_tls(&self.connect, &self.auth, self.tls.clone()).await {
                Ok(conn) => conn,
                Err(error) => {
                    let reason = connect_failure_text(&error);
                    tracing::warn!(
                        connection = %self.name,
                        host = %self.connect.host,
                        port = self.connect.port,
                        reason = %reason,
                        "connection failed"
                    );
                    return Err(PoolError::Connect(reason));
                }
            };
        Ok(Lease {
            pool: self,
            _permit: permit,
            conn,
            reused: false,
        })
    }

    /// Keeps the connection for reuse unless the pool was closed meanwhile.
    fn give_back(&self, conn: Connection) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if !self.closed.load(Ordering::SeqCst) {
            idle.push(conn);
        }
    }
}

/// Holds the permit and the connection. Dropping it without `release` closes the connection.
pub struct Lease<'a> {
    pool: &'a Pool,
    _permit: SemaphorePermit<'a>,
    conn: Connection,
    reused: bool,
}

impl Lease<'_> {
    pub fn conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// True when the connection came from the idle list rather than being opened for this lease.
    pub(crate) fn reused(&self) -> bool {
        self.reused
    }

    /// Returns the connection to the idle list only if `clean` is true and it is not poisoned.
    pub fn release(self, clean: bool) {
        let Lease {
            pool,
            _permit,
            conn,
            reused: _,
        } = self;
        if clean && !conn.is_poisoned() {
            pool.give_back(conn);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("all connections are busy")]
    Busy,
    #[error("the pool is closed")]
    Closed,
    /// Client-facing text for a failed connect; the server's own message is only logged.
    #[error("{0}")]
    Connect(String),
}

/// The client-facing text for a connect failure, by class. PostgreSQL's wording can name users and addresses.
fn connect_failure_text(error: &WireError) -> String {
    match error {
        WireError::Auth(_) => "authentication failed".to_owned(),
        WireError::Db(db) => match db.code.as_str() {
            code if code.starts_with("28") => "authentication failed".to_owned(),
            "3D000" => "the database does not exist".to_owned(),
            "53300" => "too many connections".to_owned(),
            code => format!("the server refused the connection (SQLSTATE {code})"),
        },
        WireError::Io(_) => "cannot connect to the server".to_owned(),
        WireError::Tls(_) => "TLS negotiation failed".to_owned(),
        WireError::Timeout => "connection timed out".to_owned(),
        WireError::Protocol(_) | WireError::Refused(_) => {
            "unexpected reply from the server".to_owned()
        }
    }
}
