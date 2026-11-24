//! Connection pool: a semaphore bounds the connections in use, and clean idle connections are reused.
// PoolError holds WireError, which is large (fixed by the wire interface).
#![allow(clippy::result_large_err)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{Semaphore, SemaphorePermit};

use crate::pg::wire::{ConnectConfig, Connection, WireError};
use crate::typeinfo::TypeCache;

/// Bounded pool of connections to one server. Opens nothing until the first checkout.
pub struct Pool {
    connect: ConnectConfig,
    permits: Semaphore,
    idle: Mutex<Vec<Connection>>,
    types: TypeCache,
    closed: AtomicBool,
}

impl Pool {
    /// Lazy: opens nothing until first use.
    pub fn new(connect: ConnectConfig, max_connections: usize) -> Pool {
        Pool {
            connect,
            permits: Semaphore::new(max_connections),
            idle: Mutex::new(Vec::new()),
            types: TypeCache::new(),
            closed: AtomicBool::new(false),
        }
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
        let conn = Connection::connect(&self.connect).await?;
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
    #[error(transparent)]
    Connect(#[from] WireError),
}
