//! HTTP access guard: Origin allow-list, optional API key, and the JSON errors they return.

use std::fmt;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderName, StatusCode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const FORBIDDEN_BODY: &str = r#"{"error":"forbidden","message":"Origin not allowed"}"#;
const UNAUTHORIZED_BODY: &str = r#"{"error":"unauthorized","message":"Missing or invalid API key. Send it as X-API-Key or Authorization: Bearer."}"#;

/// SHA-256 of the configured API key; requests are compared digest to digest.
#[derive(Clone)]
pub struct ApiKey([u8; 32]);

impl ApiKey {
    pub fn new(key: &str) -> ApiKey {
        ApiKey(Sha256::digest(key.as_bytes()).into())
    }

    /// Hashes `presented` first, so the comparison does not depend on its length or content.
    pub fn matches(&self, presented: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(presented).into();
        bool::from(self.0.as_slice().ct_eq(digest.as_slice()))
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(..)")
    }
}

/// The key a request presents: `X-API-Key` (even if empty) wins, else the `Bearer` token.
pub fn presented_key(headers: &HeaderMap) -> Option<Vec<u8>> {
    if let Some(value) = headers.get(&X_API_KEY) {
        return Some(value.as_bytes().to_vec());
    }
    let value = headers.get(AUTHORIZATION)?.as_bytes();
    let space = value.iter().position(|&b| b == b' ')?;
    let (scheme, rest) = value.split_at(space);
    if scheme.eq_ignore_ascii_case(b"bearer") {
        Some(rest.trim_ascii_start().to_vec())
    } else {
        None
    }
}

/// Normalised `scheme://host[:port]`; the URL parser drops a default port.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OriginKey {
    scheme: String,
    host: String,
    port: Option<u16>,
}

/// Parses an origin of the form `scheme://host[:port]`, with no path, query, fragment or userinfo.
pub(crate) fn parse_origin(raw: &str) -> Option<OriginKey> {
    let (_, rest) = raw.split_once("://")?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    let url = url::Url::parse(raw).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(OriginKey {
        scheme: url.scheme().to_owned(),
        host,
        port: url.port(),
    })
}

fn is_loopback(origin: &OriginKey) -> bool {
    matches!(origin.scheme.as_str(), "http" | "https")
        && matches!(origin.host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

/// Loopback origins are always allowed; others must equal an entry of `allowed` after normalisation.
pub fn origin_allowed(origin: &str, allowed: &[String]) -> bool {
    let Some(key) = parse_origin(origin) else {
        return false;
    };
    is_loopback(&key)
        || allowed
            .iter()
            .filter_map(|a| parse_origin(a))
            .any(|a| a == key)
}

#[derive(Clone)]
pub struct GuardState {
    pub api_key: Option<ApiKey>,
    pub allowed_origins: Arc<Vec<String>>,
}

/// Rejects a disallowed `Origin` with 403, then a missing or wrong API key with 401.
pub async fn guard(State(state): State<GuardState>, req: Request, next: Next) -> Response {
    let mut origins = req.headers().get_all(ORIGIN).iter();
    if let Some(origin) = origins.next() {
        let allowed = origins.next().is_none()
            && origin
                .to_str()
                .is_ok_and(|o| origin_allowed(o, &state.allowed_origins));
        if !allowed {
            return forbidden();
        }
    }
    if let Some(key) = &state.api_key {
        let authorized = presented_key(req.headers()).is_some_and(|p| key.matches(&p));
        if !authorized {
            return unauthorized();
        }
    }
    next.run(req).await
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(CONTENT_TYPE, "application/json")],
        FORBIDDEN_BODY,
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (WWW_AUTHENTICATE, "Bearer"),
            (CONTENT_TYPE, "application/json"),
        ],
        UNAUTHORIZED_BODY,
    )
        .into_response()
}
