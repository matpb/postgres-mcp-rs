//! HTTP access guard: API key matching, presented-key extraction, Origin rules and the middleware.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use postgres_mcp::http_guard::{ApiKey, GuardState, guard, origin_allowed, presented_key};
use tower::ServiceExt;

const UNAUTHORIZED_BODY: &str = r#"{"error":"unauthorized","message":"Missing or invalid API key. Send it as X-API-Key or Authorization: Bearer."}"#;
const FORBIDDEN_BODY: &str = r#"{"error":"forbidden","message":"Origin not allowed"}"#;
const KEY: &str = "0123456789abcdef-test-key";

fn header_map(pairs: &[(&str, &[u8])]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            HeaderValue::from_bytes(value).expect("valid header value"),
        );
    }
    headers
}

#[test]
fn api_key_matches() {
    let key = ApiKey::new(KEY);
    assert!(key.matches(KEY.as_bytes()));
    assert!(!key.matches(b"0123456789abcdef-wrong-key"));
    assert!(
        !key.matches(b"0123456789abcdef-test"),
        "prefix must not match"
    );
    assert!(
        !key.matches(b"0123456789abcdef-test-key-and-more"),
        "longer must not match"
    );
    assert!(!key.matches(b""), "empty must not match");
    assert!(
        !key.matches(&[0xff, 0xfe, 0x00, 0x80]),
        "non-UTF-8 must not match"
    );
    assert_eq!(format!("{key:?}"), "ApiKey(..)");
}

#[test]
fn presented_key_forms() {
    let x_api_key = header_map(&[("x-api-key", b"from-header")]);
    assert_eq!(presented_key(&x_api_key), Some(b"from-header".to_vec()));

    let bearer = header_map(&[("authorization", b"Bearer tok-123")]);
    assert_eq!(presented_key(&bearer), Some(b"tok-123".to_vec()));

    let lowercase = header_map(&[("authorization", b"bearer tok-456")]);
    assert_eq!(presented_key(&lowercase), Some(b"tok-456".to_vec()));

    let both = header_map(&[
        ("x-api-key", b"from-header"),
        ("authorization", b"Bearer from-bearer"),
    ]);
    assert_eq!(presented_key(&both), Some(b"from-header".to_vec()));

    let basic = header_map(&[("authorization", b"Basic dXNlcjpwYXNz")]);
    assert_eq!(presented_key(&basic), None);

    assert_eq!(presented_key(&HeaderMap::new()), None);
}

#[test]
fn presented_key_empty_and_non_utf8_values() {
    let empty = header_map(&[("x-api-key", b"")]);
    assert_eq!(presented_key(&empty), Some(Vec::new()));

    let raw = header_map(&[("x-api-key", &[0xff, 0x80, b'a'])]);
    assert_eq!(presented_key(&raw), Some(vec![0xff, 0x80, b'a']));
}

#[test]
fn origin_table() {
    let none: Vec<String> = Vec::new();
    let app = vec!["https://app.example.com".to_owned()];
    let cases: &[(&str, &[String], bool)] = &[
        ("http://localhost:3000", &none, true),
        ("http://127.0.0.1", &none, true),
        ("http://[::1]:8080", &none, true),
        ("https://localhost", &none, true),
        ("http://localhost.evil.com", &none, false),
        ("http://evil.com", &none, false),
        ("null", &none, false),
        ("", &none, false),
        ("https://app.example.com", &app, true),
        ("HTTPS://APP.EXAMPLE.COM:443", &app, true),
        ("http://app.example.com", &app, false),
        ("https://app.example.com:8443", &app, false),
        ("https://app.example.com.evil.com", &app, false),
        ("file://", &none, false),
        ("file:///etc/passwd", &none, false),
        ("http://localhost@evil.com", &none, false),
        ("https://app.example.com/", &app, false),
    ];
    for (origin, allowed, expected) in cases {
        assert_eq!(
            origin_allowed(origin, allowed),
            *expected,
            "origin {origin:?} with allowed {allowed:?}"
        );
    }
}

#[test]
fn origin_allowed_list_is_normalised() {
    let allowed = vec!["HTTPS://App.Example.com:443".to_owned()];
    assert!(origin_allowed("https://app.example.com", &allowed));
    assert!(!origin_allowed("http://app.example.com", &allowed));
}

fn app(api_key: Option<&str>, allowed_origins: &[&str]) -> Router {
    let state = GuardState {
        api_key: api_key.map(ApiKey::new),
        allowed_origins: Arc::new(allowed_origins.iter().map(|o| o.to_string()).collect()),
    };
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(from_fn_with_state(state, guard))
}

/// Sends a GET to `/` with each header appended, returning status, headers and body text.
async fn send(app: Router, headers: &[(&str, &str)]) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().uri("/");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("router responds");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8(body.to_vec()).expect("utf-8 body"),
    )
}

#[tokio::test]
async fn no_key_no_headers_is_ok() {
    let (status, _, body) = send(app(None, &[]), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn key_configured_and_missing_is_401() {
    let (status, headers, body) = send(app(Some(KEY), &[]), &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[&http::header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(headers[&http::header::CONTENT_TYPE], "application/json");
    assert_eq!(body, UNAUTHORIZED_BODY);
}

#[tokio::test]
async fn key_wrong_is_401() {
    let (status, _, body) = send(
        app(Some(KEY), &[]),
        &[("x-api-key", "wrong-key-value-0000")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, UNAUTHORIZED_BODY);
}

#[tokio::test]
async fn key_right_via_x_api_key_is_ok() {
    let (status, _, body) = send(app(Some(KEY), &[]), &[("x-api-key", KEY)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn key_right_via_bearer_is_ok() {
    let bearer = format!("Bearer {KEY}");
    let (status, _, body) = send(app(Some(KEY), &[]), &[("authorization", &bearer)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn bad_origin_is_403_even_with_right_key() {
    let (status, headers, body) = send(
        app(Some(KEY), &["https://app.example.com"]),
        &[("x-api-key", KEY), ("origin", "https://evil.example.net")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(headers[&http::header::CONTENT_TYPE], "application/json");
    assert_eq!(body, FORBIDDEN_BODY);
}

#[tokio::test]
async fn loopback_origin_with_right_key_is_ok() {
    let (status, _, body) = send(
        app(Some(KEY), &[]),
        &[("x-api-key", KEY), ("origin", "http://localhost:3000")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn allowed_origin_with_right_key_is_ok() {
    let (status, _, _) = send(
        app(Some(KEY), &["https://app.example.com"]),
        &[("x-api-key", KEY), ("origin", "https://app.example.com")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn two_origin_headers_are_403() {
    let (status, _, body) = send(
        app(None, &[]),
        &[
            ("origin", "http://localhost:3000"),
            ("origin", "http://localhost:3001"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, FORBIDDEN_BODY);
}

#[tokio::test]
async fn no_key_bad_origin_is_403() {
    let (status, _, body) = send(app(None, &[]), &[("origin", "https://evil.example.net")]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, FORBIDDEN_BODY);
}
