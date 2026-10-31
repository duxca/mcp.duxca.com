//! `/relay/v1` の HTTP 部分。本体（`POST /relay/v1`）の認証はゲートウェイ側（`crate::routes`）で行い、
//! ここには認証済みの部屋（subject）とリクエストが来る。配下の公開パスは health と docs だけ。

use super::mcp;
use super::{docs, Relay, RelayError, MAX_BODY_BYTES, PREFIX};
use axum::body::Bytes;
use axum::extract::{FromRequest, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::sync::Arc;

pub fn router(relay: Arc<Relay>) -> Router {
    let path = |p: &str| format!("{PREFIX}{p}");
    Router::new()
        .route(&path("/health"), any(health))
        .route(&path("/docs"), any(docs_text))
        .route(&path("/docs.md"), any(docs_text))
        .route(&path("/llms.txt"), any(docs_text))
        .route(&path("/{*rest}"), any(not_found))
        .with_state(relay)
}

fn json_response(status: u16, body: &Value) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        json_response(self.status, &json!({ "error": self.message }))
    }
}

async fn not_found() -> Response {
    RelayError::new(404, format!("not found; see {PREFIX}/docs")).into_response()
}

async fn health() -> Response {
    json_response(200, &json!({ "status": "ok" }))
}

async fn docs_text(State(relay): State<Arc<Relay>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        docs::docs_text(&relay.origin, relay.store.limits()),
    )
        .into_response()
}

fn parse_error() -> Response {
    json_response(
        400,
        &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }),
    )
}

/// 認証済みの `{PREFIX}` へのリクエスト。`room` は OAuth の subject。
pub async fn serve(relay: Arc<Relay>, room: String, request: Request) -> Response {
    match *request.method() {
        Method::GET => {
            let mut response =
                RelayError::new(405, "SSE stream not supported; POST JSON-RPC requests")
                    .into_response();
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST, DELETE"));
            return response;
        }
        Method::DELETE => return json_response(200, &json!({})),
        Method::POST => {}
        _ => return RelayError::new(405, "method not allowed").into_response(),
    }
    let bytes = match Bytes::from_request(request, &()).await {
        Ok(bytes) => bytes,
        Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return RelayError::new(
                413,
                format!("request body too large (limit {MAX_BODY_BYTES} bytes)"),
            )
            .into_response()
        }
        Err(_) => return parse_error(),
    };
    let body = if bytes.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return parse_error(),
        }
    };
    // 生のボディは long-poll の間まで抱えない
    drop(bytes);
    match mcp::handle(relay, room.into(), body).await {
        Some(reply) => json_response(200, &reply),
        None => StatusCode::ACCEPTED.into_response(),
    }
}
