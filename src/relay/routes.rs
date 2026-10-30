//! `/relay/v1` 配下の HTTP ルート（元 api/index.js の移植）。
//! エラーは常に `{"error": "..."}`。メソッド判定は元実装と同じ順序で handler 内で行う。

use super::js;
use super::mcp;
use super::store::{iso_ms, now_ms, ListArgs, MessageView, Side, MAX_WAIT_SECONDS};
use super::{docs, Caller, Relay, RelayError, MAX_BODY_BYTES, PREFIX};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

const ASK_DEFAULT_WAIT_SECONDS: f64 = 240.0;

pub fn router(relay: Arc<Relay>) -> Router {
    let path = |p: &str| format!("{PREFIX}{p}");
    Router::new()
        .route(&path("/health"), any(health))
        .route(&path("/docs"), any(docs_text))
        .route(&path("/docs.md"), any(docs_text))
        .route(&path("/llms.txt"), any(docs_text))
        .route(&path("/openapi.json"), any(openapi))
        .route(&path("/mcp"), any(mcp_endpoint))
        .route(&path("/files/{attachment_id}"), any(file))
        .route(&path("/ask"), any(ask))
        .route(&path("/messages"), any(messages))
        .route(&path("/messages/read"), any(messages_read))
        .route(&path("/threads"), any(threads))
        .route(&path("/threads/{thread_id}"), any(thread))
        .route(&path("/{*rest}"), any(not_found))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
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

fn unauthorized(message: &str) -> Response {
    let mut response = json_response(401, &json!({ "error": message }));
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn method_not_allowed() -> Response {
    RelayError::new(405, "method not allowed").into_response()
}

async fn not_found() -> Response {
    RelayError::new(404, format!("not found; see {PREFIX}/docs")).into_response()
}

fn query(request: &Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

async fn read_body(request: Request) -> Result<Bytes, RelayError> {
    Bytes::from_request(request, &()).await.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            RelayError::new(
                413,
                format!("request body too large (limit {MAX_BODY_BYTES} bytes)"),
            )
        } else {
            RelayError::bad_request("could not read the request body")
        }
    })
}

/// 空ボディは `{}`。JSON でなければ 400。
async fn read_json(request: Request) -> Result<Value, RelayError> {
    let bytes = read_body(request).await?;
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&bytes).map_err(|_| RelayError::bad_request("Body must be valid JSON"))
}

/// webhook を送り、結果をメッセージに記録する。クライアントが切れても送信は最後まで行う。
async fn notify_grok(relay: &Arc<Relay>, message: &MessageView) -> String {
    let task_relay = relay.clone();
    let task_message = message.clone();
    let status = tokio::spawn(async move {
        let status = task_relay.webhook.notify(&task_message).await;
        task_relay
            .store
            .set_webhook_status(&task_message.id, status.clone());
        status
    })
    .await
    .unwrap_or_else(|_| "error:Internal".into());
    tracing::info!(
        message_id = %message.id,
        thread_id = %message.thread_id,
        attachments = message.attachments.len(),
        webhook = %status,
        "relay: muse message stored"
    );
    status
}

fn muse_only(relay: &Relay, request: &Request) -> Option<Response> {
    (relay.caller(request.headers()) != Some(Caller::Muse)).then(|| {
        unauthorized("unauthorized: send the Muse API key as \"Authorization: Bearer <key>\"")
    })
}

// ---------------------------------------------------------------------------
// 無認証

async fn health() -> Response {
    json_response(200, &json!({ "status": "ok" }))
}

async fn docs_text(State(relay): State<Arc<Relay>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        docs::docs_text(&relay.origin, relay.max_total_storage_bytes),
    )
        .into_response()
}

async fn openapi(State(relay): State<Arc<Relay>>) -> Response {
    json_response(200, &docs::openapi(&relay.origin))
}

// ---------------------------------------------------------------------------
// Grok: MCP

async fn mcp_endpoint(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    if relay.caller(request.headers()) != Some(Caller::Grok) {
        return unauthorized("unauthorized");
    }
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
        _ => return method_not_allowed(),
    }
    let bytes = match read_body(request).await {
        Ok(bytes) => bytes,
        Err(e) if e.status == 413 => return e.into_response(),
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
    match mcp::handle(relay, body).await {
        Some(reply) => json_response(200, &reply),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

fn parse_error() -> Response {
    json_response(
        400,
        &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }),
    )
}

// ---------------------------------------------------------------------------
// ファイル（どちらのキーでも可）

/// JS の `encodeURIComponent`。
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn content_disposition(filename: &str) -> String {
    // filename= は ASCII だけにし、本来の名前は filename* に載せる
    let ascii: String = filename
        .chars()
        .map(|c| match c {
            '"' | '\\' => '_',
            c if c == ' ' || c.is_ascii_graphic() => c,
            _ => '_',
        })
        .collect();
    format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        encode_uri_component(filename)
    )
}

async fn file(
    State(relay): State<Arc<Relay>>,
    Path(attachment_id): Path<String>,
    request: Request,
) -> Response {
    if relay.caller(request.headers()).is_none() {
        return unauthorized("unauthorized");
    }
    if request.method() != Method::GET {
        return method_not_allowed();
    }
    let att = match relay.store.get_attachment(&Value::String(attachment_id)) {
        Ok(att) => att,
        Err(e) => return e.into_response(),
    };
    let header_value = |s: &str| HeaderValue::from_str(s).ok();
    let mut response = Response::new(Body::from(att.data));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header_value(&att.meta.content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    if let Some(v) = header_value(&content_disposition(&att.meta.filename)) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(v) = header_value(&att.meta.sha256) {
        headers.insert(HeaderName::from_static("x-content-sha256"), v);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

// ---------------------------------------------------------------------------
// Muse: REST

async fn ask(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    if let Some(denied) = muse_only(&relay, &request) {
        return denied;
    }
    if request.method() != Method::POST {
        return method_not_allowed();
    }
    match ask_inner(&relay, request).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn ask_inner(relay: &Arc<Relay>, request: Request) -> Result<Response, RelayError> {
    let b = read_json(request).await?;
    let w = match b.get("wait_seconds") {
        None | Some(Value::Null) => ASK_DEFAULT_WAIT_SECONDS,
        Some(v) => js::number(v),
    };
    if !w.is_finite() || w < 0.0 {
        return Err(RelayError::bad_request("\"wait_seconds\" must be a number"));
    }
    let message = relay.store.send_message(Side::Muse, &b)?;
    let notified = notify_grok(relay, &message).await.starts_with("http_2");
    let after: u64 = message.id.parse().unwrap_or(u64::MAX);
    let reply = relay
        .store
        .wait_for_reply(
            Side::Muse,
            &message.thread_id,
            after,
            w.min(MAX_WAIT_SECONDS),
        )
        .await;
    let body = match reply {
        Some(mut reply) => {
            if b.get("mark_reply_read") != Some(&Value::Bool(false)) {
                relay
                    .store
                    .mark_read(Side::Muse, &json!({ "message_ids": [reply.id] }))?;
                reply.read = true;
                reply.read_at = Some(iso_ms(now_ms()));
            }
            json!({ "message": message, "reply": reply, "timed_out": false, "notified": notified })
        }
        None => {
            let hint = format!(
                "Keep waiting with GET {PREFIX}/messages?thread_id={}&since={}&wait=240",
                message.thread_id, message.cursor
            );
            json!({
                "message": message, "reply": null, "timed_out": true,
                "thread_id": message.thread_id, "next_cursor": message.cursor,
                "notified": notified, "hint": hint,
            })
        }
    };
    Ok(json_response(200, &body))
}

async fn messages(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    if let Some(denied) = muse_only(&relay, &request) {
        return denied;
    }
    let result = match request.method().clone() {
        Method::POST => post_message(&relay, request).await,
        Method::GET => {
            let mut q = query(&request);
            let mut take = |k: &str| q.remove(k).map(Value::String).unwrap_or(Value::Null);
            let args = ListArgs {
                since: take("since"),
                unread_only: take("unread_only"),
                limit: take("limit"),
                thread_id: take("thread_id"),
                wait: take("wait"),
            };
            relay
                .store
                .list_incoming(Side::Muse, args)
                .await
                .map(|out| json_response(200, &out))
        }
        _ => return method_not_allowed(),
    };
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn post_message(relay: &Arc<Relay>, request: Request) -> Result<Response, RelayError> {
    let b = read_json(request).await?;
    let message = relay.store.send_message(Side::Muse, &b)?;
    let notified = notify_grok(relay, &message).await.starts_with("http_2");
    Ok(json_response(
        201,
        &json!({ "message": message, "notified": notified }),
    ))
}

async fn messages_read(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    if let Some(denied) = muse_only(&relay, &request) {
        return denied;
    }
    if request.method() != Method::POST {
        return method_not_allowed();
    }
    let result = match read_json(request).await {
        Ok(b) => relay.store.mark_read(Side::Muse, &b),
        Err(e) => Err(e),
    };
    match result {
        Ok(out) => json_response(200, &out),
        Err(e) => e.into_response(),
    }
}

async fn threads(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    if let Some(denied) = muse_only(&relay, &request) {
        return denied;
    }
    if request.method() != Method::GET {
        return not_found().await;
    }
    let limit = query(&request)
        .remove("limit")
        .map(Value::String)
        .unwrap_or(Value::Null);
    json_response(200, &relay.store.list_threads(Side::Muse, &limit))
}

async fn thread(
    State(relay): State<Arc<Relay>>,
    Path(thread_id): Path<String>,
    request: Request,
) -> Response {
    if let Some(denied) = muse_only(&relay, &request) {
        return denied;
    }
    if request.method() != Method::GET {
        return not_found().await;
    }
    match relay.store.get_thread(&Value::String(thread_id)) {
        Ok(out) => json_response(200, &out),
        Err(e) => e.into_response(),
    }
}
