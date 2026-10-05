//! HTTP ルート。OAuth の各エンドポイントは MCP Python SDK（mcp-test が使うもの）と同じ形。

use crate::auth::{
    construct_redirect_uri, normalize_url, pkce_s256, AuthorizationParams, CallbackOutcome,
    ClientRecord, OAuthServer, TokenError, AUTHORIZATION_PATH, GITHUB_CALLBACK_PATH,
    GITHUB_SETUP_PATH, MCP_PATH, REGISTRATION_PATH, TOKEN_PATH,
};
use crate::backend::McpBackend;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub public_url: String,
    pub backend: Arc<dyn McpBackend>,
    pub oauth: Arc<OAuthServer>,
}

pub fn router(state: AppState) -> Router {
    let resource_metadata_path = format!("/.well-known/oauth-protected-resource{MCP_PATH}");
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route(MCP_PATH, post(mcp_v3))
        .route("/.well-known/oauth-authorization-server", get(oauth_metadata))
        .route(&resource_metadata_path, get(resource_metadata))
        // RFC 9728 のパス挿入を試さないクライアント向けの予備。
        .route("/.well-known/oauth-protected-resource", get(resource_metadata))
        .route(AUTHORIZATION_PATH, get(authorize).post(authorize))
        .route(TOKEN_PATH, post(token))
        .route(REGISTRATION_PATH, post(register))
        .route(GITHUB_CALLBACK_PATH, get(github_callback))
        .route(GITHUB_SETUP_PATH, get(github_setup))
        .with_state(state)
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn text(status: u16, body: String) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    no_store(
        (
            status,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
            .into_response(),
    )
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    no_store(response)
}

/// x-www-form-urlencoded を辞書にする（同じキーは後勝ち）。
fn parse_form(raw: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(raw).into_owned().collect()
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    format!("MCP endpoint: POST {}{MCP_PATH}\n", state.public_url)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let mut allowed: Vec<String> = state
        .oauth
        .allowed_ids
        .read()
        .map(|ids| ids.iter().cloned().collect())
        .unwrap_or_default();
    allowed.sort();
    Json(json!({
        "ok": true,
        "service": "mcp.duxca.com",
        "version": env!("CARGO_PKG_VERSION"),
        "public_url": state.public_url,
        "github_configured": state.oauth.github.configured(),
        "allowed_github_ids": allowed,
    }))
}

// ---------------------------------------------------------------------------
// メタデータ

async fn oauth_metadata(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(state.oauth.metadata()),
    )
        .into_response()
}

async fn resource_metadata(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(state.oauth.protected_resource_metadata()),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// /authorize

struct AuthorizeContext {
    params: HashMap<String, String>,
    client: Option<ClientRecord>,
    redirect_uri: Option<String>,
    state: Option<String>,
}

impl AuthorizeContext {
    /// RFC 6749 4.1.2.1: client と redirect_uri が確かなら戻し先へ、そうでなければ 400 JSON。
    async fn error(mut self, oauth: &OAuthServer, error: &str, description: &str, load_client: bool) -> Response {
        if self.client.is_none() && load_client {
            if let Some(id) = self.params.get("client_id").filter(|s| !s.is_empty()) {
                self.client = oauth.get_client(id).await;
            }
        }
        if self.redirect_uri.is_none() {
            if let Some(client) = &self.client {
                let raw = self.params.get("redirect_uri").map(String::as_str);
                if raw.is_none() || raw.and_then(normalize_url).is_some() {
                    self.redirect_uri = client.validate_redirect_uri(raw).ok();
                }
            }
        }
        if self.state.is_none() {
            self.state = self.params.get("state").cloned();
        }
        match (&self.redirect_uri, &self.client) {
            (Some(uri), Some(_)) => redirect(&construct_redirect_uri(
                uri,
                &[
                    ("error", Some(error)),
                    ("error_description", Some(description)),
                    ("state", self.state.as_deref()),
                ],
            )),
            _ => {
                let mut body = json!({ "error": error, "error_description": description });
                if let Some(state) = &self.state {
                    body["state"] = json!(state);
                }
                no_store((StatusCode::BAD_REQUEST, Json(body)).into_response())
            }
        }
    }
}

async fn authorize(
    State(state): State<AppState>,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let oauth = state.oauth.as_ref();
    let params = if method == Method::POST {
        parse_form(&body)
    } else {
        parse_form(query.unwrap_or_default().as_bytes())
    };
    let mut ctx = AuthorizeContext {
        state: params.get("state").cloned(),
        params,
        client: None,
        redirect_uri: None,
    };

    // 入力の検証（SDK の AuthorizationRequest 相当）
    let p = &ctx.params;
    let mut problems: Vec<String> = Vec::new();
    let mut error = "invalid_request";
    if p.get("client_id").is_none() {
        problems.push("client_id: Field required".into());
    }
    match p.get("response_type").map(String::as_str) {
        Some("code") => {}
        Some(_) => {
            error = "unsupported_response_type";
            problems.push("response_type: Input should be 'code'".into());
        }
        None => problems.push("response_type: Field required".into()),
    }
    if p.get("code_challenge").is_none() {
        problems.push("code_challenge: Field required".into());
    }
    if let Some(m) = p.get("code_challenge_method") {
        if m != "S256" {
            problems.push("code_challenge_method: Input should be 'S256'".into());
        }
    }
    if let Some(uri) = p.get("redirect_uri") {
        if normalize_url(uri).is_none() {
            problems.push("redirect_uri: Input should be a valid URL".into());
        }
    }
    if !problems.is_empty() {
        let description = problems.join("\n");
        return ctx.error(oauth, error, &description, true).await;
    }

    let client_id = ctx.params["client_id"].clone();
    let Some(client) = oauth.get_client(&client_id).await else {
        let description = format!("Client ID '{client_id}' not found");
        return ctx.error(oauth, "invalid_request", &description, false).await;
    };
    ctx.client = Some(client.clone());

    let requested_redirect = ctx.params.get("redirect_uri").cloned();
    let redirect_uri = match client.validate_redirect_uri(requested_redirect.as_deref()) {
        Ok(uri) => uri,
        Err(description) => return ctx.error(oauth, "invalid_request", &description, true).await,
    };
    ctx.redirect_uri = Some(redirect_uri.clone());

    let scopes = match client.validate_scope(ctx.params.get("scope").map(String::as_str)) {
        Ok(scopes) => scopes.unwrap_or_default(),
        Err(description) => return ctx.error(oauth, "invalid_scope", &description, true).await,
    };

    let params = AuthorizationParams {
        state: ctx.state.clone(),
        scopes,
        code_challenge: ctx.params["code_challenge"].clone(),
        redirect_uri,
        redirect_uri_provided_explicitly: requested_redirect.is_some(),
        resource: ctx.params.get("resource").cloned(),
    };
    match oauth.authorize(&client, params) {
        Ok(next) => redirect(&next),
        Err(e) => ctx.error(oauth, e.error, &e.description, true).await,
    }
}

// ---------------------------------------------------------------------------
// /github/callback, /github/setup

async fn github_callback(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let q = parse_form(query.unwrap_or_default().as_bytes());
    let outcome = state
        .oauth
        .complete_github_callback(
            q.get("code").map(String::as_str),
            q.get("state").map(String::as_str),
            q.get("error").map(String::as_str),
        )
        .await;
    match outcome {
        CallbackOutcome::Redirect(url) => redirect(&url),
        CallbackOutcome::Text(status, body) => text(status, body),
    }
}

async fn github_setup(State(state): State<AppState>) -> Response {
    if state.oauth.github.configured() {
        return text(
            200,
            format!(
                "GitHub OAuth は設定済み。\nコールバック URL は {}\n",
                state.oauth.github.redirect_uri()
            ),
        );
    }
    text(503, state.oauth.setup_text())
}

// ---------------------------------------------------------------------------
// /token

fn token_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn token_error(error: &str, description: &str) -> Response {
    token_response(
        StatusCode::BAD_REQUEST,
        json!({ "error": error, "error_description": description }),
    )
}

impl From<TokenError> for Response {
    fn from(e: TokenError) -> Self {
        token_error(e.error, &e.description)
    }
}

async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let oauth = state.oauth.as_ref();
    let form = parse_form(&body);
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let client = match oauth.authenticate_client(&form, authorization).await {
        Ok(client) => client,
        Err(message) => {
            return token_response(
                StatusCode::UNAUTHORIZED,
                json!({ "error": "invalid_client", "error_description": message }),
            )
        }
    };

    let grant_type = match form.get("grant_type").map(String::as_str) {
        Some(g @ ("authorization_code" | "refresh_token")) => g,
        Some(_) => return token_error("unsupported_grant_type", "Unsupported grant type"),
        None => return token_error("invalid_request", "grant_type: Field required"),
    };
    if !client.grant_types.iter().any(|g| g == grant_type) {
        return token_error(
            "unsupported_grant_type",
            &format!(
                "Unsupported grant type (supported grant types are {:?})",
                client.grant_types
            ),
        );
    }

    let tokens = if grant_type == "authorization_code" {
        let (Some(code), Some(verifier)) = (form.get("code"), form.get("code_verifier")) else {
            return token_error("invalid_request", "code and code_verifier are required");
        };
        let token_redirect = match form.get("redirect_uri") {
            Some(raw) => match normalize_url(raw) {
                Some(uri) => Some(uri),
                None => return token_error("invalid_request", "redirect_uri: Input should be a valid URL"),
            },
            None => None,
        };
        let Some(auth_code) = oauth.load_authorization_code(&client, code) else {
            return token_error("invalid_grant", "authorization code does not exist");
        };
        if auth_code.expires_at < crate::auth::now() {
            return token_error("invalid_grant", "authorization code has expired");
        }
        // /authorize と /token で redirect_uri が変わっていないこと（RFC 6749 10.6）
        let redirect_ok = if auth_code.redirect_uri_provided_explicitly {
            token_redirect.as_deref() == Some(auth_code.redirect_uri.as_str())
        } else {
            token_redirect.is_none() || token_redirect.as_deref() == Some(auth_code.redirect_uri.as_str())
        };
        if !redirect_ok {
            return token_error(
                "invalid_request",
                "redirect_uri did not match the one used when creating auth code",
            );
        }
        if pkce_s256(verifier) != auth_code.code_challenge {
            return token_error("invalid_grant", "incorrect code_verifier");
        }
        match oauth.exchange_authorization_code(&client, &auth_code) {
            Ok(t) => t,
            Err(e) => return e.into(),
        }
    } else {
        let Some(refresh) = form.get("refresh_token") else {
            return token_error("invalid_request", "refresh_token: Field required");
        };
        let Some(current) = oauth.load_refresh_token(&client, refresh) else {
            return token_error("invalid_grant", "refresh token does not exist");
        };
        if current.expires_at < crate::auth::now() {
            return token_error("invalid_grant", "refresh token has expired");
        }
        let scopes: Vec<String> = match form.get("scope").filter(|s| !s.is_empty()) {
            Some(s) => s.split(' ').map(str::to_string).collect(),
            None => current.scopes.clone(),
        };
        if let Some(bad) = scopes.iter().find(|s| !current.scopes.contains(s)) {
            return token_error(
                "invalid_scope",
                &format!("cannot request scope `{bad}` not provided by refresh token"),
            );
        }
        match oauth.exchange_refresh_token(&client, refresh, scopes) {
            Ok(t) => t,
            Err(e) => return e.into(),
        }
    };
    token_response(StatusCode::OK, serde_json::to_value(tokens).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// /register（RFC 7591）

async fn register(State(state): State<AppState>, body: Bytes) -> Response {
    let invalid = |description: String| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_client_metadata", "error_description": description })),
        )
            .into_response()
    };
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return invalid(format!("Invalid JSON: {e}")),
    };
    let client = match crate::auth::client_from_registration(&value) {
        Ok(client) => client,
        Err(description) => return invalid(description),
    };
    tracing::info!(
        client_name = client.client_name.as_deref().unwrap_or("-"),
        method = %client.token_endpoint_auth_method,
        "registered oauth client"
    );
    let body = serde_json::to_value(&client).unwrap_or_default();
    state.oauth.register_client(client);
    no_store((StatusCode::CREATED, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// POST /mcp/v3

fn unauthorized(oauth: &OAuthServer) -> Response {
    let www = format!(
        "Bearer error=\"invalid_token\", error_description=\"Authentication required\", resource_metadata=\"{}\"",
        oauth.resource_metadata_url()
    );
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid_token", "error_description": "Authentication required" })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&www) {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if raw.len() > 7 && raw[..7].eq_ignore_ascii_case("bearer ") {
        Some(&raw[7..])
    } else {
        None
    }
}

async fn mcp_v3(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(token) = bearer(&headers) else {
        return unauthorized(&state.oauth);
    };
    let Some(principal) = state.oauth.load_access_token(token) else {
        return unauthorized(&state.oauth);
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v @ Value::Object(_)) => v,
        _ => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "json" }))).into_response(),
    };
    tracing::info!(
        subject = %principal.subject,
        method = payload.get("method").and_then(|v| v.as_str()).unwrap_or("?"),
        "mcp"
    );
    match state.backend.handle(payload).await {
        Some(reply) => Json(reply).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}
