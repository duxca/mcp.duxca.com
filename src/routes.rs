//! HTTP ルート。

use crate::auth::{self, GITHUB_CALLBACK_PATH, GITHUB_SETUP_PATH};
use crate::backend::McpBackend;
use crate::config::Config;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub public_url: String,
    pub backend: Arc<dyn McpBackend>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/mcp/v3", post(mcp_v3))
        .route(GITHUB_CALLBACK_PATH, get(github_callback))
        .route(GITHUB_SETUP_PATH, get(github_setup))
        .with_state(state)
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    format!(
        "mcp.duxca.com gateway (skeleton)\n\
         MCP endpoint: POST {}/mcp/v3\n\
         health: GET /health\n\
         github setup: GET {}\n",
        state.public_url, GITHUB_SETUP_PATH
    )
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "service": "mcp.duxca.com",
        "version": env!("CARGO_PKG_VERSION"),
        "public_url": state.public_url,
        "github_configured": state.config.github_configured(),
        "allowed_github_ids": state.config.allowed_ids().into_iter().collect::<Vec<_>>(),
    }))
}

async fn mcp_v3(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = auth::require_bearer(&headers) {
        return resp;
    }

    match state.backend.handle(body).await {
        Some(reply) => Json(reply).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

async fn github_callback(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        format!(
            "GitHub OAuth callback は骨格のみ。\n\
             想定コールバック: {}{}\n\
             mcp-test 相当の認可コード交換・allowlist・bearer 発行を後続で実装する。\n",
            state.public_url, GITHUB_CALLBACK_PATH
        ),
    )
}

async fn github_setup(State(state): State<AppState>) -> impl IntoResponse {
    auth::setup_text(&state.public_url, state.config.github_configured())
}
