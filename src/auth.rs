//! GitHub OAuth / bearer のプレースホルダ。
//!
//! 本番では mcp-test と同様に:
//! - GitHub OAuth で本人確認
//! - ALLOWED_GITHUB_IDS（数値 id）のみ許可
//! - 自前 bearer を発行し POST /mcp/v3 を保護
//!
//! いまはルート骨格と設定チェックだけ。

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub const GITHUB_CALLBACK_PATH: &str = "/github/callback";
pub const GITHUB_SETUP_PATH: &str = "/github/setup";

/// Authorization: Bearer があれば受け、無ければ 401（骨格）。
/// トークン検証・発行は未実装。
pub fn require_bearer(headers: &axum::http::HeaderMap) -> Result<String, Response> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": "Authorization: Bearer <token> が必要（骨格）",
            })),
        )
            .into_response());
    };
    let Ok(raw) = value.to_str() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized", "message": "invalid Authorization header" })),
        )
            .into_response());
    };
    let Some(token) = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer ")) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized", "message": "Bearer scheme required" })),
        )
            .into_response());
    };
    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized", "message": "empty bearer" })),
        )
            .into_response());
    }
    // TODO: 発行済みトークン照合 + GitHub id allowlist
    Ok(token.to_string())
}

pub fn setup_text(public_url: &str, github_configured: bool) -> String {
    if github_configured {
        format!(
            "GitHub OAuth は設定済み（骨格）。\n\
             コールバック: {public_url}{GITHUB_CALLBACK_PATH}\n\
             MCP: POST {public_url}/mcp/v3\n\
             本実装（認可コード交換・bearer 発行）はこれから。\n"
        )
    } else {
        format!(
            "GITHUB_CLIENT_ID と GITHUB_CLIENT_SECRET を置いて再起動する。\n\
             OAuth App のコールバック URL は {public_url}{GITHUB_CALLBACK_PATH}\n"
        )
    }
}
