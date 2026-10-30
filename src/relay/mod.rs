//! Muse ⇄ Grok の双方向リレー（AISupplyGuy/muse-relay の移植）。
//!
//! - `{PUBLIC_URL}/relay/v1` 配下に REST（Muse）と MCP（Grok）を置く。
//! - 認証は静的キー 2 本（`RELAY_MUSE_KEY` / `RELAY_GROK_KEY`）。OAuth には載せない。
//! - ストアはメモリのみ。両方のキーが揃っていなければ relay 自体を無効にする。

mod docs;
mod js;
mod mcp;
mod routes;
mod store;
#[cfg(test)]
mod tests;
mod webhook;

use crate::config::Config;
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub use routes::router;
pub use store::{Store, DEFAULT_MAX_TOTAL_STORAGE_BYTES};
use webhook::Webhook;

pub const PREFIX: &str = "/relay/v1";
/// リクエストボディ上限。添付 3 MB（base64 で約 4 MB）+ 本文に余裕を持たせる。
pub const MAX_BODY_BYTES: usize = 6 * 1024 * 1024;

/// REST / MCP 共通の業務エラー（HTTP ステータス + 説明）。
#[derive(Debug, Clone)]
pub struct RelayError {
    pub status: u16,
    pub message: String,
}

impl RelayError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }
}

/// キーの SHA-256 だけを持ち、比較は両側をハッシュしてから定数時間で行う。
struct KeyDigest([u8; 32]);

impl KeyDigest {
    fn new(key: &str) -> Self {
        Self(Sha256::digest(key.as_bytes()).into())
    }
    fn matches(&self, presented: &str) -> bool {
        !presented.is_empty()
            && crate::auth::constant_time_eq(&Sha256::digest(presented.as_bytes()), &self.0)
    }
}

/// どちらの静的キーで来たか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Muse,
    Grok,
}

pub struct Relay {
    pub store: Store,
    webhook: Webhook,
    muse_key: KeyDigest,
    grok_key: KeyDigest,
    /// PUBLIC_URL（スキーム+ホスト）
    origin: String,
    max_total_storage_bytes: u64,
}

impl Relay {
    /// 両方のキーが設定されていれば relay を作る。片方だけなら警告して無効。
    pub fn from_config(config: &Config, public_url: &str) -> Option<Arc<Self>> {
        let muse = config.relay_muse_key.trim();
        let grok = config.relay_grok_key.trim();
        match (muse.is_empty(), grok.is_empty()) {
            (true, true) => return None,
            (false, false) => {}
            _ => {
                tracing::warn!(
                    "RELAY_MUSE_KEY と RELAY_GROK_KEY は両方必要。片方だけなので relay は無効"
                );
                return None;
            }
        }
        if muse == grok {
            tracing::warn!("RELAY_MUSE_KEY と RELAY_GROK_KEY が同じ値。relay は無効");
            return None;
        }
        let origin = public_url.trim_end_matches('/').to_string();
        let max = config.relay_max_total_storage_bytes;
        Some(Arc::new(Self {
            store: Store::new(format!("{origin}{PREFIX}"), max),
            webhook: Webhook::new(
                &config.relay_grok_webhook_url,
                &config.relay_grok_webhook_auth,
                &config.relay_webhook_secret,
            ),
            muse_key: KeyDigest::new(muse),
            grok_key: KeyDigest::new(grok),
            origin,
            max_total_storage_bytes: max,
        }))
    }

    pub fn base_url(&self) -> String {
        format!("{}{PREFIX}", self.origin)
    }

    /// 提示されたキーがどちらに一致するか。
    fn caller(&self, headers: &HeaderMap) -> Option<Caller> {
        let key = presented_key(headers);
        if self.muse_key.matches(&key) {
            Some(Caller::Muse)
        } else if self.grok_key.matches(&key) {
            Some(Caller::Grok)
        } else {
            None
        }
    }
}

/// `Authorization: Bearer <key>`、なければ `X-API-Key: <key>`。
fn presented_key(headers: &HeaderMap) -> String {
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if auth.len() > 7 && auth[..6].eq_ignore_ascii_case("bearer") {
            let rest = &auth[6..];
            if rest.starts_with(|c: char| c.is_ascii_whitespace()) {
                return rest.trim().to_string();
            }
        }
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_string()
}
