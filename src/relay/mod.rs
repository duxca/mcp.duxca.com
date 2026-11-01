//! エージェント間の対称メッセージリレー（AISupplyGuy/muse-relay の移植を対称化したもの）。
//!
//! - MCP エンドポイントは `POST {PUBLIC_URL}/relay/v1` の 1 本。認証はゲートウェイの OAuth のみ。
//! - 「部屋」は OAuth の subject（GitHub 数値 id）。同じアカウントのトークンなら同じ部屋を共有する。
//! - エージェント名と起床用 webhook は呼び出し側の自己申告（`agent` / `to` / `register_agent`）。
//! - ストアは SQLite（再起動しても残る）。メッセージと添付は `RETENTION_DAYS` 日で消える。
//!   保存量・同時待機・同時 webhook・バッチには上限がある（`Limits` など）。
//! - 会話ログは tracing の info で出す（webhook の値と添付の中身は出さない）。

mod docs;
mod js;
mod mcp;
mod routes;
mod store;
#[cfg(test)]
mod tests;
mod webhook;

use crate::db::Db;
use serde_json::{Map, Value};
use std::sync::Arc;

pub use routes::{router, serve};
use store::MessageView;
pub use store::{Limits, Store, DEFAULT_MAX_TOTAL_STORAGE_BYTES};
use webhook::{Webhook, WebhookTarget};

pub const PREFIX: &str = "/relay/v1";
/// リクエストボディ上限。添付 3 MB（base64 で約 4 MB）+ 本文に余裕を持たせる。
pub const MAX_BODY_BYTES: usize = 6 * 1024 * 1024;
const MAX_WEBHOOK_URL: usize = 2048;
const MAX_WEBHOOK_HEADER: usize = 4096;

/// MCP の業務エラー（HTTP 相当のステータス + 説明）。
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

/// DB の失敗。中身はログにだけ出す。
impl From<rusqlite::Error> for RelayError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(error = %e, "relay: storage failed");
        Self::new(503, "the relay's storage failed; try again later")
    }
}

pub struct Relay {
    pub store: Store,
    webhook: Webhook,
    /// PUBLIC_URL（スキーム+ホスト）
    origin: String,
}

impl Relay {
    /// `max_total_storage_bytes` は全部屋の添付の上限。他の上限は `Limits` の既定値。
    pub fn new(public_url: &str, max_total_storage_bytes: u64, db: Db) -> Self {
        Self::with_limits(
            public_url,
            Limits::with_total_attachment_bytes(max_total_storage_bytes),
            db,
        )
    }

    pub fn with_limits(public_url: &str, limits: Limits, db: Db) -> Self {
        Self {
            store: Store::new(limits, db),
            webhook: Webhook::new(),
            origin: public_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn base_url(&self) -> String {
        format!("{}{PREFIX}", self.origin)
    }

    /// 保存して会話ログを出し、宛先に webhook があれば発火する。戻り値の bool は `notified`。
    /// 引数は保存したら手放す（大きな未使用の引数を webhook や待機の間まで抱えない）。
    async fn send(
        self: &Arc<Self>,
        room: &str,
        from: &str,
        to: &str,
        args: Map<String, Value>,
    ) -> Result<(MessageView, bool), RelayError> {
        let (message, target) = self.store.send_message(room, from, to, &args)?;
        drop(args);
        let files: Vec<String> = message
            .attachments
            .iter()
            .map(|a| format!("{} ({}, {} bytes)", a.filename, a.content_type, a.size))
            .collect();
        // 名前と本文は利用者の入力なので Debug 形式（改行などをエスケープ）で 1 行に収める
        tracing::info!(
            room,
            message_id = %message.id,
            thread_id = %message.thread_id,
            from = ?message.from,
            to = ?message.to,
            text = ?message.text,
            attachments = files.len(),
            files = ?files,
            "relay: message stored"
        );
        let notified = match target {
            Some(target) => self.notify(room, &message, target).await,
            None => false,
        };
        Ok((message, notified))
    }

    /// webhook を送り、結果をメッセージに記録する。クライアントが切れても送信と記録は最後まで行う。
    /// 同時に送れる数を超えたら送らずに諦め、そのことを記録する。
    async fn notify(
        self: &Arc<Self>,
        room: &str,
        message: &MessageView,
        target: WebhookTarget,
    ) -> bool {
        let Some(slot) = self.webhook.slot() else {
            let status = "skipped:too_many_in_flight";
            self.store
                .set_webhook_status(room, &message.id, status.into());
            tracing::warn!(room, to = ?message.to, message_id = %message.id, result = status, "relay: webhook");
            return false;
        };
        let relay = self.clone();
        let room = room.to_string();
        let message = message.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let started = std::time::Instant::now();
            let status = relay.webhook.notify(&target, &message).await;
            relay
                .store
                .set_webhook_status(&room, &message.id, status.clone());
            tracing::info!(
                room,
                to = ?message.to,
                message_id = %message.id,
                result = %status,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "relay: webhook"
            );
            status.starts_with("http_2")
        })
        .await
        .unwrap_or(false)
    }

    /// `register_agent` の webhook 引数。値はエラーにも載せない。
    fn webhook_target(&self, a: &Map<String, Value>) -> Result<Option<WebhookTarget>, RelayError> {
        let text = |k: &str| -> Result<Option<String>, RelayError> {
            match a.get(k).unwrap_or(&Value::Null) {
                Value::Null => Ok(None),
                Value::String(s) if s.is_empty() => Ok(None),
                Value::String(s) => Ok(Some(s.clone())),
                _ => Err(RelayError::bad_request(format!("\"{k}\" must be a string"))),
            }
        };
        let header = |k: &str| -> Result<Option<String>, RelayError> {
            let v = text(k)?;
            if v.as_deref().is_some_and(|s| {
                s.len() > MAX_WEBHOOK_HEADER || axum::http::HeaderValue::from_str(s).is_err()
            }) {
                return Err(RelayError::bad_request(format!(
                    "\"{k}\" must be usable as an HTTP header value (visible ASCII, max {MAX_WEBHOOK_HEADER} bytes)"
                )));
            }
            Ok(v)
        };
        let url = text("webhook_url")?;
        let auth = header("webhook_auth")?;
        let secret = header("webhook_secret")?;
        let Some(url) = url else {
            return Ok(None);
        };
        let loopback = self.webhook.allow_loopback_http;
        let parsed = url::Url::parse(&url).ok().filter(|u| {
            u.host_str().is_some() && (u.scheme() == "https" || (loopback && u.scheme() == "http"))
        });
        let Some(parsed) = parsed.filter(|_| url.chars().count() <= MAX_WEBHOOK_URL) else {
            return Err(RelayError::bad_request(format!(
                "\"webhook_url\" must be an https URL of at most {MAX_WEBHOOK_URL} characters"
            )));
        };
        if !webhook::host_is_public(&parsed, loopback) {
            return Err(RelayError::bad_request(
                "\"webhook_url\" must point to the public internet (localhost, private, link-local and other internal addresses are refused)",
            ));
        }
        let Some(secret) = secret else {
            return Err(RelayError::bad_request(
                "\"webhook_secret\" is required with \"webhook_url\": every delivery is signed with it (X-Relay-Signature)",
            ));
        };
        Ok(Some(WebhookTarget { url, auth, secret }))
    }
}

#[cfg(test)]
impl Relay {
    /// テストの受信側（http://127.0.0.1）へ webhook を送れるようにする。
    pub fn allowing_loopback_http_webhooks(mut self) -> Self {
        self.webhook.allow_loopback_http = true;
        self
    }

    /// webhook の名前解決を `hosts` の表に差し替える（公開アドレスかどうかの判定はそのまま）。
    pub fn with_webhook_dns(mut self, hosts: &[(&str, std::net::IpAddr)]) -> Self {
        let hosts: std::collections::HashMap<String, std::net::IpAddr> =
            hosts.iter().map(|(h, ip)| (h.to_string(), *ip)).collect();
        let loopback = self.webhook.allow_loopback_http;
        self.webhook = Webhook::with_lookup(Arc::new(move |host: String| {
            let found = hosts.get(&host).copied();
            Box::pin(async move { Ok(found.into_iter().collect()) })
        }));
        self.webhook.allow_loopback_http = loopback;
        self
    }

    /// webhook の同時送信枠を全部取る（溢れたときの挙動を見るため）。
    pub fn take_all_webhook_slots(&self) -> Vec<tokio::sync::OwnedSemaphorePermit> {
        std::iter::from_fn(|| self.webhook.slot()).collect()
    }
}
