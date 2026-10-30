//! Muse の新着を Grok 側へ通知する webhook（元 lib/webhook.js の移植）。

use super::store::MessageView;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const EVENT: &str = "muse.message.created";
const TIMEOUT: Duration = Duration::from_secs(5);

pub struct Webhook {
    url: Option<String>,
    /// `Authorization` にそのまま載せる値
    auth: Option<String>,
    secret: String,
    client: reqwest::Client,
}

/// `HMAC-SHA256(secret, "{timestamp}.{body}")` の hex。
pub fn signature(secret: &str, timestamp: &str, body: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn non_empty(s: &str) -> Option<String> {
    Some(s.trim().to_string()).filter(|s| !s.is_empty())
}

impl Webhook {
    pub fn new(url: &str, auth: &str, secret: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // 秘密ヘッダを転送先へ持ち出さない
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            url: non_empty(url),
            auth: non_empty(auth),
            secret: secret.to_string(),
            client,
        }
    }

    /// 単発・リトライなし。戻り値は `http_<status>` / `error:<種別>` / `skipped:no_url`。
    pub async fn notify(&self, message: &MessageView) -> String {
        let Some(url) = &self.url else {
            return "skipped:no_url".into();
        };
        let body = json!({ "event": EVENT, "message": message }).to_string();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string();
        let sig = signature(&self.secret, &ts, &body);
        let mut request = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("user-agent", "muse-relay/1.0")
            .header("x-relay-timestamp", &ts)
            .header("x-relay-signature", format!("sha256={sig}"))
            // 静的比較しかできない受信側のため、元実装どおり生の秘密も送る
            .header("x-relay-secret", &self.secret)
            .header("x-relay-event", EVENT)
            .body(body);
        if let Some(auth) = &self.auth {
            request = request.header("authorization", auth);
        }
        match request.send().await {
            Ok(r) => format!("http_{}", r.status().as_u16()),
            Err(e) if e.is_timeout() => "error:TimeoutError".into(),
            Err(e) if e.is_connect() => "error:ConnectError".into(),
            Err(e) if e.is_builder() => "error:InvalidRequest".into(),
            Err(_) => "error:RequestError".into(),
        }
    }
}

#[cfg(test)]
mod webhook_tests {
    use super::*;

    #[test]
    fn signature_is_hmac_sha256_hex_over_timestamp_dot_body() {
        // python3: hmac.new(b"test-secret", b'1700000000.{"event":"muse.message.created"}', "sha256").hexdigest()
        assert_eq!(
            signature(
                "test-secret",
                "1700000000",
                r#"{"event":"muse.message.created"}"#
            ),
            "a7dc5ece5d258bc49eaa15e39a9d647e63f331ad44539e7ec7e125f2ee36dcf6"
        );
        // 空の秘密でも署名はできる（元実装は WEBHOOK_SECRET 未設定で空文字）
        assert_eq!(signature("", "1", "{}").len(), 64);
    }
}
