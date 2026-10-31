//! 宛先エージェントが `register_agent` で登録した起床用 webhook（元 lib/webhook.js の移植）。

use super::store::MessageView;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const EVENT: &str = "relay.message.created";
const TIMEOUT: Duration = Duration::from_secs(5);

/// 登録された送り先。値はログにも応答にも出さないので Debug も伏せる。
#[derive(Clone)]
pub struct WebhookTarget {
    pub url: String,
    /// `Authorization` にそのまま載せる値
    pub auth: Option<String>,
    /// 署名用の秘密（未設定なら空文字列）
    pub secret: String,
}

impl fmt::Debug for WebhookTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookTarget { .. }")
    }
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

pub struct Webhook {
    client: reqwest::Client,
}

impl Webhook {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // 秘密ヘッダを転送先へ持ち出さない
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// 単発・リトライなし。戻り値は `http_<status>` / `error:<種別>`。
    pub async fn notify(&self, target: &WebhookTarget, message: &MessageView) -> String {
        let body = json!({ "event": EVENT, "message": message }).to_string();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string();
        let sig = signature(&target.secret, &ts, &body);
        let mut request = self
            .client
            .post(&target.url)
            .header("content-type", "application/json")
            .header("user-agent", "muse-relay/1.0")
            .header("x-relay-timestamp", &ts)
            .header("x-relay-signature", format!("sha256={sig}"))
            // 静的比較しかできない受信側のため、元実装どおり生の秘密も送る
            .header("x-relay-secret", &target.secret)
            .header("x-relay-event", EVENT)
            .body(body);
        if let Some(auth) = &target.auth {
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
        // 秘密を登録しなかった宛先は空文字列で署名する
        assert_eq!(signature("", "1", "{}").len(), 64);
    }

    #[test]
    fn debug_hides_the_target() {
        let t = WebhookTarget {
            url: "https://hook.example/secret-path".into(),
            auth: Some("Bearer dummy-auth".into()),
            secret: "dummy-secret".into(),
        };
        assert_eq!(format!("{t:?}"), "WebhookTarget { .. }");
    }
}
