//! 宛先エージェントが `register_agent` で登録した起床用 webhook（元 lib/webhook.js の移植）。
//!
//! 送り先は公開アドレスに限る。登録時に URL のホストを見て、送る直前にもう一度見る。
//! ホスト名は自前の resolver で引いて公開アドレスだけを返すので、reqwest が実際に繋ぐ先は
//! 検証済みのアドレスになる（DNS の差し替えで内部へ向けられない）。

use super::store::MessageView;
use crate::auth::is_global_ip;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde_json::{json, Value};
use sha2::Sha256;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::{Host, Url};

pub const EVENT: &str = "relay.message.created";
const TIMEOUT: Duration = Duration::from_secs(5);
/// 同時に送る webhook の数。超えた分は送らずに諦める。
pub const MAX_IN_FLIGHT: usize = 16;
pub const BLOCKED: &str = "blocked:non_public_address";

/// 登録された送り先。値はログにも応答にも出さないので Debug も伏せる。
#[derive(Clone)]
pub struct WebhookTarget {
    pub url: String,
    /// `Authorization` にそのまま載せる値
    pub auth: Option<String>,
    /// 署名用の秘密（登録時に必須）
    pub secret: String,
    /// false なら本文に text と添付を載せない（id と名前だけ）
    pub include_text: bool,
}

impl fmt::Debug for WebhookTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookTarget { .. }")
    }
}

/// webhook に載せるメッセージ。`include_text` が false なら text と添付を外す
/// （受け手は check_messages で取りに来る）。
fn payload(message: &MessageView, include_text: bool) -> Value {
    let mut value = serde_json::to_value(message).unwrap_or_default();
    if !include_text {
        if let Some(fields) = value.as_object_mut() {
            fields.remove("text");
            fields.remove("attachments");
        }
    }
    value
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

/// URL のホストが公開アドレスを指しうるか。IP は url クレートが 10 進・16 進・8 進・短縮形を
/// 正規化したものを見る。ホスト名は localhost 系だけをここで断り、残りは送る直前の名前解決で見る。
pub fn host_is_public(url: &Url, allow_loopback: bool) -> bool {
    let ip_ok = |ip: IpAddr| is_global_ip(ip) || (allow_loopback && ip.is_loopback());
    match url.host() {
        Some(Host::Ipv4(ip)) => ip_ok(ip.into()),
        Some(Host::Ipv6(ip)) => ip_ok(ip.into()),
        Some(Host::Domain(name)) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            !name.is_empty() && name != "localhost" && !name.ends_with(".localhost")
        }
        None => false,
    }
}

type LookupFuture = Pin<Box<dyn Future<Output = anyhow::Result<Vec<IpAddr>>> + Send>>;
/// ホスト名 → アドレス。本番は CIMD フェッチと同じ `public_host_addrs`。
pub type Lookup = Arc<dyn Fn(String) -> LookupFuture + Send + Sync>;

#[derive(Debug)]
struct NotPublic;

impl fmt::Display for NotPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("host has no public address")
    }
}

impl std::error::Error for NotPublic {}

/// 公開アドレスだけを reqwest に渡す resolver。空なら繋がずに `NotPublic` で失敗させる。
struct PublicOnly(Lookup);

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = (self.0)(name.as_str().to_string());
        Box::pin(async move {
            // ポート 0 は URL のポート（無ければ 443）に置き換わる
            let addrs: Vec<SocketAddr> = lookup
                .await?
                .into_iter()
                .filter(|ip| is_global_ip(*ip))
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            if addrs.is_empty() {
                return Err(NotPublic.into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn blocked_by_resolver(e: &reqwest::Error) -> bool {
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if s.is::<NotPublic>() {
            return true;
        }
        source = s.source();
    }
    false
}

pub struct Webhook {
    /// 作れなかったときは None で、webhook は送らない。
    client: Option<reqwest::Client>,
    in_flight: Arc<Semaphore>,
    /// テスト用。ループバックの http 受信側を許す。
    pub allow_loopback_http: bool,
}

impl Webhook {
    pub fn new() -> Self {
        Self::with_lookup(Arc::new(|host: String| {
            Box::pin(async move {
                let addrs = crate::auth::public_host_addrs(&host).await?;
                Ok(addrs.into_iter().map(|a| a.ip()).collect())
            })
        }))
    }

    pub fn with_lookup(lookup: Lookup) -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // 認証ヘッダを転送先へ持ち出さない
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(PublicOnly(lookup)))
            .build();
        let client = match client {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::error!(error = %e, "relay: cannot build the webhook client; webhooks are disabled");
                None
            }
        };
        Self {
            client,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            allow_loopback_http: false,
        }
    }

    /// 送信 1 件分の枠。埋まっていれば None。
    pub fn slot(&self) -> Option<OwnedSemaphorePermit> {
        self.in_flight.clone().try_acquire_owned().ok()
    }

    /// 単発・リトライなし。戻り値は `http_<status>` / `error:<種別>` / `blocked:..` / `skipped:..`。
    pub async fn notify(&self, target: &WebhookTarget, message: &MessageView) -> String {
        let Some(client) = &self.client else {
            return "skipped:webhooks_disabled".into();
        };
        let Ok(url) = Url::parse(&target.url) else {
            return "error:InvalidRequest".into();
        };
        if !host_is_public(&url, self.allow_loopback_http) {
            return BLOCKED.into();
        }
        let body =
            json!({ "event": EVENT, "message": payload(message, target.include_text) }).to_string();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string();
        let sig = signature(&target.secret, &ts, &body);
        // 署名の鍵そのものは送らない。受信側の静的な認証は webhook_auth（Authorization）で行う
        let mut request = client
            .post(url)
            .header("content-type", "application/json")
            .header("user-agent", "muse-relay/1.0")
            .header("x-relay-timestamp", &ts)
            .header("x-relay-signature", format!("sha256={sig}"))
            .header("x-relay-event", EVENT)
            .body(body);
        if let Some(auth) = &target.auth {
            request = request.header("authorization", auth);
        }
        match request.send().await {
            Ok(r) => format!("http_{}", r.status().as_u16()),
            Err(e) if blocked_by_resolver(&e) => BLOCKED.into(),
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
    }

    #[test]
    fn debug_hides_the_target() {
        let t = WebhookTarget {
            url: "https://hook.example/secret-path".into(),
            auth: Some("Bearer dummy-auth".into()),
            secret: "dummy-secret".into(),
            include_text: true,
        };
        assert_eq!(format!("{t:?}"), "WebhookTarget { .. }");
    }

    /// url クレートが正規化した後のホストで判定するので、10 進・16 進・8 進・短縮形も同じ扱いになる。
    #[test]
    fn internal_hosts_are_not_public_in_any_notation() {
        for url in [
            "https://127.0.0.1/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://0x7f.0.0.1/",
            "https://0177.0.0.1/",
            "https://127.1/",
            "https://0/",
            "https://10.0.0.1/",
            "https://012.0.0.1/",
            "https://167772161/",
            "https://192.168.1.10:8443/",
            "https://172.16.0.1/",
            "https://169.254.169.254/",
            "https://0xa9fea9fe/",
            "https://100.64.0.1/",
            "https://[::1]/",
            "https://[::]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:a9fe:a9fe]/",
            "https://[::127.0.0.1]/",
            "https://[2002:7f00:1::1]/",
            "https://[fe80::1]/",
            "https://[fd00::1]/",
            "https://localhost/",
            "https://LOCALHOST./",
            "https://api.localhost/",
        ] {
            let parsed = Url::parse(url).unwrap();
            assert!(!host_is_public(&parsed, false), "{url} -> {parsed}");
        }
        for url in [
            "https://hook.example/x",
            "https://1.1.1.1/x",
            "https://[2606:4700::1111]/x",
            "https://hook.example:8443/x",
        ] {
            assert!(host_is_public(&Url::parse(url).unwrap(), false), "{url}");
        }
        // テスト用の許可はループバックだけ
        let loopback = Url::parse("http://127.0.0.1:9/").unwrap();
        assert!(host_is_public(&loopback, true));
        assert!(!host_is_public(
            &Url::parse("http://10.0.0.1/").unwrap(),
            true
        ));
    }

    #[tokio::test]
    async fn without_a_client_nothing_is_sent() {
        let webhook = Webhook {
            client: None,
            in_flight: Arc::new(Semaphore::new(1)),
            allow_loopback_http: false,
        };
        let target = WebhookTarget {
            url: "https://hook.example/x".into(),
            auth: None,
            secret: "s".into(),
            include_text: true,
        };
        let message = MessageView {
            id: "1".into(),
            cursor: "1".into(),
            thread_id: "thr_1".into(),
            from: "a".into(),
            to: "b".into(),
            text: "x".into(),
            created_at: String::new(),
            read: false,
            read_at: None,
            attachments: Vec::new(),
        };
        assert_eq!(
            webhook.notify(&target, &message).await,
            "skipped:webhooks_disabled"
        );
    }
}
