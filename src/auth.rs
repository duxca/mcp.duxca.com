//! GitHub で本人を確認し、このプロセスが bearer を発行する。
//!
//! pascal の `~/Github/mcp-test/auth.py`（MCP Python SDK の OAuth サーバ）の移植。
//! - 動的クライアント登録（RFC 7591）と Client ID Metadata Document（CIMD）
//! - /authorize →（初めての client_id と redirect_uri なら同意画面 → /authorize/consent）→ GitHub ログイン
//!   → /oauth/callback/github → 認可コード → /token。callback は認可を始めたブラウザ（Cookie）に限る
//! - /revoke（RFC 7009）。refresh は認可から `GRANT_MAX_LIFETIME` までしか延ばせず、再利用を検知したら失効させる
//! - GitHub 認可 URL は river と同じ oauth2 クレート + `/oauth/callback/github`
//! - トークン交換は Accept: application/json の手書き POST（JSON エラーをログ可能）
//! - 許可は GitHub の数値 id（login は改名で再利用されうるので使わない）
//! - クライアント・認可の途中・コード・トークンは SQLite（`crate::db`）に置き、再起動しても残る。
//!   トークン・コード・state・client_secret は SHA-256 だけを保存する

use crate::db::{Db, DbError};
use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::TryRng;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

/// river.duxca.com と同じ GitHub OAuth コールバックパス。
pub const REDIRECT_PATH: &str = "/oauth/callback/github";
/// GitHub OAuth App 未設定時の案内。
pub const GITHUB_SETUP_PATH: &str = "/oauth/setup/github";
pub const AUTHORIZATION_PATH: &str = "/authorize";
/// 同意画面の「許可 / 拒否」を受ける。
pub const CONSENT_PATH: &str = "/authorize/consent";
pub const TOKEN_PATH: &str = "/token";
pub const REGISTRATION_PATH: &str = "/register";
/// RFC 7009
pub const REVOCATION_PATH: &str = "/revoke";

pub const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
pub const GITHUB_USER_URL: &str = "https://api.github.com/user";

pub const ACCESS_TTL: i64 = 60 * 60;
/// refresh で入れ替えた古い access を消さずに通す秒数。入れ替えの直前に出たリクエストや、
/// クライアントが新しい組へ差し替える途中のリクエストを 401 にしないため。
pub const REFRESH_GRACE_SECS: i64 = 5 * 60;
pub const REFRESH_TTL: i64 = 14 * 24 * 60 * 60;
/// 認可 1 回あたりの絶対期限。refresh を使い続けても、ここから先へは延ばさない。
pub const GRANT_MAX_LIFETIME: i64 = 90 * 24 * 60 * 60;
pub const CODE_TTL: i64 = 5 * 60;
pub const PENDING_TTL: i64 = 10 * 60;
pub const CIMD_TTL: i64 = 5 * 60;
/// 動的登録は誰でも叩ける。DB を食い潰されないよう古いものから捨てる（トークンを持つものは捨てない）。
pub const MAX_CLIENTS: usize = 1000;
/// `oauth_clients.record` の合計バイト数の上限。
pub const MAX_CLIENT_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// 動的登録の受付数（全体、1 分あたり）。送信元の IP は信用できる値が取れないので全体で数える。
pub const REGISTRATIONS_PER_MINUTE: u32 = 20;
/// `/authorize` の途中の行数。超えたら古い順に捨てる。
pub const MAX_PENDING: usize = 1000;
/// 承認済みの (client_id, redirect_uri, subject) の数。超えたら古い順に捨てる。
pub const MAX_CONSENTS: usize = 1000;
/// 取得した CIMD をメモリに置く数。超えたら最後に使ったのが古いものから捨てる。
pub const CIMD_CACHE_CAPACITY: usize = 100;
/// CIMD を同時に取りに行く数。
pub const CIMD_MAX_CONCURRENT_FETCHES: usize = 4;
/// `/register`・`/authorize`・`/token`・`/revoke` のボディ上限。
pub const MAX_OAUTH_BODY_BYTES: usize = 16 * 1024;
// 登録項目（動的登録と CIMD）と /authorize の引数の上限
pub const MAX_REDIRECT_URIS: usize = 10;
pub const MAX_URI_LEN: usize = 2048;
pub const MAX_CLIENT_NAME_CHARS: usize = 200;
pub const MAX_SCOPE_BYTES: usize = 1024;
pub const MAX_CONTACTS: usize = 10;
pub const MAX_CONTACT_LEN: usize = 320;
/// grant_types・response_types の件数と、software_id などの短い値の長さ
pub const MAX_LIST_ITEMS: usize = 10;
pub const MAX_SHORT_VALUE_LEN: usize = 200;
pub const MAX_STATE_BYTES: usize = 1024;
const USER_AGENT: &str = "duxca-mcp";
const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `secrets.token_urlsafe(32)` 相当。
pub fn token_urlsafe() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// RFC 7636 §4.2: S256 の code_challenge は SHA-256 の base64url（パディング無し）で 43 文字。
pub fn is_s256_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// 認可を始めたブラウザに置く値（`token_urlsafe` の形）か。
pub fn is_browser_secret(value: &str) -> bool {
    is_s256_challenge(value)
}

/// 同意画面のフォームに載せる CSRF トークン。ブラウザの Cookie の値から作り、値そのものは画面に出さない。
pub fn consent_csrf_token(browser: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(format!("consent-csrf:{browser}").as_bytes()))
}

/// フォームの CSRF トークンが、このブラウザの Cookie から作ったものか（double-submit）。
pub fn verify_consent_csrf(browser: &str, token: &str) -> bool {
    constant_time_eq(consent_csrf_token(browser).as_bytes(), token.as_bytes())
}

/// 保存と照合に使う SHA-256 の hex。照合しかしない値は平文で置かない。
fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn to_json(value: &impl Serialize) -> rusqlite::Result<String> {
    serde_json::to_string(value).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn from_json<T: DeserializeOwned>(raw: &str) -> rusqlite::Result<T> {
    serde_json::from_str(raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// RFC 6749 §2.3.1: Basic の client_id / client_secret は percent-decode（`+` は空白にしない）。
fn percent_unquote(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = from_hex(bytes[i + 1]);
            let lo = from_hex(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// URL を正規化した文字列にする。比較はこの形どうしで行う。
pub fn normalize_url(raw: &str) -> Option<String> {
    Url::parse(raw).ok().map(|u| u.to_string())
}

// ---------------------------------------------------------------------------
// redirect_uri の allowlist

/// 末尾 `/*` は 1 セグメントだけ、末尾 `/` は配下すべて、それ以外はパス完全一致。
/// ポート無しのループバックはポートを問わない（RFC 8252 §7.3）。
pub const DEFAULT_REDIRECT_ALLOWLIST: &[&str] = &[
    "https://chatgpt.com/connector/oauth/*",
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://agent.meta.ai/api/hatch/oauth/callback",
    "https://www.cursor.com/agents/mcp/oauth/callback",
    "https://grok.com/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
];

enum PathRule {
    Exact,
    OneSegment,
    Subtree,
}

struct RedirectRule {
    base: Url,
    path: PathRule,
}

impl RedirectRule {
    fn matches(&self, url: &Url) -> bool {
        let base = &self.base;
        if url.scheme() != base.scheme() || url.host_str() != base.host_str() {
            return false;
        }
        let any_port = base.port().is_none() && is_loopback(base);
        if !any_port && url.port_or_known_default() != base.port_or_known_default() {
            return false;
        }
        let path = url.path();
        match self.path {
            PathRule::Exact => path == base.path(),
            PathRule::Subtree => path.starts_with(base.path()),
            PathRule::OneSegment => path
                .strip_prefix(base.path())
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/')),
        }
    }
}

/// 登録・利用できる redirect_uri。認可コードを第三者のサーバへ送らせないために絞る。
pub struct RedirectAllowlist(Vec<RedirectRule>);

impl RedirectAllowlist {
    pub fn parse<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut rules = Vec::new();
        for raw in entries.into_iter().map(str::trim).filter(|s| !s.is_empty()) {
            let (prefix, path) = match raw.strip_suffix('*') {
                Some(p) if p.ends_with('/') => (p, PathRule::OneSegment),
                Some(_) => return Err(format!("`*` は末尾の `/*` だけ使える: {raw}")),
                None if raw.ends_with('/') => (raw, PathRule::Subtree),
                None => (raw, PathRule::Exact),
            };
            let base = Url::parse(prefix)
                .ok()
                .filter(|u| {
                    u.host_str().is_some()
                        && u.username().is_empty()
                        && u.password().is_none()
                        && u.query().is_none()
                        && u.fragment().is_none()
                })
                .ok_or_else(|| format!("redirect allowlist の項目が不正: {raw}"))?;
            rules.push(RedirectRule { base, path });
        }
        if rules.is_empty() {
            return Err("redirect allowlist が空".into());
        }
        Ok(Self(rules))
    }

    pub fn allows(&self, raw: &str) -> bool {
        let Ok(url) = Url::parse(raw) else {
            return false;
        };
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return false;
        }
        self.0.iter().any(|rule| rule.matches(&url))
    }

    /// ループバック以外の項目のホスト。CIMD を取りに行ってよいホストの既定にする。
    pub fn hosts(&self) -> HashSet<String> {
        self.0
            .iter()
            .filter(|rule| !is_loopback(&rule.base))
            .filter_map(|rule| rule.base.host_str().map(str::to_ascii_lowercase))
            .collect()
    }
}

impl Default for RedirectAllowlist {
    fn default() -> Self {
        Self::parse(DEFAULT_REDIRECT_ALLOWLIST.iter().copied()).expect("default redirect allowlist")
    }
}

fn is_loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// 承認を覚えるときの redirect_uri。ループバックはポートを問わず同じ戻り先とみなす（RFC 8252 §7.3）。
fn consent_redirect_key(uri: &str) -> String {
    match Url::parse(uri) {
        Ok(mut url) if url.scheme() == "http" && is_loopback(&url) => {
            let _ = url.set_port(None);
            url.to_string()
        }
        _ => uri.to_string(),
    }
}

/// `construct_redirect_uri`: 既存のクエリを残して値のある引数だけ足す。
pub fn construct_redirect_uri(base: &str, params: &[(&str, Option<&str>)]) -> String {
    let Ok(mut url) = Url::parse(base) else {
        return base.to_string();
    };
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            if let Some(value) = value {
                pairs.append_pair(key, value);
            }
        }
    }
    url.to_string()
}

// ---------------------------------------------------------------------------
// GitHub

#[derive(Debug, thiserror::Error)]
#[error("github login failed: {0}")]
pub struct GitHubLoginError(pub String);

#[async_trait]
pub trait GitHubLogin: Send + Sync {
    fn configured(&self) -> bool;
    fn redirect_uri(&self) -> &str;
    fn authorization_url(&self, state: &str) -> String;
    /// GitHub の不変の数値 id（文字列）と、表示用の login を返す。
    async fn login_for_code(&self, code: &str) -> Result<(String, String), GitHubLoginError>;
}

pub struct GitHubOAuth {
    client_id: oauth2::ClientId,
    client_secret: oauth2::ClientSecret,
    redirect_uri: oauth2::RedirectUrl,
    http: reqwest::Client,
}

impl std::fmt::Debug for GitHubOAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // client_secret はログに出さない（oauth2::ClientSecret も redacted）。
        f.debug_struct("GitHubOAuth")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

impl GitHubOAuth {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(USER_AGENT)
            // oauth2 クレート推奨: トークン交換でリダイレクトを追わない（SSRF 対策）。
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        Self {
            client_id: oauth2::ClientId::new(client_id),
            client_secret: oauth2::ClientSecret::new(client_secret),
            redirect_uri: oauth2::RedirectUrl::new(redirect_uri).expect("github redirect uri"),
            http,
        }
    }

    /// river / webrtc と同じ BasicClient 組み立て。
    fn basic_client(
        &self,
    ) -> oauth2::basic::BasicClient<
        oauth2::EndpointSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointSet,
    > {
        oauth2::basic::BasicClient::new(self.client_id.clone())
            .set_client_secret(self.client_secret.clone())
            .set_auth_uri(oauth2::AuthUrl::new(GITHUB_AUTH_URL.to_string()).unwrap())
            .set_token_uri(oauth2::TokenUrl::new(GITHUB_TOKEN_URL.to_string()).unwrap())
            .set_redirect_uri(self.redirect_uri.clone())
    }
}

#[async_trait]
impl GitHubLogin for GitHubOAuth {
    fn configured(&self) -> bool {
        !self.client_id.is_empty() && !self.client_secret.secret().is_empty()
    }

    fn redirect_uri(&self) -> &str {
        self.redirect_uri.as_str()
    }

    fn authorization_url(&self, state: &str) -> String {
        // MCP AS 側で発行した pending state をそのまま GitHub の state に載せる。
        let state = state.to_string();
        let (url, _) = self
            .basic_client()
            .authorize_url(|| oauth2::CsrfToken::new(state))
            .add_scope(oauth2::Scope::new("read:user".to_string()))
            .add_extra_param("allow_signup", "false")
            .url();
        url.to_string()
    }

    async fn login_for_code(&self, code: &str) -> Result<(String, String), GitHubLoginError> {
        // Hand-rolled token POST with Accept: application/json.
        // oauth2::exchange_code failed to parse GitHub's default form-urlencoded
        // error bodies ("Failed to parse server response" → opaque 502). JSON
        // lets us log error / error_description without leaking secrets or codes.
        let form = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.secret()),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
        ];
        let token_response = self
            .http
            .post(GITHUB_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|e| {
                tracing::info!(error = %e.without_url(), "github token exchange transport failed");
                GitHubLoginError("token".into())
            })?;
        let status = token_response.status();
        let body: Value = token_response.json().await.map_err(|e| {
            tracing::info!(%status, error = %e.without_url(), "github token exchange body parse failed");
            GitHubLoginError("token".into())
        })?;
        if let Some(err) = body.get("error").and_then(Value::as_str) {
            let desc = body
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("");
            tracing::info!(%status, error = ?err, description = ?desc, "github token exchange failed");
            return Err(GitHubLoginError("token".into()));
        }
        if !status.is_success() {
            tracing::info!(%status, "github token exchange failed (no error field)");
            return Err(GitHubLoginError("token".into()));
        }
        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                tracing::info!(%status, "github token exchange failed: missing access_token");
                GitHubLoginError("token".into())
            })?;

        let user_response = self
            .http
            .get(GITHUB_USER_URL)
            .bearer_auth(access_token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| {
                tracing::info!(error = %e.without_url(), "github account lookup failed");
                GitHubLoginError("lookup".into())
            })?;
        if user_response.status() != reqwest::StatusCode::OK {
            tracing::info!(status = %user_response.status(), "github account lookup failed");
            return Err(GitHubLoginError(user_response.status().to_string()));
        }
        let user: Value = user_response.json().await.map_err(|e| {
            tracing::info!(error = %e.without_url(), "github account lookup failed");
            GitHubLoginError("lookup".into())
        })?;
        // id は改名で変わらない。正の整数だけ受ける。
        let user_id = user
            .get("id")
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or_else(|| GitHubLoginError("id".into()))?;
        let login = user
            .get("login")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| GitHubLoginError("login".into()))?;
        Ok((user_id.to_string(), login.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Client ID Metadata Document

pub fn is_cimd_client_id(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    if url.path().is_empty() || url.path() == "/" {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(host)) => !host.eq_ignore_ascii_case("localhost"),
        _ => false,
    }
}

fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
        || o[0] >= 240)
}

fn is_global_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_ipv4(v4);
    }
    let s = ip.segments();
    let v4 = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    // IPv4 互換（::a.b.c.d、廃止済み）と 6to4（2002:a.b.c.d::/48）は埋め込みの IPv4 で判定する
    if s[..6] == [0; 6] && !ip.is_loopback() && !ip.is_unspecified() {
        return is_global_ipv4(v4(s[6], s[7]));
    }
    if s[0] == 0x2002 && !is_global_ipv4(v4(s[1], s[2])) {
        return false;
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64（64:ff9b::/32）
        || s[0] == 0x0100) // discard
}

pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => is_global_ipv6(v6),
    }
}

#[async_trait]
pub trait ClientMetadataFetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> anyhow::Result<Value>;
}

/// client_id の URL をこのプロセスが取りに行く。非公開アドレスだと内部へ届くので弾く。
/// 解決したアドレスに固定して取りに行く（DNS の差し替えで内部へ向けられないように）。
pub struct HttpClientMetadataFetcher;

/// 公開アドレスだけを残す。ローカル DNS が 198.18.0.0/15 などの合成アドレスを返すときは空。
fn public_addrs(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addrs.into_iter().filter(|a| is_global_ip(a.ip())).collect()
}

/// Cloudflare DoH。ローカル resolver が壊れていても SSRF 判定用の本物の A/AAAA を取る。
async fn resolve_via_doh(host: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build()?;
    let mut addrs = Vec::new();
    for (qtype, field) in [(1u16, "A"), (28u16, "AAAA")] {
        let url = format!(
            "https://cloudflare-dns.com/dns-query?name={}&type={qtype}",
            urlencoding_host(host)
        );
        let response = client
            .get(url)
            .header("Accept", "application/dns-json")
            .send()
            .await?;
        if !response.status().is_success() {
            continue;
        }
        let body: Value = response.json().await?;
        let Some(answers) = body.get("Answer").and_then(Value::as_array) else {
            continue;
        };
        for answer in answers {
            if answer.get("type").and_then(Value::as_u64) != Some(u64::from(qtype)) {
                continue;
            }
            let Some(data) = answer.get("data").and_then(Value::as_str) else {
                continue;
            };
            if let Ok(ip) = data.parse::<IpAddr>() {
                addrs.push(SocketAddr::new(ip, 443));
            }
        }
        let _ = field;
    }
    Ok(public_addrs(addrs))
}

fn urlencoding_host(host: &str) -> String {
    // ホスト名に許容される文字だけなので、最低限エスケープする。
    host.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// `host` の公開アドレス（ポートは 443）。無ければ空。relay の webhook も同じ判定で送り先を決める。
pub(crate) async fn public_host_addrs(host: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let system = public_addrs(tokio::net::lookup_host((host, 443)).await?);
    if !system.is_empty() {
        return Ok(system);
    }
    resolve_via_doh(host).await
}

async fn resolve_public_host(host: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let addrs = public_host_addrs(host).await?;
    if addrs.is_empty() {
        anyhow::bail!("cimd host is not public");
    }
    Ok(addrs)
}

#[async_trait]
impl ClientMetadataFetcher for HttpClientMetadataFetcher {
    async fn fetch(&self, raw: &str) -> anyhow::Result<Value> {
        let url = Url::parse(raw)?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("cimd host"))?
            .to_string();
        let addrs = resolve_public_host(&host).await?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(USER_AGENT)
            .resolve_to_addrs(&host, &addrs)
            .build()?;
        let mut response = client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await?;
        if response.status() != reqwest::StatusCode::OK {
            anyhow::bail!("cimd document status");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > 64_000 {
                anyhow::bail!("cimd document too large");
            }
        }
        let document: Value = serde_json::from_slice(&body)?;
        if !document.is_object() {
            anyhow::bail!("cimd document");
        }
        Ok(document)
    }
}

// ---------------------------------------------------------------------------
// クライアント

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientRecord {
    pub client_id: String,
    /// 平文は登録の応答で 1 回だけ返す。DB には入れない（`secret_sha256` だけを置く）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip)]
    pub secret_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    /// client_uri / logo_uri / contacts など、保存して返すだけの項目。
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ClientRecord {
    /// 登録時に scope が無いクライアントは、呼び出し側の scope をそのまま受ける。
    pub fn validate_scope(&self, requested: Option<&str>) -> Result<Option<Vec<String>>, String> {
        let Some(requested) = requested else {
            return Ok(None);
        };
        let requested: Vec<String> = requested.split(' ').map(str::to_string).collect();
        let Some(allowed) = &self.scope else {
            return Ok(Some(requested));
        };
        let allowed: Vec<&str> = allowed.split(' ').collect();
        for scope in &requested {
            if !allowed.contains(&scope.as_str()) {
                return Err(format!("Client was not registered with scope {scope}"));
            }
        }
        Ok(Some(requested))
    }

    /// 戻り値は正規化済みの redirect_uri。
    pub fn validate_redirect_uri(
        &self,
        requested: Option<&str>,
        allowlist: &RedirectAllowlist,
    ) -> Result<String, String> {
        let uri = match requested {
            Some(raw) => {
                let normalized = normalize_url(raw)
                    .ok_or_else(|| format!("Redirect URI '{raw}' not registered for client"))?;
                if self
                    .redirect_uris
                    .iter()
                    .any(|u| *u == normalized || loopback_matches(u, &normalized))
                {
                    normalized
                } else {
                    return Err(format!("Redirect URI '{raw}' not registered for client"));
                }
            }
            None if self.redirect_uris.len() == 1 => self.redirect_uris[0].clone(),
            None => return Err(
                "redirect_uri must be specified unless the client has exactly one registered URI"
                    .into(),
            ),
        };
        if !allowlist.allows(&uri) {
            return Err(format!("Redirect URI '{uri}' is not allowed"));
        }
        Ok(uri)
    }
}

/// RFC 8252 §7.3: ループバックの redirect_uri はポートを問わず一致とみなす。
fn loopback_matches(registered: &str, requested: &str) -> bool {
    let (Ok(reg), Ok(mut req)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    if reg.scheme() != "http" || !is_loopback(&reg) || reg.port().is_some() {
        return false;
    }
    if req.set_port(None).is_err() {
        return false;
    }
    req == reg
}

fn string_list(value: Option<&Value>, field: &str) -> Result<Option<Vec<String>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{field}: Input should be a valid string"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(format!("{field}: Input should be a valid list")),
    }
}

/// 件数と 1 件の長さ（バイト）に上限のあるリスト。
fn bounded_list(
    value: Option<&Value>,
    field: &str,
    max_items: usize,
    max_len: usize,
) -> Result<Option<Vec<String>>, String> {
    let list = string_list(value, field)?;
    if let Some(list) = &list {
        if list.len() > max_items {
            return Err(format!("{field}: at most {max_items} items"));
        }
        if list.iter().any(|v| v.len() > max_len) {
            return Err(format!(
                "{field}: each item must be at most {max_len} bytes"
            ));
        }
    }
    Ok(list)
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{field}: Input should be a valid string")),
    }
}

/// 長さ（バイト）に上限のある文字列。
fn bounded_string(
    value: Option<&Value>,
    field: &str,
    max_len: usize,
) -> Result<Option<String>, String> {
    let s = optional_string(value, field)?;
    if s.as_ref().is_some_and(|s| s.len() > max_len) {
        return Err(format!("{field}: must be at most {max_len} bytes"));
    }
    Ok(s)
}

fn client_name(value: Option<&Value>) -> Result<Option<String>, String> {
    let name = optional_string(value, "client_name")?;
    if name
        .as_ref()
        .is_some_and(|n| n.chars().count() > MAX_CLIENT_NAME_CHARS)
    {
        return Err(format!(
            "client_name: must be at most {MAX_CLIENT_NAME_CHARS} characters"
        ));
    }
    Ok(name)
}

/// 正規化して、件数・長さ・allowlist を見る。
fn redirect_uris(
    value: Option<&Value>,
    allowlist: &RedirectAllowlist,
) -> Result<Vec<String>, String> {
    let list = string_list(value, "redirect_uris")?
        .ok_or_else(|| "redirect_uris: Field required".to_string())?;
    if list.is_empty() {
        return Err("redirect_uris: List should have at least 1 item".into());
    }
    if list.len() > MAX_REDIRECT_URIS {
        return Err(format!("redirect_uris: at most {MAX_REDIRECT_URIS} items"));
    }
    let list = list
        .iter()
        .map(|u| {
            normalize_url(u)
                .filter(|n| n.len() <= MAX_URI_LEN)
                .ok_or_else(|| {
                    format!(
                        "redirect_uris: Input should be a valid URL of at most {MAX_URI_LEN} bytes"
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(bad) = list.iter().find(|u| !allowlist.allows(u)) {
        return Err(format!("redirect_uris: '{bad}' is not allowed"));
    }
    Ok(list)
}

/// RFC 7591 の登録要求を検証し、登録済みクライアントを作る（SDK の RegistrationHandler 相当）。
/// 誰でも叩けて DB に残るので、項目ごとに長さ・件数の上限を置く。
pub fn client_from_registration(
    body: &Value,
    allowlist: &RedirectAllowlist,
) -> Result<ClientRecord, String> {
    let Some(obj) = body.as_object() else {
        return Err("Input should be an object".into());
    };
    let redirect_uris = redirect_uris(obj.get("redirect_uris"), allowlist)?;

    let method = optional_string(
        obj.get("token_endpoint_auth_method"),
        "token_endpoint_auth_method",
    )?
    .unwrap_or_else(|| "client_secret_post".into());
    match method.as_str() {
        "none" | "client_secret_post" | "client_secret_basic" => {}
        "private_key_jwt" => {
            return Err("token_endpoint_auth_method 'private_key_jwt' is not supported".into())
        }
        other => {
            return Err(format!(
                "token_endpoint_auth_method: '{other}' is not supported"
            ))
        }
    }
    let grant_types = bounded_list(
        obj.get("grant_types"),
        "grant_types",
        MAX_LIST_ITEMS,
        MAX_SHORT_VALUE_LEN,
    )?
    .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    if !grant_types.iter().any(|g| g == "authorization_code") {
        return Err("grant_types must include 'authorization_code'".into());
    }
    if grant_types.iter().any(|g| g == JWT_BEARER_GRANT_TYPE) {
        return Err(format!(
            "grant_types must not include '{JWT_BEARER_GRANT_TYPE}'; \
             the identity-assertion grant requires a pre-registered client"
        ));
    }
    let response_types = bounded_list(
        obj.get("response_types"),
        "response_types",
        MAX_LIST_ITEMS,
        MAX_SHORT_VALUE_LEN,
    )?
    .unwrap_or_else(|| vec!["code".into()]);
    if !response_types.iter().any(|r| r == "code") {
        return Err("response_types must include 'code' for authorization_code grant".into());
    }
    let application_type = optional_string(obj.get("application_type"), "application_type")?
        .unwrap_or_else(|| "native".into());
    if application_type != "web" && application_type != "native" {
        return Err("application_type: Input should be 'web' or 'native'".into());
    }

    let mut extra = Map::new();
    for key in ["software_id", "software_version"] {
        if let Some(s) = bounded_string(obj.get(key), key, MAX_SHORT_VALUE_LEN)? {
            extra.insert(key.into(), Value::String(s));
        }
    }
    for key in [
        "client_uri",
        "logo_uri",
        "tos_uri",
        "policy_uri",
        "jwks_uri",
    ] {
        if let Some(s) = bounded_string(obj.get(key), key, MAX_URI_LEN)?.filter(|s| !s.is_empty()) {
            let ok = Url::parse(&s)
                .map(|u| u.scheme() == "http" || u.scheme() == "https")
                .unwrap_or(false);
            if !ok {
                return Err(format!("{key}: Input should be a valid URL"));
            }
            extra.insert(key.into(), Value::String(s));
        }
    }
    if let Some(contacts) = bounded_list(
        obj.get("contacts"),
        "contacts",
        MAX_CONTACTS,
        MAX_CONTACT_LEN,
    )? {
        extra.insert("contacts".into(), contacts.into());
    }
    // jwks は保存しない（private_key_jwt に対応しないので使い道が無い）

    let issued_at = now();
    let client_secret = (method != "none").then(token_hex);
    Ok(ClientRecord {
        client_id: uuid::Uuid::new_v4().to_string(),
        client_secret_expires_at: client_secret.as_ref().map(|_| 0),
        secret_sha256: client_secret.as_deref().map(sha256_hex),
        client_secret,
        client_id_issued_at: Some(issued_at),
        redirect_uris,
        token_endpoint_auth_method: method,
        grant_types,
        response_types,
        scope: bounded_string(obj.get("scope"), "scope", MAX_SCOPE_BYTES)?,
        client_name: client_name(obj.get("client_name"))?,
        application_type: Some(application_type),
        extra,
    })
}

/// CIMD を公開クライアントとして受ける。項目の上限は動的登録と同じ。
pub fn client_from_cimd(
    url: &str,
    document: &Value,
    allowlist: &RedirectAllowlist,
) -> Option<ClientRecord> {
    let obj = document.as_object()?;
    if obj.get("client_id").and_then(Value::as_str) != Some(url) {
        return None;
    }
    // ChatGPT は private_key_jwt を既定にしつつ token_endpoint_auth_methods_supported に
    // "none" も載せる。その場合は公開クライアント（PKCE 必須）として受ける。
    let supports_none = obj
        .get("token_endpoint_auth_methods_supported")
        .and_then(Value::as_array)
        .is_some_and(|m| m.iter().any(|v| v.as_str() == Some("none")));
    match obj.get("token_endpoint_auth_method") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s == "none" => {}
        Some(Value::String(_)) if supports_none => {}
        _ => return None,
    }
    let redirect_uris = match redirect_uris(obj.get("redirect_uris"), allowlist) {
        Ok(uris) => uris,
        Err(reason) => {
            tracing::info!(client_id = ?url, reason = ?reason, "cimd redirect_uris rejected");
            return None;
        }
    };
    let list = |key: &str| {
        bounded_list(obj.get(key), key, MAX_LIST_ITEMS, MAX_SHORT_VALUE_LEN)
            .ok()
            .map(|v| v.filter(|v| !v.is_empty()))
    };
    let grant_types = list("grant_types")?
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    let response_types = list("response_types")?.unwrap_or_else(|| vec!["code".into()]);
    if !grant_types.iter().any(|g| g == "authorization_code")
        || !response_types.iter().any(|r| r == "code")
    {
        return None;
    }
    // 文字列でない scope / client_name は今までどおり無視し、長すぎるものは文書ごと断る
    let text = |key: &str| obj.get(key).filter(|v| v.is_string());
    let scope = bounded_string(text("scope"), "scope", MAX_SCOPE_BYTES).ok()?;
    let client_name = client_name(text("client_name")).ok()?;
    Some(ClientRecord {
        client_id: url.to_string(),
        client_secret: None,
        secret_sha256: None,
        client_id_issued_at: None,
        client_secret_expires_at: None,
        redirect_uris,
        token_endpoint_auth_method: "none".into(),
        grant_types,
        response_types,
        scope,
        client_name,
        application_type: None,
        extra: Map::new(),
    })
}

// ---------------------------------------------------------------------------
// 保存物

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationParams {
    pub state: Option<String>,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub redirect_uri_provided_explicitly: bool,
    pub resource: Option<String>,
}

struct Pending {
    client_id: String,
    params: AuthorizationParams,
    expires_at: i64,
    browser_sha256: Option<String>,
}

#[derive(Clone)]
pub struct AuthorizationCode {
    pub scopes: Vec<String>,
    pub expires_at: i64,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub redirect_uri_provided_explicitly: bool,
    pub resource: String,
    pub subject: String,
    /// コードのハッシュ。このコードから発行したトークンの系列（grant_id）にする
    grant_id: String,
}

#[derive(Clone)]
pub struct IssuedToken {
    pub scopes: Vec<String>,
    pub expires_at: i64,
    pub resource: String,
    pub subject: String,
    /// 発行先の OAuth クライアント
    pub client_id: String,
}

#[derive(Serialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub refresh_token: String,
}

/// `oauth_tokens` の行（`TOKEN_COLUMNS` の順に選ぶ）。
fn issued_token(r: &Row) -> rusqlite::Result<IssuedToken> {
    Ok(IssuedToken {
        scopes: from_json(&r.get::<_, String>(0)?)?,
        expires_at: r.get(1)?,
        resource: r.get(2)?,
        subject: r.get(3)?,
        client_id: r.get(4)?,
    })
}

const TOKEN_COLUMNS: &str = "scopes, expires_at, resource, subject, client_id";

const INSERT_TOKEN: &str = "INSERT INTO oauth_tokens \
    (token_sha256, kind, client_id, subject, resource, scopes, issued_at, expires_at, access_sha256, grant_id, granted_at) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";

/// 認可 1 回分の系列。refresh で入れ替えても引き継ぐ。
struct Grant<'a> {
    id: &'a str,
    /// 絶対期限（`GRANT_MAX_LIFETIME`）の起点
    granted_at: i64,
}

/// `client_id` が `subject` 向けに、期限内で未使用のトークンを持っているか。
/// relay の登録の持ち主が今も使われているかを見るのに使う。
pub(crate) fn client_holds_live_token(
    c: &Connection,
    client_id: &str,
    subject: &str,
) -> rusqlite::Result<bool> {
    c.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM oauth_tokens WHERE client_id = ?1 AND subject = ?2 \
         AND used_at IS NULL AND expires_at >= ?3)",
    )?
    .query_row(params![client_id, subject, now()], |r| r.get(0))
}

// ---------------------------------------------------------------------------
// エラー

pub struct AuthorizeError {
    pub error: &'static str,
    pub description: String,
}

pub struct TokenError {
    pub error: &'static str,
    pub description: String,
}

impl TokenError {
    fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }
}

pub enum CallbackOutcome {
    Redirect(String),
    Text(u16, String),
}

// ---------------------------------------------------------------------------
// CIMD のキャッシュ

struct CimdEntry {
    expires_at: i64,
    last_used: u64,
    client: ClientRecord,
}

/// 件数に上限のある LRU。取り直せるのでメモリだけに置く。
#[derive(Default)]
struct CimdCache {
    entries: HashMap<String, CimdEntry>,
    clock: u64,
}

impl CimdCache {
    fn get(&mut self, client_id: &str, now: i64) -> Option<ClientRecord> {
        self.clock += 1;
        let clock = self.clock;
        let entry = self
            .entries
            .get_mut(client_id)
            .filter(|e| e.expires_at > now)?;
        entry.last_used = clock;
        Some(entry.client.clone())
    }

    fn insert(&mut self, client_id: String, client: ClientRecord, now: i64) {
        self.entries.remove(&client_id);
        self.purge(now);
        while self.entries.len() >= CIMD_CACHE_CAPACITY {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.clock += 1;
        self.entries.insert(
            client_id,
            CimdEntry {
                expires_at: now + CIMD_TTL,
                last_used: self.clock,
                client,
            },
        );
    }

    fn purge(&mut self, now: i64) {
        self.entries.retain(|_, e| e.expires_at > now);
    }
}

// ---------------------------------------------------------------------------
// 認可サーバ本体

pub struct OAuthServer {
    pub issuer: String,
    /// 唯一の保護リソース（`{issuer}/relay/v1`）。`resource` 省略時もここに束ねる。
    pub resource_url: String,
    /// 共有の参照。集合から外すと発行済みの bearer も次の照合で弾かれる。
    pub allowed_ids: Arc<RwLock<HashSet<String>>>,
    pub github: Arc<dyn GitHubLogin>,
    pub redirect_allowlist: RedirectAllowlist,
    /// CIMD を取りに行ってよいホスト。既定は redirect allowlist のループバック以外のホスト。
    cimd_hosts: HashSet<String>,
    fetcher: Arc<dyn ClientMetadataFetcher>,
    db: Db,
    cimd_cache: Mutex<CimdCache>,
    cimd_fetches: tokio::sync::Semaphore,
    /// 動的登録の受付数（分, 件数）
    registrations: Mutex<(i64, u32)>,
}

impl OAuthServer {
    pub fn new(
        issuer: &str,
        allowed_ids: Arc<RwLock<HashSet<String>>>,
        github: Arc<dyn GitHubLogin>,
        fetcher: Arc<dyn ClientMetadataFetcher>,
        redirect_allowlist: RedirectAllowlist,
        db: Db,
    ) -> Self {
        let issuer = issuer.trim_end_matches('/').to_string();
        let resource_url = format!("{issuer}{}", crate::relay::PREFIX);
        Self {
            issuer,
            resource_url,
            allowed_ids,
            github,
            cimd_hosts: redirect_allowlist.hosts(),
            redirect_allowlist,
            fetcher,
            db,
            cimd_cache: Mutex::default(),
            cimd_fetches: tokio::sync::Semaphore::new(CIMD_MAX_CONCURRENT_FETCHES),
            registrations: Mutex::default(),
        }
    }

    /// CIMD を取りに行ってよいホストを差し替える。
    pub fn with_cimd_hosts(mut self, hosts: HashSet<String>) -> Self {
        self.cimd_hosts = hosts;
        self
    }

    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource{}",
            self.issuer,
            crate::relay::PREFIX
        )
    }

    pub fn setup_url(&self) -> String {
        format!("{}{GITHUB_SETUP_PATH}", self.issuer)
    }

    fn cimd_cache(&self) -> std::sync::MutexGuard<'_, CimdCache> {
        self.cimd_cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 期限切れを消す。期限切れの refresh は対の access も消す。
    fn purge(&self, tx: &Connection, now: i64) -> rusqlite::Result<()> {
        self.cimd_cache().purge(now);
        tx.execute("DELETE FROM oauth_pending WHERE expires_at < ?1", [now])?;
        tx.execute("DELETE FROM oauth_codes WHERE expires_at < ?1", [now])?;
        tx.execute(
            "DELETE FROM oauth_tokens WHERE expires_at < ?1 OR token_sha256 IN \
             (SELECT access_sha256 FROM oauth_tokens WHERE kind = 'refresh' AND expires_at < ?1)",
            [now],
        )?;
        Ok(())
    }

    /// subject は GitHub の数値 id。login は改名で再利用されうるので照合に使わない。
    pub fn allows(&self, user_id: &str) -> bool {
        self.allowed_ids
            .read()
            .map(|ids| ids.contains(user_id))
            .unwrap_or(false)
    }

    pub fn setup_text(&self) -> String {
        format!(
            "GitHub OAuth App の client id と client secret が無い。\n\
             環境変数 GITHUB_CLIENT_ID と GITHUB_CLIENT_SECRET を置いて、プロセスを再起動する。\n\
             コールバック URL は {}\n",
            self.github.redirect_uri()
        )
    }

    pub fn metadata(&self) -> Value {
        serde_json::json!({
            "issuer": self.issuer,
            "authorization_endpoint": format!("{}{AUTHORIZATION_PATH}", self.issuer),
            "token_endpoint": format!("{}{TOKEN_PATH}", self.issuer),
            "registration_endpoint": format!("{}{REGISTRATION_PATH}", self.issuer),
            "revocation_endpoint": format!("{}{REVOCATION_PATH}", self.issuer),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            // Claude は none があり CIMD が true のとき、公開 URL を client_id にする。
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
            "code_challenge_methods_supported": ["S256"],
            "client_id_metadata_document_supported": true,
        })
    }

    pub fn protected_resource_metadata(&self) -> Value {
        serde_json::json!({
            "resource": self.resource_url,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
        })
    }

    /// ルート `/.well-known/oauth-protected-resource` 用の拡張一覧。
    pub fn protected_resources_index(&self) -> Value {
        serde_json::json!({
            "resources": [self.resource_url],
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
        })
    }

    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientRecord>, DbError> {
        if client_id.len() > MAX_URI_LEN {
            return Ok(None);
        }
        let now = now();
        let stored = self.db.read(|c| {
            c.query_row(
                "SELECT record, secret_sha256 FROM oauth_clients WHERE client_id = ?1",
                [client_id],
                |r| {
                    let mut client: ClientRecord = from_json(&r.get::<_, String>(0)?)?;
                    client.secret_sha256 = r.get(1)?;
                    Ok(client)
                },
            )
            .optional()
        })?;
        if stored.is_some() {
            return Ok(stored);
        }
        if !is_cimd_client_id(client_id) {
            return Ok(None);
        }
        let host = Url::parse(client_id)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
        if !host.is_some_and(|h| self.cimd_hosts.contains(&h)) {
            tracing::info!(client_id = ?client_id, "cimd host is not allowed");
            return Ok(None);
        }
        if let Some(client) = self.cimd_cache().get(client_id, now) {
            return Ok(Some(client));
        }
        // 同時に取りに行く数を絞る。空きを待つのは 1 回の取得のタイムアウトまで
        let permit =
            tokio::time::timeout(Duration::from_secs(5), self.cimd_fetches.acquire()).await;
        let Ok(Ok(_permit)) = permit else {
            tracing::warn!(client_id = ?client_id, "cimd fetch skipped: too many fetches in flight");
            return Ok(None);
        };
        // 待っている間に他の要求が取ってきていれば、それを使う
        if let Some(client) = self.cimd_cache().get(client_id, now) {
            return Ok(Some(client));
        }
        let document = match self.fetcher.fetch(client_id).await {
            Ok(doc) => doc,
            Err(_) => {
                tracing::info!(client_id = ?client_id, "cimd fetch failed");
                return Ok(None);
            }
        };
        let Some(client) = client_from_cimd(client_id, &document, &self.redirect_allowlist) else {
            tracing::info!(client_id = ?client_id, "cimd document rejected");
            return Ok(None);
        };
        self.cimd_cache()
            .insert(client_id.to_string(), client.clone(), now);
        Ok(Some(client))
    }

    /// 動的登録を 1 件受けてよいか（1 分ごとの固定窓で、全体で数える）。
    pub fn admit_registration(&self) -> bool {
        let minute = now() / 60;
        let mut window = self.registrations.lock().unwrap_or_else(|e| e.into_inner());
        if window.0 != minute {
            *window = (minute, 0);
        }
        if window.1 >= REGISTRATIONS_PER_MINUTE {
            return false;
        }
        window.1 += 1;
        true
    }

    /// 入れたら true。件数か合計バイト数が上限で、捨ててよいもの（期限内のトークンを持たないもの）が
    /// 無ければ入れずに false。
    pub fn register_client(&self, client: ClientRecord) -> Result<bool, DbError> {
        let record = to_json(&ClientRecord {
            client_secret: None,
            ..client.clone()
        })?;
        let now = now();
        let inserted = self.db.write(|tx| -> rusqlite::Result<bool> {
            loop {
                let (count, bytes): (i64, i64) = tx.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(length(CAST(record AS BLOB))), 0) FROM oauth_clients",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if (count as usize) < MAX_CLIENTS
                    && bytes as usize + record.len() <= MAX_CLIENT_RECORD_BYTES
                {
                    break;
                }
                // 使われているクライアントは、登録を大量に送られても追い出さない
                let victim: Option<String> = tx
                    .query_row(
                        "SELECT client_id FROM oauth_clients c WHERE NOT EXISTS \
                         (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.client_id \
                          AND t.used_at IS NULL AND t.expires_at >= ?1) \
                         ORDER BY registered_at, rowid LIMIT 1",
                        [now],
                        |r| r.get(0),
                    )
                    .optional()?;
                let Some(victim) = victim else {
                    return Ok(false);
                };
                tx.execute("DELETE FROM oauth_clients WHERE client_id = ?1", [&victim])?;
                tx.execute("DELETE FROM oauth_consents WHERE client_id = ?1", [&victim])?;
            }
            tx.execute(
                "INSERT INTO oauth_clients (client_id, secret_sha256, record, registered_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![client.client_id, client.secret_sha256, record, now],
            )?;
            Ok(true)
        })?;
        Ok(inserted)
    }

    fn normalize_resource_key(url: &str) -> String {
        normalize_url(url)
            .unwrap_or_else(|| url.to_string())
            .trim_end_matches('/')
            .to_ascii_lowercase()
    }

    /// RFC 8707: 要求された resource を relay に束ねる。省略時も relay。
    fn bound_resource(&self, requested: Option<&str>) -> Result<String, AuthorizeError> {
        match requested {
            Some(r)
                if Self::normalize_resource_key(r)
                    != Self::normalize_resource_key(&self.resource_url) =>
            {
                Err(AuthorizeError {
                    error: "invalid_target",
                    description: "resource does not match a configured MCP service".into(),
                })
            }
            _ => Ok(self.resource_url.clone()),
        }
    }

    /// 同意画面を出す前に、resource が relay を指しているかを見る。
    pub fn check_resource(&self, requested: Option<&str>) -> Result<(), AuthorizeError> {
        self.bound_resource(requested).map(|_| ())
    }

    /// (client_id, redirect_uri) が、今も許可されている GitHub ログインで承認済みか。
    pub fn has_consent(&self, client_id: &str, redirect_uri: &str) -> Result<bool, DbError> {
        let subjects: Vec<String> = self.db.read(|c| {
            c.prepare_cached(
                "SELECT subject FROM oauth_consents WHERE client_id = ?1 AND redirect_uri = ?2",
            )?
            .query_map(
                params![client_id, consent_redirect_key(redirect_uri)],
                |r| r.get(0),
            )?
            .collect()
        })?;
        Ok(subjects.iter().any(|s| self.allows(s)))
    }

    /// 同意の済んだ認可要求を置き、次にブラウザを送る URL（GitHub）を返す。
    /// `browser` は認可を始めたブラウザの Cookie の値。callback で同じ値が要る。
    pub fn authorize(
        &self,
        client: &ClientRecord,
        params: AuthorizationParams,
        browser: &str,
    ) -> Result<Result<String, AuthorizeError>, DbError> {
        if let Err(e) = self.bound_resource(params.resource.as_deref()) {
            return Ok(Err(e));
        }
        if !self.github.configured() {
            return Ok(Ok(self.setup_url()));
        }
        let state = token_urlsafe();
        let now = now();
        let params = to_json(&params)?;
        self.db.write(|tx| -> rusqlite::Result<()> {
            self.purge(tx, now)?;
            // 入れたあとも MAX_PENDING 件に収まるよう、古い順に捨てる
            tx.execute(
                "DELETE FROM oauth_pending WHERE state_sha256 IN (SELECT state_sha256 FROM oauth_pending \
                 ORDER BY expires_at, rowid LIMIT max(0, (SELECT COUNT(*) FROM oauth_pending) - ?1))",
                [MAX_PENDING as i64 - 1],
            )?;
            tx.execute(
                "INSERT INTO oauth_pending (state_sha256, client_id, params, expires_at, browser_sha256) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    sha256_hex(&state),
                    client.client_id,
                    params,
                    now + PENDING_TTL,
                    sha256_hex(browser),
                ],
            )?;
            Ok(())
        })?;
        Ok(Ok(self.github.authorization_url(&state)))
    }

    /// `browser` はこのリクエストの Cookie の値（無ければ None）。
    pub async fn complete_github_callback(
        &self,
        code: Option<&str>,
        state: Option<&str>,
        error: Option<&str>,
        browser: Option<&str>,
    ) -> Result<CallbackOutcome, DbError> {
        let pending = match state {
            Some(state) => self.db.write(|tx| {
                tx.query_row(
                    "DELETE FROM oauth_pending WHERE state_sha256 = ?1 \
                     RETURNING client_id, params, expires_at, browser_sha256",
                    [sha256_hex(state)],
                    |r| {
                        Ok(Pending {
                            client_id: r.get(0)?,
                            params: from_json(&r.get::<_, String>(1)?)?,
                            expires_at: r.get(2)?,
                            browser_sha256: r.get(3)?,
                        })
                    },
                )
                .optional()
            })?,
            None => None,
        };
        let Some(pending) = pending.filter(|p| p.expires_at >= now()) else {
            return Ok(CallbackOutcome::Text(
                400,
                "認可の手続きが見つからない。\n接続をやり直す。\n".into(),
            ));
        };
        // 認可を始めたブラウザでなければ断る（GitHub の URL だけを踏ませる経路を塞ぐ）
        let same_browser = match (&pending.browser_sha256, browser) {
            (Some(stored), Some(browser)) => {
                constant_time_eq(stored.as_bytes(), sha256_hex(browser).as_bytes())
            }
            _ => false,
        };
        if !same_browser {
            tracing::warn!(
                client_id = ?pending.client_id,
                "oauth callback from a browser that did not start the authorization"
            );
            return Ok(CallbackOutcome::Text(
                400,
                "この認可は、このブラウザで始めたものではない（Cookie が一致しない）。\n接続をやり直す。\n"
                    .into(),
            ));
        }
        let code = match (error, code) {
            (None, Some(code)) if !code.is_empty() => code,
            _ => {
                return Ok(CallbackOutcome::Text(
                    400,
                    "GitHub の認可が完了していない。\n接続をやり直す。\n".into(),
                ))
            }
        };
        let (user_id, login) = match self.github.login_for_code(code).await {
            Ok(found) => found,
            Err(_) => {
                return Ok(CallbackOutcome::Text(
                    502,
                    "GitHub からアカウントを取れなかった。\n接続をやり直す。\n".into(),
                ))
            }
        };
        if !self.allows(&user_id) {
            tracing::info!(login = ?login, id = %user_id, "github login denied");
            return Ok(CallbackOutcome::Text(
                403,
                format!(
                    "この GitHub アカウントは許可されていない。\nlogin: {login}\nid: {user_id}\n"
                ),
            ));
        }
        let resource = match self.bound_resource(pending.params.resource.as_deref()) {
            Ok(r) => r,
            Err(e) => return Ok(CallbackOutcome::Text(400, format!("{}\n", e.description))),
        };
        let issued = token_urlsafe();
        let now = now();
        let p = &pending.params;
        let scopes = to_json(&p.scopes)?;
        self.db.write(|tx| -> rusqlite::Result<()> {
            self.purge(tx, now)?;
            tx.execute(
                "INSERT INTO oauth_codes (code_sha256, client_id, subject, resource, scopes, \
                 code_challenge, redirect_uri, redirect_uri_provided_explicitly, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    sha256_hex(&issued),
                    pending.client_id,
                    user_id,
                    resource,
                    scopes,
                    p.code_challenge,
                    p.redirect_uri,
                    p.redirect_uri_provided_explicitly,
                    now + CODE_TTL,
                ],
            )?;
            // 許可されたログインで最後まで通ったので、この組を覚える（次回は同意画面を出さない）
            tx.execute(
                "INSERT INTO oauth_consents (client_id, redirect_uri, subject, approved_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (client_id, redirect_uri, subject) \
                 DO UPDATE SET approved_at = excluded.approved_at",
                params![
                    pending.client_id,
                    consent_redirect_key(&p.redirect_uri),
                    user_id,
                    now
                ],
            )?;
            tx.execute(
                "DELETE FROM oauth_consents WHERE rowid IN (SELECT rowid FROM oauth_consents \
                 ORDER BY approved_at, rowid LIMIT max(0, (SELECT COUNT(*) FROM oauth_consents) - ?1))",
                [MAX_CONSENTS as i64],
            )?;
            Ok(())
        })?;
        tracing::info!(login = ?login, id = %user_id, "github login allowed");
        Ok(CallbackOutcome::Redirect(construct_redirect_uri(
            &p.redirect_uri,
            &[
                ("code", Some(issued.as_str())),
                ("state", p.state.as_deref()),
            ],
        )))
    }

    /// クライアントが一致すれば取り出す（一度きり）。使用済みのコードがもう一度来たら、
    /// そのコードから発行したトークンを失効させる（RFC 6749 §4.1.2）。
    pub fn load_authorization_code(
        &self,
        client: &ClientRecord,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, DbError> {
        let code_sha256 = sha256_hex(code);
        let found = self.db.write(|tx| -> rusqlite::Result<_> {
            let found = tx
                .query_row(
                    "UPDATE oauth_codes SET used_at = ?3 \
                     WHERE code_sha256 = ?1 AND client_id = ?2 AND used_at IS NULL \
                     RETURNING scopes, expires_at, code_challenge, redirect_uri, \
                     redirect_uri_provided_explicitly, resource, subject",
                    params![code_sha256, client.client_id, now()],
                    |r| {
                        Ok(AuthorizationCode {
                            scopes: from_json(&r.get::<_, String>(0)?)?,
                            expires_at: r.get(1)?,
                            code_challenge: r.get(2)?,
                            redirect_uri: r.get(3)?,
                            redirect_uri_provided_explicitly: r.get(4)?,
                            resource: r.get(5)?,
                            subject: r.get(6)?,
                            grant_id: code_sha256.clone(),
                        })
                    },
                )
                .optional()?;
            if found.is_none() {
                let reused: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM oauth_codes WHERE code_sha256 = ?1 AND client_id = ?2)",
                    params![code_sha256, client.client_id],
                    |r| r.get(0),
                )?;
                if reused {
                    let revoked =
                        tx.execute("DELETE FROM oauth_tokens WHERE grant_id = ?1", [&code_sha256])?;
                    tracing::warn!(
                        client_id = ?client.client_id,
                        revoked,
                        "authorization code used twice; revoked the tokens issued from it"
                    );
                }
            }
            Ok(found)
        })?;
        Ok(found)
    }

    pub fn exchange_authorization_code(
        &self,
        client: &ClientRecord,
        code: &AuthorizationCode,
    ) -> Result<Result<OAuthToken, TokenError>, DbError> {
        if code.subject.is_empty() || !self.allows(&code.subject) {
            return Ok(Err(TokenError::new(
                "invalid_grant",
                "github login is not allowed",
            )));
        }
        let grant = Grant {
            id: &code.grant_id,
            granted_at: now(),
        };
        let token = self.db.write(|tx| {
            self.issue(
                tx,
                &client.client_id,
                code.scopes.clone(),
                &code.subject,
                &code.resource,
                &grant,
            )
        })?;
        Ok(Ok(token))
    }

    /// 未使用の refresh だけを返す。
    pub fn load_refresh_token(
        &self,
        client: &ClientRecord,
        token: &str,
    ) -> Result<Option<IssuedToken>, DbError> {
        let found = self.db.read(|c| {
            c.query_row(
                &format!(
                    "SELECT {TOKEN_COLUMNS} FROM oauth_tokens \
                     WHERE token_sha256 = ?1 AND kind = 'refresh' AND client_id = ?2 AND used_at IS NULL"
                ),
                params![sha256_hex(token), client.client_id],
                issued_token,
            )
            .optional()
        })?;
        Ok(found)
    }

    /// 使用済みの refresh がもう一度来たとき。入れ替えから `REFRESH_GRACE_SECS` を過ぎていれば漏れたものとみなし、
    /// 同じクライアントと subject のトークンを全部失効させて true を返す。猶予のうちは、同時に refresh した
    /// 要求の行き違いとみなして何もしない。
    pub fn revoke_on_refresh_reuse(
        &self,
        client: &ClientRecord,
        token: &str,
    ) -> Result<bool, DbError> {
        let now = now();
        let revoked = self.db.write(|tx| -> rusqlite::Result<bool> {
            let used: Option<(String, i64)> = tx
                .query_row(
                    "SELECT subject, used_at FROM oauth_tokens WHERE token_sha256 = ?1 \
                     AND kind = 'refresh' AND client_id = ?2 AND used_at IS NOT NULL",
                    params![sha256_hex(token), client.client_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((subject, used_at)) = used else {
                return Ok(false);
            };
            if used_at + REFRESH_GRACE_SECS > now {
                return Ok(false);
            }
            let revoked = tx.execute(
                "DELETE FROM oauth_tokens WHERE client_id = ?1 AND subject = ?2",
                params![client.client_id, subject],
            )?;
            tracing::warn!(
                client_id = ?client.client_id,
                subject = %subject,
                revoked,
                "used refresh token presented again; revoked every token of this client"
            );
            Ok(true)
        })?;
        Ok(revoked)
    }

    /// 古い refresh に使用済みの印を付けて新しい組を入れるまでを 1 つのトランザクションで行う。
    /// 対の access は消さず、残りを `REFRESH_GRACE_SECS` までに縮める。系列と絶対期限は引き継ぐ。
    pub fn exchange_refresh_token(
        &self,
        client: &ClientRecord,
        refresh_token: &str,
        scopes: Vec<String>,
    ) -> Result<Result<OAuthToken, TokenError>, DbError> {
        let now = now();
        let outcome = self.db.write(|tx| -> rusqlite::Result<_> {
            let current = tx
                .query_row(
                    &format!(
                        "UPDATE oauth_tokens SET used_at = ?3 \
                         WHERE token_sha256 = ?1 AND kind = 'refresh' AND client_id = ?2 AND used_at IS NULL \
                         RETURNING {TOKEN_COLUMNS}, access_sha256, grant_id, granted_at"
                    ),
                    params![sha256_hex(refresh_token), client.client_id, now],
                    |r| {
                        Ok((
                            issued_token(r)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, Option<String>>(6)?,
                            r.get::<_, Option<i64>>(7)?,
                        ))
                    },
                )
                .optional()?;
            let Some((current, old_access, grant_id, granted_at)) = current else {
                return Ok(Err(TokenError::new(
                    "invalid_grant",
                    "refresh token does not exist",
                )));
            };
            let grant_id = grant_id.unwrap_or_else(|| sha256_hex(refresh_token));
            // 許可から外れていたら、この系列ごと消したままにする
            if current.subject.is_empty() || !self.allows(&current.subject) {
                tx.execute("DELETE FROM oauth_tokens WHERE grant_id = ?1", [&grant_id])?;
                if let Some(old_access) = old_access {
                    tx.execute(
                        "DELETE FROM oauth_tokens WHERE token_sha256 = ?1 AND kind = 'access'",
                        [old_access],
                    )?;
                }
                return Ok(Err(TokenError::new(
                    "invalid_grant",
                    "github login is not allowed",
                )));
            }
            // 期限が来たら purge が消す
            if let Some(old_access) = old_access {
                tx.execute(
                    "UPDATE oauth_tokens SET expires_at = MIN(expires_at, ?2) \
                     WHERE token_sha256 = ?1 AND kind = 'access'",
                    params![old_access, now + REFRESH_GRACE_SECS],
                )?;
            }
            let grant = Grant {
                id: &grant_id,
                granted_at: granted_at.unwrap_or(now),
            };
            self.issue(
                tx,
                &client.client_id,
                scopes,
                &current.subject,
                &current.resource,
                &grant,
            )
            .map(Ok)
        })?;
        Ok(outcome)
    }

    /// RFC 7009: このクライアントに発行したトークンなら、その認可の系列ごと失効させる。
    /// 知らないトークン・他のクライアントのトークンは何もしない（どちらでも 200 を返すため、区別を返さない）。
    pub fn revoke(&self, client: &ClientRecord, token: &str) -> Result<(), DbError> {
        let hash = sha256_hex(token);
        self.db.write(|tx| -> rusqlite::Result<()> {
            let grant: Option<String> = tx
                .query_row(
                    "SELECT COALESCE(grant_id, token_sha256) FROM oauth_tokens \
                     WHERE token_sha256 = ?1 AND client_id = ?2",
                    params![hash, client.client_id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(grant) = grant {
                let revoked = tx.execute(
                    "DELETE FROM oauth_tokens WHERE grant_id = ?1 OR token_sha256 = ?1",
                    [&grant],
                )?;
                tracing::info!(client_id = ?client.client_id, revoked, "oauth tokens revoked");
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Bearer を照合する。期限・許可 id・resource（RFC 8707）を見る。
    /// `expected_resource_url` はこのリクエストの MCP パスに対応する絶対 URL。
    pub fn load_access_token(
        &self,
        token: &str,
        expected_resource_url: &str,
    ) -> Result<Option<IssuedToken>, DbError> {
        let found = self.db.read(|c| {
            c.query_row(
                &format!(
                    "SELECT {TOKEN_COLUMNS} FROM oauth_tokens \
                     WHERE token_sha256 = ?1 AND kind = 'access' AND expires_at >= ?2"
                ),
                params![sha256_hex(token), now()],
                issued_token,
            )
            .optional()
        })?;
        let Some(found) = found else {
            return Ok(None);
        };
        if found.subject.is_empty() || !self.allows(&found.subject) {
            return Ok(None);
        }
        let same_resource = Self::normalize_resource_key(&found.resource)
            == Self::normalize_resource_key(expected_resource_url);
        if !same_resource {
            tracing::warn!(
                expected = %expected_resource_url,
                token_resource = %found.resource,
                "bearer token resource does not match this MCP path"
            );
            return Ok(None);
        }
        Ok(Some(found))
    }

    /// access と refresh の組を入れる。どちらの期限も、系列の絶対期限を越えない。
    fn issue(
        &self,
        tx: &Connection,
        client_id: &str,
        scopes: Vec<String>,
        subject: &str,
        resource: &str,
        grant: &Grant,
    ) -> rusqlite::Result<OAuthToken> {
        let now = now();
        let access_token = token_urlsafe();
        let refresh_token = token_urlsafe();
        let access_sha256 = sha256_hex(&access_token);
        let scopes_json = to_json(&scopes)?;
        let limit = grant.granted_at + GRANT_MAX_LIFETIME;
        let access_expires_at = (now + ACCESS_TTL).min(limit);
        let refresh_expires_at = (now + REFRESH_TTL).min(limit);
        self.purge(tx, now)?;
        tx.execute(
            INSERT_TOKEN,
            params![
                access_sha256,
                "access",
                client_id,
                subject,
                resource,
                scopes_json,
                now,
                access_expires_at,
                None::<String>,
                grant.id,
                grant.granted_at,
            ],
        )?;
        tx.execute(
            INSERT_TOKEN,
            params![
                sha256_hex(&refresh_token),
                "refresh",
                client_id,
                subject,
                resource,
                scopes_json,
                now,
                refresh_expires_at,
                access_sha256,
                grant.id,
                grant.granted_at,
            ],
        )?;
        Ok(OAuthToken {
            access_token,
            token_type: "Bearer",
            expires_in: access_expires_at - now,
            scope: (!scopes.is_empty()).then(|| scopes.join(" ")),
            refresh_token,
        })
    }

    /// /token のクライアント認証（SDK の ClientAuthenticator 相当）。
    pub async fn authenticate_client(
        &self,
        form: &HashMap<String, String>,
        authorization: Option<&str>,
    ) -> Result<Result<ClientRecord, String>, DbError> {
        let Some(client_id) = form.get("client_id").filter(|s| !s.is_empty()) else {
            return Ok(Err("Missing client_id".into()));
        };
        Ok(match self.get_client(client_id).await? {
            Some(client) => {
                verify_client_secret(&client, client_id, form, authorization).map(|()| client)
            }
            None => Err("Invalid client_id".into()),
        })
    }
}

/// 受け取った client_secret をハッシュにして、保存したハッシュと定数時間で比べる。
fn verify_client_secret(
    client: &ClientRecord,
    client_id: &str,
    form: &HashMap<String, String>,
    authorization: Option<&str>,
) -> Result<(), String> {
    let request_secret: Option<String> = match client.token_endpoint_auth_method.as_str() {
        "client_secret_basic" => {
            let header = authorization.unwrap_or("");
            let Some(encoded) = header.strip_prefix("Basic ") else {
                return Err(
                    "Missing or invalid Basic authentication in Authorization header".into(),
                );
            };
            let decoded = STANDARD
                .decode(encoded.trim())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| "Invalid Basic authentication header".to_string())?;
            let Some((basic_id, secret)) = decoded.split_once(':') else {
                return Err("Invalid Basic authentication header".into());
            };
            let basic_id = percent_unquote(basic_id);
            let secret = percent_unquote(secret);
            if basic_id != *client_id {
                return Err("Client ID mismatch in Basic auth".into());
            }
            Some(secret)
        }
        "client_secret_post" => form.get("client_secret").cloned(),
        "none" => None,
        other => return Err(format!("Unsupported auth method: {other}")),
    };
    if client.token_endpoint_auth_method != "none" && client.secret_sha256.is_none() {
        return Err(
            "Client is registered for secret-based authentication but has no stored secret".into(),
        );
    }
    if let Some(stored) = &client.secret_sha256 {
        let Some(given) = request_secret.filter(|s| !s.is_empty()) else {
            return Err("Client secret is required".into());
        };
        if !constant_time_eq(stored.as_bytes(), sha256_hex(&given).as_bytes()) {
            return Err("Invalid client_secret".into());
        }
        if let Some(exp) = client.client_secret_expires_at {
            if exp != 0 && exp < now() {
                return Err("Client secret has expired".into());
            }
        }
    }
    Ok(())
}
