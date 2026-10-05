//! GitHub で本人を確認し、このプロセスが bearer を発行する。
//!
//! pascal の `~/Github/mcp-test/auth.py`（MCP Python SDK の OAuth サーバ）の移植。
//! - 動的クライアント登録（RFC 7591）と Client ID Metadata Document（CIMD）
//! - /authorize → GitHub ログイン → /github/callback → 認可コード → /token
//! - 許可は GitHub の数値 id（login は改名で再利用されうるので使わない）
//! - トークンはメモリだけ。プロセスを再起動すると消える（mcp-test と同じ）

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

pub const MCP_PATH: &str = "/mcp/v3";
pub const GITHUB_CALLBACK_PATH: &str = "/github/callback";
pub const GITHUB_SETUP_PATH: &str = "/github/setup";
pub const AUTHORIZATION_PATH: &str = "/authorize";
pub const TOKEN_PATH: &str = "/token";
pub const REGISTRATION_PATH: &str = "/register";

pub const ACCESS_TTL: i64 = 60 * 60;
pub const REFRESH_TTL: i64 = 14 * 24 * 60 * 60;
pub const CODE_TTL: i64 = 5 * 60;
pub const PENDING_TTL: i64 = 10 * 60;
pub const CIMD_TTL: i64 = 5 * 60;
/// 動的登録は誰でも叩ける。メモリを食い潰されないよう古いものから捨てる。
pub const MAX_CLIENTS: usize = 1000;
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
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
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
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for GitHubOAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // client_secret はログに出さない。
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
            .build()
            .expect("reqwest client");
        Self {
            client_id,
            client_secret,
            redirect_uri,
            http,
        }
    }
}

#[async_trait]
impl GitHubLogin for GitHubOAuth {
    fn configured(&self) -> bool {
        !self.client_id.is_empty() && !self.client_secret.is_empty()
    }

    fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    fn authorization_url(&self, state: &str) -> String {
        let mut url = Url::parse("https://github.com/login/oauth/authorize").expect("static url");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", "read:user")
            .append_pair("state", state)
            .append_pair("allow_signup", "false");
        url.to_string()
    }

    async fn login_for_code(&self, code: &str) -> Result<(String, String), GitHubLoginError> {
        let lookup = |e: reqwest::Error| {
            tracing::info!("github account lookup failed: {}", e.without_url());
            GitHubLoginError("lookup".into())
        };
        let token_response = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
            ])
            .send()
            .await
            .map_err(lookup)?;
        if token_response.status() != reqwest::StatusCode::OK {
            return Err(GitHubLoginError(token_response.status().to_string()));
        }
        let body: Value = token_response.json().await.map_err(lookup)?;
        let Some(access_token) = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            tracing::info!(
                "github token error {}",
                body.get("error").and_then(|v| v.as_str()).unwrap_or("-")
            );
            return Err(GitHubLoginError("token".into()));
        };
        let user_response = self
            .http
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(lookup)?;
        if user_response.status() != reqwest::StatusCode::OK {
            return Err(GitHubLoginError(user_response.status().to_string()));
        }
        let user: Value = user_response.json().await.map_err(lookup)?;
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
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64
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

async fn resolve_public_host(host: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let system = public_addrs(tokio::net::lookup_host((host, 443)).await?);
    if !system.is_empty() {
        return Ok(system);
    }
    let doh = resolve_via_doh(host).await?;
    if doh.is_empty() {
        anyhow::bail!("cimd host is not public");
    }
    Ok(doh)
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

#[derive(Clone, Serialize)]
pub struct ClientRecord {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
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
    pub fn validate_redirect_uri(&self, requested: Option<&str>) -> Result<String, String> {
        match requested {
            Some(raw) => {
                let normalized = normalize_url(raw)
                    .ok_or_else(|| format!("Redirect URI '{raw}' not registered for client"))?;
                if self
                    .redirect_uris
                    .iter()
                    .any(|u| *u == normalized || loopback_matches(u, &normalized))
                {
                    Ok(normalized)
                } else {
                    Err(format!("Redirect URI '{raw}' not registered for client"))
                }
            }
            None if self.redirect_uris.len() == 1 => Ok(self.redirect_uris[0].clone()),
            None => Err(
                "redirect_uri must be specified unless the client has exactly one registered URI"
                    .into(),
            ),
        }
    }
}

/// RFC 8252 §7.3: ループバックの redirect_uri はポートを問わず一致とみなす。
fn loopback_matches(registered: &str, requested: &str) -> bool {
    let (Ok(reg), Ok(mut req)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    let loopback = matches!(reg.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if reg.scheme() != "http" || !loopback || reg.port().is_some() {
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

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{field}: Input should be a valid string")),
    }
}

fn normalized_uris(list: Vec<String>, field: &str) -> Result<Vec<String>, String> {
    list.iter()
        .map(|u| normalize_url(u).ok_or_else(|| format!("{field}: Input should be a valid URL")))
        .collect()
}

/// RFC 7591 の登録要求を検証し、登録済みクライアントを作る（SDK の RegistrationHandler 相当）。
pub fn client_from_registration(body: &Value) -> Result<ClientRecord, String> {
    let Some(obj) = body.as_object() else {
        return Err("Input should be an object".into());
    };
    let redirect_uris = string_list(obj.get("redirect_uris"), "redirect_uris")?
        .ok_or_else(|| "redirect_uris: Field required".to_string())?;
    if redirect_uris.is_empty() {
        return Err("redirect_uris: List should have at least 1 item".into());
    }
    let redirect_uris = normalized_uris(redirect_uris, "redirect_uris")?;

    let method = optional_string(obj.get("token_endpoint_auth_method"), "token_endpoint_auth_method")?
        .unwrap_or_else(|| "client_secret_post".into());
    match method.as_str() {
        "none" | "client_secret_post" | "client_secret_basic" => {}
        "private_key_jwt" => {
            return Err("token_endpoint_auth_method 'private_key_jwt' is not supported".into())
        }
        other => return Err(format!("token_endpoint_auth_method: '{other}' is not supported")),
    }
    let grant_types = string_list(obj.get("grant_types"), "grant_types")?
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
    let response_types =
        string_list(obj.get("response_types"), "response_types")?.unwrap_or_else(|| vec!["code".into()]);
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
        if let Some(s) = optional_string(obj.get(key), key)? {
            extra.insert(key.into(), Value::String(s));
        }
    }
    for key in ["client_uri", "logo_uri", "tos_uri", "policy_uri", "jwks_uri"] {
        if let Some(s) = optional_string(obj.get(key), key)?.filter(|s| !s.is_empty()) {
            let ok = Url::parse(&s)
                .map(|u| u.scheme() == "http" || u.scheme() == "https")
                .unwrap_or(false);
            if !ok {
                return Err(format!("{key}: Input should be a valid URL"));
            }
            extra.insert(key.into(), Value::String(s));
        }
    }
    if let Some(contacts) = string_list(obj.get("contacts"), "contacts")? {
        extra.insert("contacts".into(), contacts.into());
    }
    if let Some(jwks) = obj.get("jwks").filter(|v| !v.is_null()) {
        extra.insert("jwks".into(), jwks.clone());
    }

    let issued_at = now();
    let client_secret = (method != "none").then(token_hex);
    Ok(ClientRecord {
        client_id: uuid::Uuid::new_v4().to_string(),
        client_secret_expires_at: client_secret.as_ref().map(|_| 0),
        client_secret,
        client_id_issued_at: Some(issued_at),
        redirect_uris,
        token_endpoint_auth_method: method,
        grant_types,
        response_types,
        scope: optional_string(obj.get("scope"), "scope")?,
        client_name: optional_string(obj.get("client_name"), "client_name")?,
        application_type: Some(application_type),
        extra,
    })
}

/// CIMD を公開クライアントとして受ける。
pub fn client_from_cimd(url: &str, document: &Value) -> Option<ClientRecord> {
    let obj = document.as_object()?;
    if obj.get("client_id").and_then(Value::as_str) != Some(url) {
        return None;
    }
    match obj.get("token_endpoint_auth_method") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s == "none" => {}
        _ => return None,
    }
    let redirect_uris = string_list(obj.get("redirect_uris"), "redirect_uris").ok()??;
    if redirect_uris.is_empty() {
        return None;
    }
    let redirect_uris = normalized_uris(redirect_uris, "redirect_uris").ok()?;
    let grant_types = string_list(obj.get("grant_types"), "grant_types")
        .ok()?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    let response_types = string_list(obj.get("response_types"), "response_types")
        .ok()?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["code".into()]);
    if !grant_types.iter().any(|g| g == "authorization_code")
        || !response_types.iter().any(|r| r == "code")
    {
        return None;
    }
    Some(ClientRecord {
        client_id: url.to_string(),
        client_secret: None,
        client_id_issued_at: None,
        client_secret_expires_at: None,
        redirect_uris,
        token_endpoint_auth_method: "none".into(),
        grant_types,
        response_types,
        scope: obj.get("scope").and_then(Value::as_str).map(str::to_string),
        client_name: obj.get("client_name").and_then(Value::as_str).map(str::to_string),
        application_type: None,
        extra: Map::new(),
    })
}

// ---------------------------------------------------------------------------
// 保存物

#[derive(Clone)]
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
}

#[derive(Clone)]
pub struct AuthorizationCode {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub expires_at: i64,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub redirect_uri_provided_explicitly: bool,
    pub resource: String,
    pub subject: String,
}

#[derive(Clone)]
pub struct IssuedToken {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub expires_at: i64,
    pub resource: String,
    pub subject: String,
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

#[derive(Default)]
struct Store {
    clients: HashMap<String, ClientRecord>,
    client_order: VecDeque<String>,
    cimd_cache: HashMap<String, (i64, ClientRecord)>,
    pending: HashMap<String, Pending>,
    codes: HashMap<String, AuthorizationCode>,
    access_tokens: HashMap<String, IssuedToken>,
    refresh_tokens: HashMap<String, IssuedToken>,
    refresh_to_access: HashMap<String, String>,
}

impl Store {
    fn purge(&mut self, now: i64) {
        self.cimd_cache.retain(|_, (exp, _)| *exp > now);
        self.pending.retain(|_, p| p.expires_at >= now);
        self.codes.retain(|_, c| c.expires_at >= now);
        self.access_tokens.retain(|_, t| t.expires_at >= now);
        let expired: Vec<String> = self
            .refresh_tokens
            .iter()
            .filter(|(_, t)| t.expires_at < now)
            .map(|(k, _)| k.clone())
            .collect();
        for token in expired {
            self.refresh_tokens.remove(&token);
            if let Some(access) = self.refresh_to_access.remove(&token) {
                self.access_tokens.remove(&access);
            }
        }
    }
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
// 認可サーバ本体

pub struct OAuthServer {
    pub issuer: String,
    pub resource_url: String,
    /// 共有の参照。集合から外すと発行済みの bearer も次の照合で弾かれる。
    pub allowed_ids: Arc<RwLock<HashSet<String>>>,
    pub github: Arc<dyn GitHubLogin>,
    fetcher: Arc<dyn ClientMetadataFetcher>,
    store: Mutex<Store>,
}

impl OAuthServer {
    pub fn new(
        issuer: &str,
        allowed_ids: Arc<RwLock<HashSet<String>>>,
        github: Arc<dyn GitHubLogin>,
        fetcher: Arc<dyn ClientMetadataFetcher>,
    ) -> Self {
        let issuer = issuer.trim_end_matches('/').to_string();
        Self {
            resource_url: format!("{issuer}{MCP_PATH}"),
            issuer,
            allowed_ids,
            github,
            fetcher,
            store: Mutex::new(Store::default()),
        }
    }

    pub fn resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource{MCP_PATH}", self.issuer)
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
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
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            // Claude は none があり CIMD が true のとき、公開 URL を client_id にする。
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
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

    pub async fn get_client(&self, client_id: &str) -> Option<ClientRecord> {
        let now = now();
        {
            let store = self.store();
            if let Some(found) = store.clients.get(client_id) {
                return Some(found.clone());
            }
            if !is_cimd_client_id(client_id) {
                return None;
            }
            if let Some((exp, client)) = store.cimd_cache.get(client_id) {
                if *exp > now {
                    return Some(client.clone());
                }
            }
        }
        let document = match self.fetcher.fetch(client_id).await {
            Ok(doc) => doc,
            Err(_) => {
                tracing::info!("cimd fetch failed {client_id}");
                return None;
            }
        };
        let Some(client) = client_from_cimd(client_id, &document) else {
            tracing::info!("cimd document rejected {client_id}");
            return None;
        };
        self.store()
            .cimd_cache
            .insert(client_id.to_string(), (now + CIMD_TTL, client.clone()));
        Some(client)
    }

    pub fn register_client(&self, client: ClientRecord) {
        let mut store = self.store();
        while store.clients.len() >= MAX_CLIENTS {
            let Some(oldest) = store.client_order.pop_front() else {
                break;
            };
            store.clients.remove(&oldest);
        }
        store.client_order.push_back(client.client_id.clone());
        store.clients.insert(client.client_id.clone(), client);
    }

    fn bound_resource(&self, requested: Option<&str>) -> Result<String, AuthorizeError> {
        match requested {
            None => Ok(self.resource_url.clone()),
            Some(r) if r.trim_end_matches('/') == self.resource_url.trim_end_matches('/') => {
                Ok(self.resource_url.clone())
            }
            Some(_) => Err(AuthorizeError {
                error: "invalid_target",
                description: "resource does not match this MCP server".into(),
            }),
        }
    }

    /// 次にブラウザを送る URL を返す。
    pub fn authorize(
        &self,
        client: &ClientRecord,
        params: AuthorizationParams,
    ) -> Result<String, AuthorizeError> {
        self.bound_resource(params.resource.as_deref())?;
        if !self.github.configured() {
            return Ok(format!("{}{GITHUB_SETUP_PATH}", self.issuer));
        }
        let state = token_urlsafe();
        let now = now();
        let mut store = self.store();
        store.purge(now);
        store.pending.insert(
            state.clone(),
            Pending {
                client_id: client.client_id.clone(),
                params,
                expires_at: now + PENDING_TTL,
            },
        );
        drop(store);
        Ok(self.github.authorization_url(&state))
    }

    pub async fn complete_github_callback(
        &self,
        code: Option<&str>,
        state: Option<&str>,
        error: Option<&str>,
    ) -> CallbackOutcome {
        let pending = state.and_then(|s| self.store().pending.remove(s));
        let Some(pending) = pending.filter(|p| p.expires_at >= now()) else {
            return CallbackOutcome::Text(400, "認可の手続きが見つからない。\n接続をやり直す。\n".into());
        };
        let code = match (error, code) {
            (None, Some(code)) if !code.is_empty() => code,
            _ => {
                return CallbackOutcome::Text(
                    400,
                    "GitHub の認可が完了していない。\n接続をやり直す。\n".into(),
                )
            }
        };
        let (user_id, login) = match self.github.login_for_code(code).await {
            Ok(found) => found,
            Err(_) => {
                return CallbackOutcome::Text(
                    502,
                    "GitHub からアカウントを取れなかった。\n接続をやり直す。\n".into(),
                )
            }
        };
        if !self.allows(&user_id) {
            tracing::info!("github login denied {login} (id {user_id})");
            return CallbackOutcome::Text(
                403,
                format!("この GitHub アカウントは許可されていない。\nlogin: {login}\nid: {user_id}\n"),
            );
        }
        let resource = match self.bound_resource(pending.params.resource.as_deref()) {
            Ok(r) => r,
            Err(e) => return CallbackOutcome::Text(400, format!("{}\n", e.description)),
        };
        let issued = token_urlsafe();
        let now = now();
        {
            let mut store = self.store();
            store.purge(now);
            store.codes.insert(
                issued.clone(),
                AuthorizationCode {
                    client_id: pending.client_id.clone(),
                    scopes: pending.params.scopes.clone(),
                    expires_at: now + CODE_TTL,
                    code_challenge: pending.params.code_challenge.clone(),
                    redirect_uri: pending.params.redirect_uri.clone(),
                    redirect_uri_provided_explicitly: pending.params.redirect_uri_provided_explicitly,
                    resource,
                    subject: user_id.clone(),
                },
            );
        }
        tracing::info!("github login allowed {login} (id {user_id})");
        CallbackOutcome::Redirect(construct_redirect_uri(
            &pending.params.redirect_uri,
            &[
                ("code", Some(issued.as_str())),
                ("state", pending.params.state.as_deref()),
            ],
        ))
    }

    /// クライアントが一致すれば取り出す（一度きり）。
    pub fn load_authorization_code(&self, client: &ClientRecord, code: &str) -> Option<AuthorizationCode> {
        let mut store = self.store();
        match store.codes.get(code) {
            Some(found) if found.client_id == client.client_id => store.codes.remove(code),
            _ => None,
        }
    }

    pub fn exchange_authorization_code(
        &self,
        client: &ClientRecord,
        code: &AuthorizationCode,
    ) -> Result<OAuthToken, TokenError> {
        if code.subject.is_empty() || !self.allows(&code.subject) {
            return Err(TokenError::new("invalid_grant", "github login is not allowed"));
        }
        Ok(self.issue(&client.client_id, code.scopes.clone(), &code.subject, &code.resource))
    }

    pub fn load_refresh_token(&self, client: &ClientRecord, token: &str) -> Option<IssuedToken> {
        self.store()
            .refresh_tokens
            .get(token)
            .filter(|t| t.client_id == client.client_id)
            .cloned()
    }

    pub fn exchange_refresh_token(
        &self,
        client: &ClientRecord,
        refresh_token: &str,
        scopes: Vec<String>,
    ) -> Result<OAuthToken, TokenError> {
        let current = {
            let mut store = self.store();
            let current = store.refresh_tokens.remove(refresh_token);
            let Some(current) = current.filter(|c| c.client_id == client.client_id) else {
                return Err(TokenError::new("invalid_grant", "refresh token does not exist"));
            };
            if let Some(old_access) = store.refresh_to_access.remove(refresh_token) {
                store.access_tokens.remove(&old_access);
            }
            current
        };
        if current.subject.is_empty() || !self.allows(&current.subject) {
            return Err(TokenError::new("invalid_grant", "github login is not allowed"));
        }
        Ok(self.issue(&client.client_id, scopes, &current.subject, &current.resource))
    }

    /// Bearer を照合する。期限・許可 id・resource（RFC 8707）を見る。
    pub fn load_access_token(&self, token: &str) -> Option<IssuedToken> {
        let found = {
            let mut store = self.store();
            let found = store.access_tokens.get(token)?.clone();
            if found.expires_at < now() {
                store.access_tokens.remove(token);
                return None;
            }
            found
        };
        if found.subject.is_empty() || !self.allows(&found.subject) {
            return None;
        }
        let same_resource = normalize_url(&found.resource)
            .map(|r| r.trim_end_matches('/').to_ascii_lowercase())
            == normalize_url(&self.resource_url).map(|r| r.trim_end_matches('/').to_ascii_lowercase());
        if !same_resource {
            tracing::warn!("bearer token resource is not this server");
            return None;
        }
        Some(found)
    }

    fn issue(&self, client_id: &str, scopes: Vec<String>, subject: &str, resource: &str) -> OAuthToken {
        let now = now();
        let access_token = token_urlsafe();
        let refresh_token = token_urlsafe();
        let base = IssuedToken {
            client_id: client_id.to_string(),
            scopes: scopes.clone(),
            expires_at: now + ACCESS_TTL,
            resource: resource.to_string(),
            subject: subject.to_string(),
        };
        let refresh = IssuedToken {
            expires_at: now + REFRESH_TTL,
            ..base.clone()
        };
        {
            let mut store = self.store();
            store.purge(now);
            store.access_tokens.insert(access_token.clone(), base);
            store.refresh_tokens.insert(refresh_token.clone(), refresh);
            store
                .refresh_to_access
                .insert(refresh_token.clone(), access_token.clone());
        }
        OAuthToken {
            access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TTL,
            scope: (!scopes.is_empty()).then(|| scopes.join(" ")),
            refresh_token,
        }
    }

    /// /token のクライアント認証（SDK の ClientAuthenticator 相当）。
    pub async fn authenticate_client(
        &self,
        form: &HashMap<String, String>,
        authorization: Option<&str>,
    ) -> Result<ClientRecord, String> {
        let Some(client_id) = form.get("client_id").filter(|s| !s.is_empty()) else {
            return Err("Missing client_id".into());
        };
        let Some(client) = self.get_client(client_id).await else {
            return Err("Invalid client_id".into());
        };
        let request_secret: Option<String> = match client.token_endpoint_auth_method.as_str() {
            "client_secret_basic" => {
                let header = authorization.unwrap_or("");
                let Some(encoded) = header.strip_prefix("Basic ") else {
                    return Err("Missing or invalid Basic authentication in Authorization header".into());
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
        if client.token_endpoint_auth_method != "none" && client.client_secret.is_none() {
            return Err("Client is registered for secret-based authentication but has no stored secret".into());
        }
        if let Some(stored) = &client.client_secret {
            let Some(given) = request_secret.filter(|s| !s.is_empty()) else {
                return Err("Client secret is required".into());
            };
            if !constant_time_eq(stored.as_bytes(), given.as_bytes()) {
                return Err("Invalid client_secret".into());
            }
            if let Some(exp) = client.client_secret_expires_at {
                if exp != 0 && exp < now() {
                    return Err("Client secret has expired".into());
                }
            }
        }
        Ok(client)
    }
}
