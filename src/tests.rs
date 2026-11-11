//! mcp-test の tests/test_auth.py を移植した結合テスト。

use crate::auth::{
    is_cimd_client_id, pkce_s256, token_urlsafe, ClientMetadataFetcher, GitHubLogin,
    GitHubLoginError, OAuthServer, RedirectAllowlist, REFRESH_GRACE_SECS,
};
use crate::db::Db;
use crate::relay::Relay;
use crate::routes::{router, AppState};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;
use url::Url;

pub(crate) const PUBLIC_URL: &str = "https://demo.trycloudflare.com";
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";
/// 保護リソースは relay だけ。
const TEST_MCP_PATH: &str = crate::relay::PREFIX;

pub(crate) fn resource() -> String {
    format!("{PUBLIC_URL}{TEST_MCP_PATH}")
}

struct FakeGitHub {
    /// code -> (GitHub の数値 id, login)
    logins: HashMap<String, (String, String)>,
    configured: bool,
}

#[async_trait]
impl GitHubLogin for FakeGitHub {
    fn configured(&self) -> bool {
        self.configured
    }
    fn redirect_uri(&self) -> &str {
        "https://demo.trycloudflare.com/oauth/callback/github"
    }
    fn authorization_url(&self, state: &str) -> String {
        format!("https://github.com/login/oauth/authorize?state={state}")
    }
    async fn login_for_code(&self, code: &str) -> Result<(String, String), GitHubLoginError> {
        self.logins
            .get(code)
            .cloned()
            .ok_or_else(|| GitHubLoginError(code.into()))
    }
}

struct FakeFetcher(Option<Value>);

#[async_trait]
impl ClientMetadataFetcher for FakeFetcher {
    async fn fetch(&self, _url: &str) -> anyhow::Result<Value> {
        self.0.clone().ok_or_else(|| anyhow::anyhow!("no document"))
    }
}

pub(crate) struct Harness {
    pub(crate) app: Router,
    pub(crate) allowed: Arc<RwLock<HashSet<String>>>,
    oauth: Arc<OAuthServer>,
    pub(crate) relay: Arc<Relay>,
}

fn harness_with(logins: &[(&str, &str, &str)], configured: bool, cimd: Option<Value>) -> Harness {
    gateway(
        logins,
        configured,
        cimd,
        Relay::new(
            PUBLIC_URL,
            crate::relay::DEFAULT_MAX_TOTAL_STORAGE_BYTES,
            Db::open_in_memory(),
        ),
    )
}

/// OAuth（フェイクの GitHub ログイン）+ relay のゲートウェイ全体。
pub(crate) fn gateway(
    logins: &[(&str, &str, &str)],
    configured: bool,
    cimd: Option<Value>,
    relay: Relay,
) -> Harness {
    let allowed = Arc::new(RwLock::new(HashSet::from(["2429307".to_string()])));
    let github = FakeGitHub {
        logins: logins
            .iter()
            .map(|(code, id, login)| (code.to_string(), (id.to_string(), login.to_string())))
            .collect(),
        configured,
    };
    // 本番と同じく OAuth と relay で 1 つの DB を共有する
    let oauth = Arc::new(OAuthServer::new(
        PUBLIC_URL,
        allowed.clone(),
        Arc::new(github),
        Arc::new(FakeFetcher(cimd)),
        RedirectAllowlist::default(),
        relay.store.db().clone(),
    ));
    let relay = Arc::new(relay);
    let app = router(AppState {
        oauth: oauth.clone(),
        relay: relay.clone(),
    });
    Harness {
        app,
        allowed,
        oauth,
        relay,
    }
}

fn harness() -> Harness {
    harness_with(&[("ok", "2429307", "legokichi")], true, None)
}

pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: axum::http::HeaderMap,
    pub(crate) body: String,
}

impl Reply {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn location(&self) -> Url {
        Url::parse(self.headers[header::LOCATION].to_str().unwrap()).unwrap()
    }
}

fn query(url: &Url) -> HashMap<String, String> {
    url.query_pairs().into_owned().collect()
}

pub(crate) async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 64 << 20)
        .await
        .unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

pub(crate) async fn get(app: &Router, path: &str) -> Reply {
    send(app, Request::get(path).body(Body::empty()).unwrap()).await
}

fn encode(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

async fn post_form(app: &Router, path: &str, pairs: &[(&str, &str)]) -> Reply {
    send(
        app,
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(encode(pairs)))
            .unwrap(),
    )
    .await
}

async fn mcp(app: &Router, token: Option<&str>, id: i64) -> Reply {
    let mut req = Request::post(TEST_MCP_PATH).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" }).to_string();
    send(app, req.body(Body::from(body)).unwrap()).await
}

async fn register(app: &Router, method: &str) -> Value {
    let body = json!({
        "redirect_uris": [REDIRECT_URI],
        "token_endpoint_auth_method": method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "test",
    });
    let reply = send(
        app,
        Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    reply.json()
}

async fn register_client(app: &Router) -> String {
    register(app, "none").await["client_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn pkce() -> (String, String) {
    let verifier = token_urlsafe();
    let challenge = pkce_s256(&verifier);
    (verifier, challenge)
}

fn authorize_path(client_id: &str, challenge: &str, resource: Option<&str>) -> String {
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", "client-state"),
    ];
    if let Some(r) = resource {
        pairs.push(("resource", r));
    }
    format!("/authorize?{}", encode(&pairs))
}

/// `Set-Cookie` の `name=value`。
fn set_cookie(reply: &Reply) -> Option<String> {
    reply
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or_default().to_string())
        .next()
}

fn html_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// 同意画面の hidden の値（出てくる順）。
fn hidden_fields(html: &str) -> Vec<(String, String)> {
    const START: &str = "<input type=\"hidden\" name=\"";
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(START) {
        rest = &rest[i + START.len()..];
        let end = rest.find('"').unwrap();
        let name = html_unescape(&rest[..end]);
        rest = &rest[end..];
        rest = &rest[rest.find("value=\"").unwrap() + "value=\"".len()..];
        let end = rest.find('"').unwrap();
        out.push((name, html_unescape(&rest[..end])));
        rest = &rest[end..];
    }
    out
}

fn assert_consent_page(page: &Reply) {
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("このアプリに接続を許可するか"),
        "{}",
        page.body
    );
    assert!(page.headers.get(header::LOCATION).is_none());
}

/// 同意画面で `action`（approve / deny）を押す。`cookie` が None なら画面の Set-Cookie を使う。
async fn submit_consent(app: &Router, page: &Reply, action: &str, cookie: Option<&str>) -> Reply {
    let cookie = cookie
        .map(str::to_string)
        .or_else(|| set_cookie(page))
        .unwrap_or_default();
    let mut pairs = hidden_fields(&page.body);
    pairs.push(("consent_action".into(), action.into()));
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    send(
        app,
        Request::post("/authorize/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie)
            .body(Body::from(encode(&pairs)))
            .unwrap(),
    )
    .await
}

/// GitHub へ送られた認可。callback には同じブラウザ（Cookie）で戻る。
pub(crate) struct Started {
    state: String,
    cookie: String,
}

/// `/authorize` から GitHub へ送られるところまで。同意画面が出たら許可する。
async fn start(app: &Router, path: &str) -> Started {
    let first = get(app, path).await;
    let reply = if first.status == StatusCode::OK {
        assert_consent_page(&first);
        submit_consent(app, &first, "approve", None).await
    } else {
        first
    };
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);
    let location = reply.location();
    assert!(
        location
            .as_str()
            .starts_with("https://github.com/login/oauth/authorize"),
        "{location}"
    );
    Started {
        state: query(&location)["state"].clone(),
        cookie: set_cookie(&reply).expect("the browser cookie"),
    }
}

/// GitHub から `/oauth/callback/github` へ戻る。`login` はフェイク GitHub のコード。
async fn callback(app: &Router, started: &Started, login: &str) -> Reply {
    send(
        app,
        Request::get(format!(
            "/oauth/callback/github?{}",
            encode(&[("code", login), ("state", &started.state)])
        ))
        .header(header::COOKIE, &started.cookie)
        .body(Body::empty())
        .unwrap(),
    )
    .await
}

async fn github_state(app: &Router, client_id: &str, challenge: &str, resource: &str) -> Started {
    start(app, &authorize_path(client_id, challenge, Some(resource))).await
}

async fn authorization_code(app: &Router, client_id: &str, challenge: &str) -> String {
    authorization_code_for(app, client_id, challenge, "ok", &resource()).await
}

/// `login` はフェイク GitHub のコード（= どのアカウントでログインするか）。
async fn authorization_code_for(
    app: &Router,
    client_id: &str,
    challenge: &str,
    login: &str,
    resource: &str,
) -> String {
    let started = github_state(app, client_id, challenge, resource).await;
    let finished = callback(app, &started, login).await;
    assert_eq!(finished.status, StatusCode::FOUND, "{}", finished.body);
    let location = finished.location();
    assert!(location.as_str().starts_with(REDIRECT_URI));
    let q = query(&location);
    assert_eq!(q["state"], "client-state");
    q["code"].clone()
}

async fn issue_token(app: &Router) -> (String, String, String) {
    issue_token_for(app, "ok", &resource()).await
}

/// フェイク GitHub の `login` で `resource` 向けのトークンを取る（クライアント登録から）。
pub(crate) async fn issue_token_for(
    app: &Router,
    login: &str,
    resource: &str,
) -> (String, String, String) {
    let client_id = register_client(app).await;
    let (verifier, challenge) = pkce();
    let code = authorization_code_for(app, &client_id, &challenge, login, resource).await;
    let token = post_form(
        app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", &verifier),
            ("resource", resource),
        ],
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    let body = token.json();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(token.headers[header::CACHE_CONTROL], "no-store");
    (
        body["access_token"].as_str().unwrap().into(),
        body["refresh_token"].as_str().unwrap().into(),
        client_id,
    )
}

#[test]
fn cimd_client_id_rejects_local_and_root_urls() {
    assert!(is_cimd_client_id("https://client.example/oauth.json"));
    assert!(!is_cimd_client_id("https://127.0.0.1/oauth.json"));
    assert!(!is_cimd_client_id("https://localhost/oauth.json"));
    assert!(!is_cimd_client_id("https://client.example/"));
    assert!(!is_cimd_client_id("http://client.example/oauth.json"));
    assert!(!is_cimd_client_id("https://client.example/oauth.json#frag"));
    assert!(!is_cimd_client_id("https://user@client.example/oauth.json"));
}

#[test]
fn private_addresses_are_not_global() {
    use crate::auth::is_global_ip;
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "::ffff:10.0.0.1",
        "::127.0.0.1",
        "::a9fe:a9fe",
        "2002:7f00:1::1",
        "2002:a00:1::",
        "64:ff9b::a00:1",
        "0.0.0.0",
        "::",
    ] {
        assert!(!is_global_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "1.1.1.1",
        "140.82.112.3",
        "2606:4700::1111",
        "::ffff:1.1.1.1",
        "2002:101:101::1",
    ] {
        assert!(is_global_ip(ip.parse().unwrap()), "{ip}");
    }
}

#[tokio::test]
async fn metadata_advertises_public_clients_and_mcp_requires_a_bearer() {
    let h = harness();
    let metadata = get(&h.app, "/.well-known/oauth-authorization-server").await;
    assert_eq!(metadata.status, StatusCode::OK);
    let body = metadata.json();
    assert_eq!(body["issuer"], PUBLIC_URL);
    assert_eq!(
        body["authorization_endpoint"],
        format!("{PUBLIC_URL}/authorize")
    );
    assert_eq!(body["token_endpoint"], format!("{PUBLIC_URL}/token"));
    assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
    assert!(body["grant_types_supported"]
        .as_array()
        .unwrap()
        .contains(&json!("authorization_code")));
    assert!(body["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .contains(&json!("none")));
    assert_eq!(body["client_id_metadata_document_supported"], true);
    assert_eq!(
        body["registration_endpoint"],
        format!("{PUBLIC_URL}/register")
    );

    let prm = get(
        &h.app,
        &format!("/.well-known/oauth-protected-resource{TEST_MCP_PATH}"),
    )
    .await;
    assert_eq!(prm.status, StatusCode::OK);
    assert_eq!(prm.json()["resource"], resource());
    assert_eq!(prm.json()["authorization_servers"], json!([PUBLIC_URL]));

    let denied = mcp(&h.app, None, 1).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    let www = denied.headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        www.contains(&format!(
            "/.well-known/oauth-protected-resource{TEST_MCP_PATH}"
        )),
        "{www}"
    );
    assert!(www.starts_with("Bearer error=\"invalid_token\""));

    let bogus = mcp(&h.app, Some("not-a-token"), 1).await;
    assert_eq!(bogus.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn allowed_github_login_can_call_tools_and_refresh() {
    let h = harness();
    let (access, refresh, client_id) = issue_token(&h.app).await;
    let listed = mcp(&h.app, Some(&access), 2).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.json()["result"]["tools"][0]["name"], "send_message");

    let refreshed = post_form(
        &h.app,
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.body);
    let new_access = refreshed.json()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        mcp(&h.app, Some(&new_access), 3).await.status,
        StatusCode::OK
    );
    assert_eq!(mcp(&h.app, Some(&access), 4).await.status, StatusCode::OK);

    let reused = post_form(
        &h.app,
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(reused.status, StatusCode::BAD_REQUEST);
    assert_eq!(reused.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn other_github_login_gets_no_code() {
    let h = harness_with(&[("ok", "1", "someoneelse")], true, None);
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let started = github_state(&h.app, &client_id, &challenge, &resource()).await;
    let denied = callback(&h.app, &started, "ok").await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert!(denied
        .body
        .contains("この GitHub アカウントは許可されていない。"));
    assert!(denied.body.contains("login: someoneelse"));
    assert!(denied.body.contains("id: 1"));
    let replay = callback(&h.app, &started, "ok").await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reused_login_with_another_id_gets_no_code() {
    // legokichi が改名され、別人が同じ login を取った場合。id が違うので弾く。
    let h = harness_with(&[("ok", "99999999", "legokichi")], true, None);
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let started = github_state(&h.app, &client_id, &challenge, &resource()).await;
    let denied = callback(&h.app, &started, "ok").await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert!(denied.body.contains("id: 99999999"));
}

#[tokio::test]
async fn removing_a_login_rejects_an_existing_bearer() {
    let h = harness();
    let (access, _refresh, _client_id) = issue_token(&h.app).await;
    h.allowed.write().unwrap().clear();
    assert_eq!(
        mcp(&h.app, Some(&access), 1).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn cimd_client_id_is_fetched_and_a_mismatch_is_rejected() {
    let url = "https://claude.ai/oauth/test-client.json";
    let h = harness_with(
        &[("ok", "2429307", "legokichi")],
        true,
        Some(
            json!({ "client_id": url, "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none" }),
        ),
    );
    let (_verifier, challenge) = pkce();
    start(&h.app, &authorize_path(url, &challenge, Some(&resource()))).await;

    let h = harness_with(
        &[],
        true,
        Some(
            json!({ "client_id": "https://claude.ai/oauth/other.json", "redirect_uris": [REDIRECT_URI] }),
        ),
    );
    let rejected = get(&h.app, &authorize_path(url, &challenge, None)).await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_github_app_explains_the_callback() {
    let h = harness_with(&[], false, None);
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let started = get(&h.app, &authorize_path(&client_id, &challenge, None)).await;
    assert_eq!(started.status, StatusCode::FOUND);
    assert_eq!(
        started.location().as_str(),
        format!("{PUBLIC_URL}/oauth/setup/github")
    );
    let page = get(&h.app, "/oauth/setup/github").await;
    assert_eq!(page.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(page.body.contains("GITHUB_CLIENT_ID"));
    assert!(page.body.contains("/oauth/callback/github"));
}

#[tokio::test]
async fn authorization_code_cannot_be_reused_and_needs_the_verifier() {
    let h = harness();
    let client_id = register_client(&h.app).await;
    let (verifier, challenge) = pkce();

    // 誤った verifier はコードを消費して弾く
    let code = authorization_code(&h.app, &client_id, &challenge).await;
    let wrong = post_form(
        &h.app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", "wrong"),
        ],
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.json()["error"], "invalid_grant");

    let code = authorization_code(&h.app, &client_id, &challenge).await;
    let payload = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let first = post_form(&h.app, "/token", &payload).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let second = post_form(&h.app, "/token", &payload).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert_eq!(second.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn wrong_resource_is_redirected_back_with_invalid_target() {
    let h = harness();
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    // 撤去した stdio サービスのパスも、もう保護リソースではない
    for wrong in [
        "https://evil.example/mcp".to_string(),
        format!("{PUBLIC_URL}/default/v1"),
        format!("{PUBLIC_URL}/adb/v1"),
    ] {
        let started = get(
            &h.app,
            &authorize_path(&client_id, &challenge, Some(&wrong)),
        )
        .await;
        assert_eq!(started.status, StatusCode::FOUND, "{wrong}");
        let location = started.location();
        assert!(location.as_str().starts_with(REDIRECT_URI), "{wrong}");
        let q = query(&location);
        assert_eq!(q["error"], "invalid_target", "{wrong}");
        assert_eq!(q["state"], "client-state", "{wrong}");
    }
}

#[tokio::test]
async fn unknown_client_and_unregistered_redirect_get_a_json_error() {
    let h = harness();
    let (_verifier, challenge) = pkce();
    let unknown = get(&h.app, &authorize_path("nope", &challenge, None)).await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown.json()["error"], "invalid_request");

    let client_id = register_client(&h.app).await;
    let path = format!(
        "/authorize?{}",
        encode(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "https://evil.example/cb"),
            ("code_challenge", &challenge),
        ])
    );
    let bad_redirect = get(&h.app, &path).await;
    assert_eq!(bad_redirect.status, StatusCode::BAD_REQUEST);
    assert!(bad_redirect.headers.get(header::LOCATION).is_none());
}

#[tokio::test]
async fn confidential_client_must_send_its_secret() {
    let h = harness();
    let registered = register(&h.app, "client_secret_post").await;
    let client_id = registered["client_id"].as_str().unwrap().to_string();
    let secret = registered["client_secret"].as_str().unwrap().to_string();
    assert_eq!(registered["client_secret_expires_at"], 0);

    let (verifier, challenge) = pkce();
    let code = authorization_code(&h.app, &client_id, &challenge).await;
    let base = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let missing = post_form(&h.app, "/token", &base).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.json()["error"], "invalid_client");

    let mut with_secret = base.to_vec();
    with_secret.push(("client_secret", secret.as_str()));
    let ok = post_form(&h.app, "/token", &with_secret).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
}

#[tokio::test]
async fn registration_rejects_bad_metadata() {
    let h = harness();
    for body in [
        json!({}),
        json!({ "redirect_uris": [] }),
        json!({ "redirect_uris": [REDIRECT_URI], "grant_types": ["refresh_token"] }),
        json!({ "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "private_key_jwt" }),
    ] {
        let reply = send(
            &h.app,
            Request::post("/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.json()["error"], "invalid_client_metadata");
    }
}

#[tokio::test]
async fn loopback_redirect_accepts_any_port_for_cimd_clients() {
    // Claude Code の CIMD は http://localhost/callback を載せ、実際はポート付きで来る。
    let url = "https://claude.ai/oauth/claude-code-client-metadata";
    let h = harness_with(
        &[("ok", "2429307", "legokichi")],
        true,
        Some(json!({
            "client_id": url,
            "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none",
        })),
    );
    let (verifier, challenge) = pkce();
    let redirect = "http://localhost:53682/callback";
    let path = format!(
        "/authorize?{}",
        encode(&[
            ("response_type", "code"),
            ("client_id", url),
            ("redirect_uri", redirect),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", "st"),
        ])
    );
    let started = start(&h.app, &path).await;
    let finished = callback(&h.app, &started, "ok").await;
    assert_eq!(finished.status, StatusCode::FOUND, "{}", finished.body);
    assert!(finished.location().as_str().starts_with(redirect));
    let code = query(&finished.location())["code"].clone();
    let token = post_form(
        &h.app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect),
            ("client_id", url),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);

    // ループバック以外はポート違いを許さない
    let other = format!(
        "/authorize?{}",
        encode(&[
            ("response_type", "code"),
            ("client_id", url),
            ("redirect_uri", "http://evil.example:8080/callback"),
            ("code_challenge", &challenge),
        ])
    );
    assert_eq!(get(&h.app, &other).await.status, StatusCode::BAD_REQUEST);
}

#[test]
fn github_oauth_uses_river_style_callback_and_keeps_state() {
    use crate::auth::{GitHubOAuth, REDIRECT_PATH};
    let redirect = format!("https://mcp.duxca.com{REDIRECT_PATH}");
    let github = GitHubOAuth::new("cid".into(), "dummy-secret".into(), redirect.clone());
    assert!(github.configured());
    assert_eq!(
        github.redirect_uri(),
        "https://mcp.duxca.com/oauth/callback/github"
    );
    let url = Url::parse(&github.authorization_url("pending-state")).unwrap();
    assert_eq!(url.origin().ascii_serialization(), "https://github.com");
    assert_eq!(url.path(), "/login/oauth/authorize");
    let q = query(&url);
    assert_eq!(q["client_id"], "cid");
    assert_eq!(q["redirect_uri"], redirect);
    assert_eq!(q["state"], "pending-state");
    assert_eq!(q["scope"], "read:user");
    assert_eq!(q["response_type"], "code");
    assert!(!url.as_str().contains("dummy-secret"));
    assert!(!format!("{github:?}").contains("dummy-secret"));
}

#[tokio::test]
async fn root_is_an_empty_404() {
    let h = harness();
    let r = get(&h.app, "/").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body.is_empty());
}

#[tokio::test]
async fn health_is_an_empty_404() {
    let h = harness();
    let r = get(&h.app, "/health").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body.is_empty());
}

#[tokio::test]
async fn relay_is_a_built_in_resource_and_leaves_the_gateway_alone() {
    let h = harness();
    let relay_resource = format!("{PUBLIC_URL}/relay/v1");

    let r = get(&h.app, "/relay/v1/health").await;
    assert_eq!(
        (r.status, r.json()),
        (StatusCode::OK, json!({ "status": "ok" }))
    );
    for path in ["/", "/health"] {
        let r = get(&h.app, path).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
        assert!(r.body.is_empty(), "{path}");
    }

    // relay も既存 MCP と同じ形の 401 を返す（resource_metadata だけが relay を指す）
    let r = mcp(&h.app, None, 1).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = send(
        &h.app,
        Request::post("/relay/v1")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.json(),
        json!({ "error": "invalid_token", "error_description": "Authentication required" })
    );
    assert_eq!(
        r.headers[header::WWW_AUTHENTICATE],
        format!(
            "Bearer error=\"invalid_token\", error_description=\"Authentication required\", resource_metadata=\"{PUBLIC_URL}/.well-known/oauth-protected-resource/relay/v1\""
        )
    );

    let prm = get(&h.app, "/.well-known/oauth-protected-resource/relay/v1").await;
    assert_eq!(prm.status, StatusCode::OK);
    assert_eq!(prm.json()["resource"], relay_resource);
    let index = get(&h.app, "/.well-known/oauth-protected-resource")
        .await
        .json();
    assert_eq!(index["resources"], json!([relay_resource.clone()]));

    // resource を省略しても relay に束ねる
    let client_id = register_client(&h.app).await;
    let (verifier, challenge) = pkce();
    let started = start(&h.app, &authorize_path(&client_id, &challenge, None)).await;
    let finished = callback(&h.app, &started, "ok").await;
    let code = query(&finished.location())["code"].clone();
    let token = post_form(
        &h.app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    let access = token.json()["access_token"].as_str().unwrap().to_string();
    assert_eq!(mcp(&h.app, Some(&access), 1).await.status, StatusCode::OK);

    // stdio サービスのパスはもう無い
    for path in ["/adb/v1", "/default/v1"] {
        let r = send(
            &h.app,
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
        assert!(r.body.is_empty(), "{path}");
        let prm = get(
            &h.app,
            &format!("/.well-known/oauth-protected-resource{path}"),
        )
        .await;
        assert_eq!(prm.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[test]
fn cimd_private_key_jwt_is_accepted_only_when_none_is_also_supported() {
    use crate::auth::client_from_cimd;
    let url = "https://chatgpt.com/oauth/abc/client.json";
    let chatgpt = json!({
        "client_id": url,
        "redirect_uris": ["https://chatgpt.com/connector/oauth/abc"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    });
    let allowlist = RedirectAllowlist::default();
    let client = client_from_cimd(url, &chatgpt, &allowlist).expect("chatgpt cimd accepted");
    assert_eq!(client.token_endpoint_auth_method, "none");
    assert!(client.client_secret.is_none());

    let jwt_only = json!({
        "client_id": url,
        "redirect_uris": ["https://chatgpt.com/connector/oauth/abc"],
        "token_endpoint_auth_method": "private_key_jwt",
    });
    assert!(client_from_cimd(url, &jwt_only, &allowlist).is_none());
}

#[test]
fn default_redirect_allowlist() {
    let allowlist = RedirectAllowlist::default();
    for ok in [
        "https://chatgpt.com/connector/oauth/abc123",
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "https://agent.meta.ai/api/hatch/oauth/callback",
        "https://www.cursor.com/agents/mcp/oauth/callback",
        "https://grok.com/",
        "https://grok.com/oauth/callback",
        "http://localhost/callback",
        "http://localhost:53682/callback",
        "http://127.0.0.1:9/cb",
        "http://[::1]:8080/",
    ] {
        assert!(allowlist.allows(ok), "{ok}");
    }
    for bad in [
        "https://evil.example/cb",
        "https://chatgpt.com/connector/oauth/",
        "https://chatgpt.com/connector/oauth/a/b",
        "https://chatgpt.com/other",
        "https://claude.ai/api/mcp/auth_callback/x",
        "https://claude.ai/api/mcp/../../evil",
        "https://claude.ai:8443/api/mcp/auth_callback",
        "http://claude.ai/api/mcp/auth_callback",
        "https://agent.meta.ai/api/hatch/oauth/callback/extra",
        "https://agent.meta.ai/api/hatch/oauth/callback/",
        "https://agent.meta.ai.evil.example/api/hatch/oauth/callback",
        "https://meta.ai/api/hatch/oauth/callback",
        "https://www.cursor.com/agents/mcp/oauth/callback/",
        "https://www.cursor.com/agents/mcp/oauth/callback/extra",
        "https://www.cursor.com/agents/mcp/oauth/other",
        "https://www.cursor.com/agents/mcp/oauth/",
        "https://cursor.com/agents/mcp/oauth/callback",
        "https://www.cursor.com.evil.example/agents/mcp/oauth/callback",
        "http://www.cursor.com/agents/mcp/oauth/callback",
        "https://grok.com.evil.example/",
        "https://sub.grok.com/",
        "http://grok.com/",
        "https://localhost/callback",
        "http://10.0.0.1/callback",
        // fragment / userinfo
        "https://claude.ai/api/mcp/auth_callback#x",
        "https://claude.ai/api/mcp/auth_callback#",
        "https://user@claude.ai/api/mcp/auth_callback",
        "https://user:pw@grok.com/",
        "http://user@localhost/callback",
        "not a url",
    ] {
        assert!(!allowlist.allows(bad), "{bad}");
    }
}

async fn register_redirects(app: &Router, redirect_uris: &[&str]) -> Reply {
    let body = json!({ "redirect_uris": redirect_uris, "token_endpoint_auth_method": "none" });
    send(
        app,
        Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

fn authorize_with_redirect(client_id: &str, challenge: &str, redirect: Option<&str>) -> String {
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", "st"),
    ];
    if let Some(r) = redirect {
        pairs.push(("redirect_uri", r));
    }
    format!("/authorize?{}", encode(&pairs))
}

fn assert_json_error_without_redirect(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert!(reply.headers.get(header::LOCATION).is_none());
    assert_eq!(reply.json()["error"], "invalid_request");
}

#[tokio::test]
async fn registration_rejects_redirect_uris_outside_the_allowlist() {
    let h = harness();
    for uris in [
        vec!["https://evil.example/cb"],
        vec![
            "https://claude.ai/api/mcp/auth_callback",
            "https://evil.example/cb",
        ],
        vec!["https://claude.ai/api/mcp/auth_callback#frag"],
        vec!["https://user@claude.ai/api/mcp/auth_callback"],
        vec!["https://chatgpt.com/connector/oauth/a/b"],
    ] {
        let reply = register_redirects(&h.app, &uris).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{uris:?}");
        assert_eq!(reply.json()["error"], "invalid_client_metadata");
        assert!(
            reply.json()["error_description"]
                .as_str()
                .unwrap()
                .contains("not allowed"),
            "{}",
            reply.body
        );
    }
}

#[tokio::test]
async fn registration_accepts_chatgpt_and_authorize_starts_github_login() {
    let h = harness();
    let redirect = "https://chatgpt.com/connector/oauth/abc123";
    let reply = register_redirects(&h.app, &[redirect]).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let client_id = reply.json()["client_id"].as_str().unwrap().to_string();
    let (_verifier, challenge) = pkce();
    start(
        &h.app,
        &authorize_with_redirect(&client_id, &challenge, Some(redirect)),
    )
    .await;
}

#[tokio::test]
async fn registration_accepts_loopback_on_any_port() {
    let h = harness();
    let reply = register_redirects(
        &h.app,
        &["http://localhost/callback", "http://[::1]/callback"],
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let client_id = reply.json()["client_id"].as_str().unwrap().to_string();
    let (_verifier, challenge) = pkce();
    for redirect in [
        "http://localhost:53682/callback",
        "http://[::1]:8080/callback",
    ] {
        start(
            &h.app,
            &authorize_with_redirect(&client_id, &challenge, Some(redirect)),
        )
        .await;
    }
}

#[tokio::test]
async fn cimd_with_redirect_uris_outside_the_allowlist_is_rejected() {
    let url = "https://claude.ai/oauth/test-client.json";
    let (_verifier, challenge) = pkce();
    for redirect_uris in [
        json!(["https://evil.example/cb"]),
        // 1 つでも allowlist 外があれば文書ごと拒否する
        json!([
            "https://claude.ai/api/mcp/auth_callback",
            "https://evil.example/cb"
        ]),
    ] {
        let h = harness_with(
            &[("ok", "2429307", "legokichi")],
            true,
            Some(json!({
                "client_id": url,
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
            })),
        );
        for redirect in [
            Some("https://evil.example/cb"),
            Some("https://claude.ai/api/mcp/auth_callback"),
            None,
        ] {
            let reply = get(&h.app, &authorize_with_redirect(url, &challenge, redirect)).await;
            assert_json_error_without_redirect(&reply);
        }
    }
}

#[tokio::test]
async fn authorize_rejects_a_stored_redirect_outside_the_allowlist_without_redirecting() {
    // 登録時の検査をすり抜けたクライアントでも、/authorize は戻し先へ送らない。
    let h = harness();
    let permissive = RedirectAllowlist::parse(["https://evil.example/"]).unwrap();
    let client = crate::auth::client_from_registration(
        &json!({ "redirect_uris": ["https://evil.example/cb"], "token_endpoint_auth_method": "none" }),
        &permissive,
    )
    .unwrap();
    let client_id = client.client_id.clone();
    h.oauth.register_client(client).unwrap();
    let (_verifier, challenge) = pkce();
    for redirect in [Some("https://evil.example/cb"), None] {
        let reply = get(
            &h.app,
            &authorize_with_redirect(&client_id, &challenge, redirect),
        )
        .await;
        assert_json_error_without_redirect(&reply);
        assert!(
            reply.json()["error_description"]
                .as_str()
                .unwrap()
                .contains("not allowed"),
            "{}",
            reply.body
        );
    }
}

// ---------------------------------------------------------------------------
// 永続化（SQLite）

fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn file_harness(path: &crate::db::TempPath) -> Harness {
    let db = Db::open(&path.0, None).unwrap();
    gateway(
        &[("ok", "2429307", "legokichi")],
        true,
        None,
        Relay::new(
            PUBLIC_URL,
            crate::relay::DEFAULT_MAX_TOTAL_STORAGE_BYTES,
            db,
        ),
    )
}

/// relay のツールを呼び、structuredContent を返す。
async fn tool(app: &Router, token: &str, name: &str, arguments: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": arguments } });
    let reply = send(
        app,
        Request::post(TEST_MCP_PATH)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let result = reply.json()["result"].clone();
    assert!(result.get("isError").is_none(), "{result}");
    result["structuredContent"].clone()
}

async fn refresh_with(app: &Router, refresh: &str, client_id: &str) -> Reply {
    post_form(
        app,
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
        ],
    )
    .await
}

#[tokio::test]
async fn state_survives_a_restart_and_secrets_are_stored_hashed() {
    use base64::Engine;
    let path = crate::db::TempPath::new("restart");
    let data = b"\x89PNG not really, but bytes that must come back";
    let file = json!({ "filename": "a.png", "content_type": "image/png",
        "content_base64": base64::engine::general_purpose::STANDARD.encode(data) });
    let webhook_secret = "whsec-plaintext-on-purpose-U4";

    let h = file_harness(&path);
    let (access, refresh, client_id) = issue_token(&h.app).await;
    let sent = tool(
        &h.app,
        &access,
        "send_message",
        json!({ "agent": "muse", "to": "grok", "text": "survive", "attachments": [file] }),
    )
    .await;
    let first_id: u64 = sent["message"]["id"].as_str().unwrap().parse().unwrap();
    let attachment_id = sent["message"]["attachments"][0]["id"].clone();
    // 既読も残る
    tool(
        &h.app,
        &access,
        "send_message",
        json!({ "agent": "grok", "to": "muse", "text": "read me" }),
    )
    .await;
    tool(
        &h.app,
        &access,
        "check_messages",
        json!({ "agent": "muse", "mark_read": true }),
    )
    .await;
    tool(
        &h.app,
        &access,
        "register_agent",
        json!({ "agent": "grok", "description": "Wakes up on webhooks; handles builds.",
        "webhook_url": "https://hook.example/wake", "webhook_secret": webhook_secret }),
    )
    .await;
    // 平文が残ってはいけない値: client_secret、使っていない認可コード、GitHub へ渡した state
    let confidential = register(&h.app, "client_secret_post").await;
    let client_secret = confidential["client_secret"].as_str().unwrap().to_string();
    let (_, challenge) = pkce();
    let code = authorization_code(&h.app, &client_id, &challenge).await;
    let state = github_state(&h.app, &client_id, &challenge, &resource())
        .await
        .state;
    drop(h);

    let h = file_harness(&path);
    // 再認可なしで同じトークンが通り、メッセージ・添付・既読・登録が残っている
    let inbox = tool(
        &h.app,
        &access,
        "check_messages",
        json!({ "agent": "grok", "unread_only": false }),
    )
    .await;
    assert_eq!(inbox["messages"][0]["text"], "survive");
    assert_eq!(inbox["messages"][0]["id"], first_id.to_string());
    let att = tool(
        &h.app,
        &access,
        "get_attachment",
        json!({ "attachment_id": attachment_id }),
    )
    .await;
    assert_eq!(att["sha256"], sha256_hex_bytes(data));
    let muse = tool(
        &h.app,
        &access,
        "check_messages",
        json!({ "agent": "muse", "unread_only": false }),
    )
    .await;
    assert_eq!(muse["messages"][0]["read"], true);
    assert_eq!(
        tool(&h.app, &access, "list_agents", json!({})).await["agents"],
        json!([{ "name": "grok", "webhook": true, "description": "Wakes up on webhooks; handles builds." }])
    );
    // id は戻らない
    let next = tool(
        &h.app,
        &access,
        "send_message",
        json!({ "agent": "muse", "to": "carol", "text": "after" }),
    )
    .await;
    let next_id: u64 = next["message"]["id"].as_str().unwrap().parse().unwrap();
    assert!(next_id > first_id + 1, "{next_id} <= {first_id} + 1");
    // refresh も使え、古い refresh は二度と使えない
    let refreshed = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.body);
    let replay = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(replay.json()["error"], "invalid_grant");
    assert_eq!(mcp(&h.app, Some(&access), 9).await.status, StatusCode::OK);
    let new_refresh = refreshed.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    drop(h);

    let bytes = path.bytes();
    let contains = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
    for secret in [
        &access,
        &refresh,
        &new_refresh,
        &client_secret,
        &code,
        &state,
    ] {
        assert!(!contains(secret), "plaintext {secret} found in the DB");
    }
    for stored in [&new_refresh, &client_secret, &code, &state] {
        assert!(
            contains(&sha256_hex(stored)),
            "hash of {stored} not found in the DB"
        );
    }
    // U4: webhook の秘密は送るときに要るので平文で置く
    assert!(contains(webhook_secret));
}

fn sha256_hex_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn refresh_rotation_is_one_transaction() {
    let h = harness();
    let (access, refresh, client_id) = issue_token(&h.app).await;
    let db = h.relay.store.db().clone();
    // 新しい組を入れるところで失敗させる。古い refresh を消したことも巻き戻る
    db.read(|c| {
        c.execute_batch(
            "CREATE TEMP TRIGGER fail_issue BEFORE INSERT ON oauth_tokens \
             BEGIN SELECT RAISE(ABORT, 'injected'); END",
        )
    })
    .unwrap();
    let failed = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(
        failed.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        failed.body
    );
    assert_eq!(failed.json()["error"], "temporarily_unavailable");
    assert_eq!(mcp(&h.app, Some(&access), 1).await.status, StatusCode::OK);
    db.read(|c| c.execute_batch("DROP TRIGGER fail_issue"))
        .unwrap();

    let rotated = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let new_access = rotated.json()["access_token"].as_str().unwrap().to_string();
    let new_refresh = rotated.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(mcp(&h.app, Some(&access), 2).await.status, StatusCode::OK);
    assert_eq!(
        mcp(&h.app, Some(&new_access), 3).await.status,
        StatusCode::OK
    );
    let replay = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(
        (replay.status, replay.json()["error"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalid_grant"))
    );
    assert_eq!(
        refresh_with(&h.app, &new_refresh, &client_id).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rotated_access_keeps_working_only_for_the_grace() {
    let h = harness();
    let (access, refresh, client_id) = issue_token(&h.app).await;
    let db = h.relay.store.db().clone();
    let expires_at = |token: &str| -> i64 {
        db.read(|c| {
            c.query_row(
                "SELECT expires_at FROM oauth_tokens WHERE token_sha256 = ?1",
                [sha256_hex(token)],
                |r| r.get(0),
            )
        })
        .unwrap()
    };
    let set_expires_at = |token: &str, at: i64| {
        db.read(|c| {
            c.execute(
                "UPDATE oauth_tokens SET expires_at = ?1 WHERE token_sha256 = ?2",
                rusqlite::params![at, sha256_hex(token)],
            )
        })
        .unwrap();
    };

    let rotated = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let new_access = rotated.json()["access_token"].as_str().unwrap().to_string();
    let new_refresh = rotated.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // 古い access は猶予のあいだ通り、残りは REFRESH_GRACE_SECS までに縮む
    assert_eq!(mcp(&h.app, Some(&access), 1).await.status, StatusCode::OK);
    let now = crate::auth::now();
    let capped = expires_at(&access);
    assert!(
        capped > now && capped <= now + REFRESH_GRACE_SECS,
        "{capped} {now}"
    );
    assert_eq!(
        mcp(&h.app, Some(&new_access), 2).await.status,
        StatusCode::OK
    );
    let replay = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(
        (replay.status, replay.json()["error"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalid_grant"))
    );

    // 猶予が切れたら 401。新しい組には響かない
    set_expires_at(&access, crate::auth::now() - 1);
    assert_eq!(
        mcp(&h.app, Some(&access), 3).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        mcp(&h.app, Some(&new_access), 4).await.status,
        StatusCode::OK
    );

    // 猶予より先に切れる access は延ばさない
    let sooner = crate::auth::now() + 10;
    set_expires_at(&new_access, sooner);
    assert_eq!(
        refresh_with(&h.app, &new_refresh, &client_id).await.status,
        StatusCode::OK
    );
    assert_eq!(expires_at(&new_access), sooner);
}

/// DB の失敗を 401 や invalid_grant にすると、クライアントは再認可へ進んでしまう。
#[tokio::test]
async fn storage_failures_are_503_not_401_or_invalid_grant() {
    let h = harness();
    let (access, refresh, client_id) = issue_token(&h.app).await;
    let db = h.relay.store.db().clone();
    db.read(|c| c.execute_batch("ALTER TABLE relay_messages RENAME TO relay_messages_gone"))
        .unwrap();
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "check_messages", "arguments": { "agent": "muse" } } });
    let reply = send(
        &h.app,
        Request::post(TEST_MCP_PATH)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {access}"))
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        reply.json()["result"]["content"][0]["text"],
        "Error: the relay's storage failed; try again later"
    );

    db.read(|c| c.execute_batch("ALTER TABLE oauth_tokens RENAME TO oauth_tokens_gone"))
        .unwrap();
    let bearer = mcp(&h.app, Some(&access), 2).await;
    assert_eq!(
        bearer.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        bearer.body
    );
    assert!(bearer.headers.get(header::WWW_AUTHENTICATE).is_none());
    let token = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(
        token.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        token.body
    );
    assert_eq!(token.json()["error"], "temporarily_unavailable");
}

#[tokio::test]
async fn client_registrations_are_capped_by_evicting_the_oldest() {
    let h = harness();
    let none = json!({ "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none" });
    let mut ids = Vec::new();
    for _ in 0..=crate::auth::MAX_CLIENTS {
        let client =
            crate::auth::client_from_registration(&none, &RedirectAllowlist::default()).unwrap();
        ids.push(client.client_id.clone());
        h.oauth.register_client(client).unwrap();
    }
    assert!(h.oauth.get_client(&ids[0]).await.unwrap().is_none());
    assert!(h.oauth.get_client(&ids[1]).await.unwrap().is_some());
    assert!(h
        .oauth
        .get_client(ids.last().unwrap())
        .await
        .unwrap()
        .is_some());
    let count: i64 = h
        .relay
        .store
        .db()
        .read(|c| c.query_row("SELECT COUNT(*) FROM oauth_clients", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(count as usize, crate::auth::MAX_CLIENTS);
}

// ---------------------------------------------------------------------------
// セキュリティレビュー（2026-11-11）

async fn register_json(app: &Router, body: &Value) -> Reply {
    send(
        app,
        Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

fn count(h: &Harness, sql: &str) -> i64 {
    h.relay
        .store
        .db()
        .read(|c| c.query_row(sql, [], |r| r.get(0)))
        .unwrap()
}

fn exec(h: &Harness, sql: &str, params: impl rusqlite::Params) {
    h.relay.store.db().read(|c| c.execute(sql, params)).unwrap();
}

/// H-1: 初めての (client_id, redirect_uri) は同意画面を出し、許可されたログインまで済んだら次から省く。
#[tokio::test]
async fn consent_is_asked_once_per_client_and_redirect() {
    let h = harness();
    let registered = register_json(
        &h.app,
        &json!({ "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none",
                 "client_name": "<b>Claude</b> & \"co\"" }),
    )
    .await;
    let client_id = registered.json()["client_id"].as_str().unwrap().to_string();
    let (_verifier, challenge) = pkce();
    let path = authorize_path(&client_id, &challenge, Some(&resource()));

    let page = get(&h.app, &path).await;
    assert_consent_page(&page);
    assert_eq!(page.headers[header::X_FRAME_OPTIONS], "DENY");
    let csp = page.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    // 自己申告の名前はエスケープし、client_id と戻り先のオリジンも見せる
    assert!(page
        .body
        .contains("&lt;b&gt;Claude&lt;/b&gt; &amp; &quot;co&quot;"));
    assert!(!page.body.contains("<b>Claude</b>"));
    assert!(page.body.contains("自己申告"));
    assert!(page.body.contains(&client_id));
    assert!(page.body.contains("http://127.0.0.1:9"));
    let cookie = page.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("__Host-mcp_authz="), "{cookie}");
    for attr in ["Path=/", "HttpOnly", "SameSite=Lax", "Secure"] {
        assert!(cookie.contains(attr), "{attr} not in {cookie}");
    }
    // Cookie の値そのものは画面に出さない（CSRF トークンはそこから作った別の値）
    let value = set_cookie(&page).unwrap();
    let value = value.split_once('=').unwrap().1;
    assert!(!page.body.contains(value));

    // 承認しただけ（GitHub から戻る前）では覚えない
    let started = start(&h.app, &path).await;
    assert_consent_page(&get(&h.app, &path).await);
    let finished = callback(&h.app, &started, "ok").await;
    assert_eq!(finished.status, StatusCode::FOUND, "{}", finished.body);
    assert!(finished.location().as_str().starts_with(REDIRECT_URI));

    // 次からは同意画面を出さずに GitHub へ送り、そのブラウザの Cookie を付ける
    let again = get(&h.app, &path).await;
    assert_eq!(again.status, StatusCode::FOUND, "{}", again.body);
    assert!(again
        .location()
        .as_str()
        .starts_with("https://github.com/login/oauth/authorize"));
    assert!(set_cookie(&again).is_some());

    // 別のクライアントは改めて聞く
    let other = register_client(&h.app).await;
    assert_consent_page(&get(&h.app, &authorize_path(&other, &challenge, None)).await);

    // 承認した id が許可から外れたら、覚えた承認も使わない
    h.allowed.write().unwrap().clear();
    assert_consent_page(&get(&h.app, &path).await);
}

#[tokio::test]
async fn consent_is_not_remembered_for_a_login_that_is_not_allowed() {
    let h = harness_with(
        &[
            ("ok", "2429307", "legokichi"),
            ("other", "1", "someoneelse"),
        ],
        true,
        None,
    );
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let path = authorize_path(&client_id, &challenge, None);
    // 攻撃者が自分のブラウザで承認し、自分の GitHub でログインしても覚えない
    let started = start(&h.app, &path).await;
    assert_eq!(
        callback(&h.app, &started, "other").await.status,
        StatusCode::FORBIDDEN
    );
    assert_consent_page(&get(&h.app, &path).await);
    assert_eq!(count(&h, "SELECT COUNT(*) FROM oauth_consents"), 0);
}

#[tokio::test]
async fn loopback_consent_ignores_the_port() {
    let h = harness();
    let reply = register_redirects(&h.app, &["http://localhost/callback"]).await;
    let client_id = reply.json()["client_id"].as_str().unwrap().to_string();
    let (_verifier, challenge) = pkce();
    let path = |port: u16| {
        authorize_with_redirect(
            &client_id,
            &challenge,
            Some(&format!("http://localhost:{port}/callback")),
        )
    };
    let started = start(&h.app, &path(53682)).await;
    assert_eq!(
        callback(&h.app, &started, "ok").await.status,
        StatusCode::FOUND
    );
    let again = get(&h.app, &path(40000)).await;
    assert_eq!(again.status, StatusCode::FOUND, "{}", again.body);
    // パスが違えば別の戻り先
    let other =
        authorize_with_redirect(&client_id, &challenge, Some("http://localhost:40000/other"));
    assert_eq!(get(&h.app, &other).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consent_needs_the_same_browser_and_can_be_denied() {
    let h = harness();
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let path = authorize_path(&client_id, &challenge, None);
    let page = get(&h.app, &path).await;
    assert_consent_page(&page);

    // Cookie が無い・別のブラウザの Cookie では、許可も拒否も受けない
    let elsewhere = set_cookie(&get(&h.app, &path).await).unwrap();
    for cookie in ["", elsewhere.as_str()] {
        for action in ["approve", "deny"] {
            let r = submit_consent(&h.app, &page, action, Some(cookie)).await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{cookie} {action}");
            assert!(r.headers.get(header::LOCATION).is_none());
        }
    }
    let r = get(&h.app, "/authorize/consent").await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);

    // hidden の値を書き換えても検証し直す（許可外の戻り先へは送らない）
    let cookie = set_cookie(&page).unwrap();
    let mut pairs: Vec<(String, String)> = hidden_fields(&page.body)
        .into_iter()
        .map(|(k, v)| {
            if k == "redirect_uri" {
                (k, "https://evil.example/cb".into())
            } else {
                (k, v)
            }
        })
        .collect();
    pairs.push(("consent_action".into(), "approve".into()));
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let tampered = send(
        &h.app,
        Request::post("/authorize/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .body(Body::from(encode(&pairs)))
            .unwrap(),
    )
    .await;
    assert_json_error_without_redirect(&tampered);

    // 拒否はクライアントへ access_denied を返し、何も覚えない
    let denied = submit_consent(&h.app, &page, "deny", None).await;
    assert_eq!(denied.status, StatusCode::FOUND, "{}", denied.body);
    let location = denied.location();
    assert!(location.as_str().starts_with(REDIRECT_URI));
    let q = query(&location);
    assert_eq!(q["error"], "access_denied");
    assert_eq!(q["state"], "client-state");
    assert_eq!(count(&h, "SELECT COUNT(*) FROM oauth_pending"), 0);
    assert_consent_page(&get(&h.app, &path).await);
}

/// H-1: GitHub の URL（state）だけを他人のブラウザで踏ませても、認可を始めたブラウザでなければ通らない。
#[tokio::test]
async fn callback_needs_the_browser_that_started_the_authorization() {
    let h = harness();
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let started = github_state(&h.app, &client_id, &challenge, &resource()).await;
    let bare = get(
        &h.app,
        &format!(
            "/oauth/callback/github?{}",
            encode(&[("code", "ok"), ("state", &started.state)])
        ),
    )
    .await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST);
    assert!(bare.body.contains("このブラウザで始めたものではない"));
    // 一度外れた state はもう使えない
    assert_eq!(
        callback(&h.app, &started, "ok").await.status,
        StatusCode::BAD_REQUEST
    );

    let started = github_state(&h.app, &client_id, &challenge, &resource()).await;
    let other = Started {
        state: started.state.clone(),
        cookie: format!("__Host-mcp_authz={}", token_urlsafe()),
    };
    assert_eq!(
        callback(&h.app, &other, "ok").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(count(&h, "SELECT COUNT(*) FROM oauth_codes"), 0);
}

/// H-2: 未認証の OAuth エンドポイントは小さなボディしか受けない。
#[tokio::test]
async fn oauth_endpoints_take_small_bodies_only() {
    let h = harness();
    let big = "x".repeat(crate::auth::MAX_OAUTH_BODY_BYTES + 1);
    for path in [
        "/register",
        "/token",
        "/authorize",
        "/authorize/consent",
        "/revoke",
    ] {
        let r = send(
            &h.app,
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(big.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
    }
}

/// H-2: 登録の各項目に件数・長さの上限があり、jwks は保存しない。
#[tokio::test]
async fn registration_fields_are_limited_and_jwks_is_not_kept() {
    let h = harness();
    let base = json!({ "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none" });
    let with = |key: &str, value: Value| {
        let mut body = base.clone();
        body[key] = value;
        body
    };
    let long_loopback = format!("http://127.0.0.1/{}", "a".repeat(2048));
    for body in [
        with("redirect_uris", json!(vec![REDIRECT_URI; 11])),
        with("redirect_uris", json!([long_loopback])),
        with("client_name", json!("a".repeat(201))),
        with("scope", json!("s".repeat(1025))),
        with("contacts", json!(vec!["a@example.com"; 11])),
        with("contacts", json!(["a".repeat(321)])),
        with("grant_types", json!(vec!["authorization_code"; 11])),
        with("software_id", json!("a".repeat(201))),
        with(
            "client_uri",
            json!(format!("https://example.com/{}", "a".repeat(2048))),
        ),
    ] {
        let r = register_json(&h.app, &body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
        assert_eq!(r.json()["error"], "invalid_client_metadata");
    }
    // 上限ちょうどは通る（名前は文字数で数える）
    let mut ok = with("client_name", json!("あ".repeat(200)));
    ok["redirect_uris"] = json!(vec![REDIRECT_URI; 10]);
    ok["jwks"] = json!({ "keys": [{ "kty": "RSA", "n": "x".repeat(1000), "e": "AQAB" }] });
    let r = register_json(&h.app, &ok).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert!(r.json().get("jwks").is_none());
    assert_eq!(
        count(
            &h,
            "SELECT COUNT(*) FROM oauth_clients WHERE record LIKE '%jwks%' OR record LIKE '%kty%'"
        ),
        0
    );
}

/// H-2: state・code_challenge・scope・resource の長さを見る。長すぎる state は応答にも載せない。
#[tokio::test]
async fn authorize_rejects_oversized_values_and_malformed_challenges() {
    let h = harness();
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let long_state = "s".repeat(crate::auth::MAX_STATE_BYTES + 1);
    let padded = format!("{}=", &challenge[..42]);
    let long_resource = format!("{}/{}", resource(), "./".repeat(1100));
    let long_scope = "x".repeat(1025);
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![("state", long_state.as_str())],
        vec![("code_challenge", "short")],
        vec![("code_challenge", padded.as_str())],
        vec![("resource", long_resource.as_str())],
        vec![("scope", long_scope.as_str())],
    ];
    for overrides in cases {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", "client-state"),
        ];
        for (k, v) in &overrides {
            pairs.retain(|(key, _)| key != k);
            pairs.push((k, v));
        }
        let r = get(&h.app, &format!("/authorize?{}", encode(&pairs))).await;
        assert_eq!(r.status, StatusCode::FOUND, "{overrides:?}: {}", r.body);
        let q = query(&r.location());
        assert_eq!(q["error"], "invalid_request", "{overrides:?}");
        assert_eq!(
            q.get("state").map(String::as_str),
            (overrides[0].0 != "state").then_some("client-state"),
            "{overrides:?}"
        );
    }
    assert_eq!(count(&h, "SELECT COUNT(*) FROM oauth_pending"), 0);
}

/// H-2: 認可の途中の行は MAX_PENDING 件まで（古い順に捨てる）。
#[tokio::test]
async fn pending_authorizations_are_capped() {
    let h = harness();
    let client_id = register_client(&h.app).await;
    let client = h.oauth.get_client(&client_id).await.unwrap().unwrap();
    let (_verifier, challenge) = pkce();
    let params = crate::auth::AuthorizationParams {
        state: None,
        scopes: Vec::new(),
        code_challenge: challenge,
        redirect_uri: REDIRECT_URI.into(),
        redirect_uri_provided_explicitly: true,
        resource: None,
    };
    for _ in 0..crate::auth::MAX_PENDING + 5 {
        assert!(h
            .oauth
            .authorize(&client, params.clone(), &token_urlsafe())
            .unwrap()
            .is_ok());
    }
    assert_eq!(
        count(&h, "SELECT COUNT(*) FROM oauth_pending") as usize,
        crate::auth::MAX_PENDING
    );
}

/// H-2: 登録を大量に送られても、使われている（トークンのある）クライアントは追い出さない。
#[tokio::test]
async fn clients_in_use_survive_a_registration_flood() {
    let h = harness();
    let (access, refresh, in_use) = issue_token(&h.app).await;
    let none = json!({ "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none" });
    let mut ids = Vec::new();
    for _ in 0..crate::auth::MAX_CLIENTS + 10 {
        let client =
            crate::auth::client_from_registration(&none, &RedirectAllowlist::default()).unwrap();
        ids.push(client.client_id.clone());
        assert!(h.oauth.register_client(client).unwrap());
    }
    assert!(h.oauth.get_client(&in_use).await.unwrap().is_some());
    assert!(h.oauth.get_client(&ids[0]).await.unwrap().is_none());
    assert_eq!(
        count(&h, "SELECT COUNT(*) FROM oauth_clients") as usize,
        crate::auth::MAX_CLIENTS
    );
    assert_eq!(mcp(&h.app, Some(&access), 1).await.status, StatusCode::OK);
    assert_eq!(
        refresh_with(&h.app, &refresh, &in_use).await.status,
        StatusCode::OK
    );

    // 全部が使われていれば、入れずに断る
    exec(
        &h,
        "INSERT INTO oauth_tokens (token_sha256, kind, client_id, subject, resource, scopes, issued_at, expires_at) \
         SELECT 'fake-' || client_id, 'access', client_id, '2429307', 'r', '[]', 0, ?1 FROM oauth_clients \
         WHERE client_id != ?2",
        rusqlite::params![crate::auth::now() + 3600, in_use],
    );
    let client =
        crate::auth::client_from_registration(&none, &RedirectAllowlist::default()).unwrap();
    assert!(!h.oauth.register_client(client).unwrap());
    let r = register_json(&h.app, &none).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
    assert_eq!(r.json()["error"], "temporarily_unavailable");
}

/// H-2: 登録の合計バイト数にも上限がある。
#[tokio::test]
async fn client_records_are_capped_in_total_bytes() {
    let h = harness();
    let uris: Vec<String> = (0..10)
        .map(|i| format!("http://127.0.0.1/{i}/{}", "a".repeat(2000)))
        .collect();
    let big = json!({ "redirect_uris": uris, "token_endpoint_auth_method": "none" });
    for _ in 0..300 {
        let client =
            crate::auth::client_from_registration(&big, &RedirectAllowlist::default()).unwrap();
        assert!(h.oauth.register_client(client).unwrap());
    }
    let bytes = count(
        &h,
        "SELECT SUM(length(CAST(record AS BLOB))) FROM oauth_clients",
    );
    assert!(
        bytes as usize <= crate::auth::MAX_CLIENT_RECORD_BYTES,
        "{bytes}"
    );
    assert!(count(&h, "SELECT COUNT(*) FROM oauth_clients") < 300);
}

/// H-2: 動的登録は全体で 1 分あたりの件数を絞る。
#[tokio::test]
async fn registrations_are_rate_limited() {
    let h = harness();
    let body = json!({ "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none" });
    let limit = crate::auth::REGISTRATIONS_PER_MINUTE as usize;
    // 分の境目をまたいでも、2 窓分を送れば必ず断られる
    let mut created = 0;
    let mut refused = None;
    for _ in 0..2 * limit + 2 {
        let r = register_json(&h.app, &body).await;
        if r.status == StatusCode::CREATED {
            created += 1;
        } else {
            refused = Some(r);
            break;
        }
    }
    let refused = refused.expect("registrations were never refused");
    assert!(created >= limit, "{created}");
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.headers[header::RETRY_AFTER], "60");
    assert_eq!(refused.json()["error"], "temporarily_unavailable");
}

/// URL に合わせた CIMD を返し、取りに来た回数を数える。
struct EchoFetcher {
    calls: std::sync::atomic::AtomicUsize,
    in_flight: std::sync::atomic::AtomicUsize,
    max_in_flight: std::sync::atomic::AtomicUsize,
    delay: std::time::Duration,
}

impl EchoFetcher {
    fn new(delay_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            calls: Default::default(),
            in_flight: Default::default(),
            max_in_flight: Default::default(),
            delay: std::time::Duration::from_millis(delay_ms),
        })
    }
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl ClientMetadataFetcher for EchoFetcher {
    async fn fetch(&self, url: &str) -> anyhow::Result<Value> {
        use std::sync::atomic::Ordering::SeqCst;
        self.calls.fetch_add(1, SeqCst);
        let now = self.in_flight.fetch_add(1, SeqCst) + 1;
        self.max_in_flight.fetch_max(now, SeqCst);
        tokio::time::sleep(self.delay).await;
        self.in_flight.fetch_sub(1, SeqCst);
        Ok(
            json!({ "client_id": url, "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none" }),
        )
    }
}

fn oauth_with(fetcher: Arc<EchoFetcher>) -> OAuthServer {
    OAuthServer::new(
        PUBLIC_URL,
        Arc::new(RwLock::new(HashSet::new())),
        Arc::new(FakeGitHub {
            logins: HashMap::new(),
            configured: true,
        }),
        fetcher,
        RedirectAllowlist::default(),
        Db::open_in_memory(),
    )
}

/// M-1: CIMD は allowlist のホストからだけ取る（既定は redirect allowlist のホスト）。
#[tokio::test]
async fn cimd_is_fetched_only_from_allowed_hosts() {
    let fetcher = EchoFetcher::new(0);
    let oauth = oauth_with(fetcher.clone());
    assert!(oauth
        .get_client("https://attacker.example/c.json")
        .await
        .unwrap()
        .is_none());
    assert_eq!(fetcher.calls(), 0);
    for allowed in [
        "https://claude.ai/oauth/x.json",
        "https://chatgpt.com/oauth/x.json",
    ] {
        assert!(
            oauth.get_client(allowed).await.unwrap().is_some(),
            "{allowed}"
        );
    }
    assert_eq!(fetcher.calls(), 2);

    let fetcher = EchoFetcher::new(0);
    let oauth =
        oauth_with(fetcher.clone()).with_cimd_hosts(HashSet::from(["client.example".to_string()]));
    assert!(oauth
        .get_client("https://client.example/c.json")
        .await
        .unwrap()
        .is_some());
    assert!(oauth
        .get_client("https://claude.ai/oauth/x.json")
        .await
        .unwrap()
        .is_none());
    assert_eq!(fetcher.calls(), 1);
}

/// M-1: CIMD のキャッシュは件数に上限があり、最後に使ったのが古いものから捨てる。
#[tokio::test]
async fn cimd_cache_is_a_bounded_lru() {
    let fetcher = EchoFetcher::new(0);
    let oauth = oauth_with(fetcher.clone());
    let url = |i: usize| format!("https://claude.ai/oauth/{i}.json");
    let n = crate::auth::CIMD_CACHE_CAPACITY;
    for i in 0..n {
        oauth.get_client(&url(i)).await.unwrap().unwrap();
    }
    // 0 を使い直してから 1 件足すと、1 が捨てられる
    oauth.get_client(&url(0)).await.unwrap().unwrap();
    assert_eq!(fetcher.calls(), n);
    oauth.get_client(&url(n)).await.unwrap().unwrap();
    oauth.get_client(&url(0)).await.unwrap().unwrap();
    assert_eq!(fetcher.calls(), n + 1);
    oauth.get_client(&url(1)).await.unwrap().unwrap();
    assert_eq!(fetcher.calls(), n + 2);
}

/// M-1: CIMD を同時に取りに行く数を絞る。
#[tokio::test]
async fn cimd_fetches_are_limited_in_number() {
    let fetcher = EchoFetcher::new(50);
    let oauth = Arc::new(oauth_with(fetcher.clone()));
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10 {
        let oauth = oauth.clone();
        set.spawn(async move {
            oauth
                .get_client(&format!("https://claude.ai/oauth/{i}.json"))
                .await
                .unwrap()
                .is_some()
        });
    }
    while let Some(found) = set.join_next().await {
        assert!(found.unwrap());
    }
    let max = fetcher
        .max_in_flight
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        max <= crate::auth::CIMD_MAX_CONCURRENT_FETCHES && max > 1,
        "{max}"
    );
}

/// M-1: CIMD の項目にも登録と同じ上限を置く。
#[test]
fn cimd_documents_are_limited_like_registrations() {
    use crate::auth::client_from_cimd;
    let url = "https://claude.ai/oauth/x.json";
    let allowlist = RedirectAllowlist::default();
    let doc = |key: &str, value: Value| {
        let mut d = json!({ "client_id": url, "redirect_uris": [REDIRECT_URI] });
        d[key] = value;
        d
    };
    assert!(client_from_cimd(url, &doc("client_name", json!("Claude")), &allowlist).is_some());
    // 文字列でない名前は今までどおり無視する
    let ignored = client_from_cimd(url, &doc("client_name", json!(1)), &allowlist).unwrap();
    assert!(ignored.client_name.is_none());
    for bad in [
        doc("redirect_uris", json!(vec![REDIRECT_URI; 11])),
        doc("client_name", json!("a".repeat(201))),
        doc("scope", json!("s".repeat(1025))),
        doc("grant_types", json!(vec!["authorization_code"; 11])),
    ] {
        assert!(client_from_cimd(url, &bad, &allowlist).is_none(), "{bad}");
    }
}

/// L-3: 使ったコードがもう一度来たら、そのコードから発行したトークンを失効させる。
#[tokio::test]
async fn a_reused_code_revokes_the_tokens_issued_from_it() {
    let h = harness();
    let client_id = register_client(&h.app).await;
    let (verifier, challenge) = pkce();
    let code = authorization_code(&h.app, &client_id, &challenge).await;
    let payload = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let first = post_form(&h.app, "/token", &payload).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let access = first.json()["access_token"].as_str().unwrap().to_string();
    let refresh = first.json()["refresh_token"].as_str().unwrap().to_string();
    // 同じクライアントの別の認可は巻き込まない
    let (other_verifier, other_challenge) = pkce();
    let other_code = authorization_code(&h.app, &client_id, &other_challenge).await;
    let other = post_form(
        &h.app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &other_code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", &other_verifier),
        ],
    )
    .await;
    let other_access = other.json()["access_token"].as_str().unwrap().to_string();

    let second = post_form(&h.app, "/token", &payload).await;
    assert_eq!(second.json()["error"], "invalid_grant");
    assert_eq!(
        mcp(&h.app, Some(&access), 1).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh_with(&h.app, &refresh, &client_id).await.json()["error"],
        "invalid_grant"
    );
    assert_eq!(
        mcp(&h.app, Some(&other_access), 2).await.status,
        StatusCode::OK
    );
}

/// L-3: 入れ替え済みの refresh が猶予の後にもう一度来たら、そのクライアントのトークンを全部失効させる。
#[tokio::test]
async fn a_refresh_reused_after_the_grace_revokes_the_clients_tokens() {
    let h = harness();
    let (access, refresh, client_id) = issue_token(&h.app).await;
    let (other_access, _, _) = issue_token(&h.app).await;
    let rotated = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let new_access = rotated.json()["access_token"].as_str().unwrap().to_string();
    let new_refresh = rotated.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // 猶予のうちの再送は、断るだけで失効させない
    let early = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(early.json()["error"], "invalid_grant");
    assert_eq!(
        mcp(&h.app, Some(&new_access), 1).await.status,
        StatusCode::OK
    );

    exec(
        &h,
        "UPDATE oauth_tokens SET used_at = ?1 WHERE token_sha256 = ?2",
        rusqlite::params![
            crate::auth::now() - REFRESH_GRACE_SECS - 1,
            sha256_hex(&refresh)
        ],
    );
    let reused = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(reused.status, StatusCode::BAD_REQUEST);
    assert_eq!(reused.json()["error"], "invalid_grant");
    assert!(reused.json()["error_description"]
        .as_str()
        .unwrap()
        .contains("already used"));
    for token in [&access, &new_access] {
        assert_eq!(
            mcp(&h.app, Some(token), 2).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        refresh_with(&h.app, &new_refresh, &client_id).await.json()["error"],
        "invalid_grant"
    );
    // 別のクライアントには響かない
    assert_eq!(
        mcp(&h.app, Some(&other_access), 3).await.status,
        StatusCode::OK
    );
}

/// L-3: refresh で延ばせるのは認可から GRANT_MAX_LIFETIME まで。
#[tokio::test]
async fn grants_have_an_absolute_lifetime() {
    let h = harness();
    let (_access, refresh, client_id) = issue_token(&h.app).await;
    let now = crate::auth::now();
    exec(
        &h,
        "UPDATE oauth_tokens SET granted_at = ?1",
        [now - crate::auth::GRANT_MAX_LIFETIME + 100],
    );
    let rotated = refresh_with(&h.app, &refresh, &client_id).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let expires_in = rotated.json()["expires_in"].as_i64().unwrap();
    assert!(expires_in <= 100, "{expires_in}");
    let new_refresh = rotated.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let refresh_expires: i64 = h
        .relay
        .store
        .db()
        .read(|c| {
            c.query_row(
                "SELECT expires_at FROM oauth_tokens WHERE token_sha256 = ?1",
                [sha256_hex(&new_refresh)],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(refresh_expires <= now + 100, "{refresh_expires} {now}");
}

/// L-3: RFC 7009 の失効。発行先のクライアントからだけ、認可の系列ごと失効させる。
#[tokio::test]
async fn revocation_endpoint_revokes_the_grant() {
    let h = harness();
    let metadata = get(&h.app, "/.well-known/oauth-authorization-server")
        .await
        .json();
    assert_eq!(
        metadata["revocation_endpoint"],
        format!("{PUBLIC_URL}/revoke")
    );
    let (access, refresh, client_id) = issue_token(&h.app).await;
    let (_, _, other_client) = issue_token(&h.app).await;

    // 他のクライアントからは失効させられない（応答は同じ 200）
    let r = post_form(
        &h.app,
        "/revoke",
        &[("token", &refresh), ("client_id", &other_client)],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(mcp(&h.app, Some(&access), 1).await.status, StatusCode::OK);

    for (form, status) in [
        (vec![("token", refresh.as_str())], StatusCode::UNAUTHORIZED),
        (
            vec![("client_id", client_id.as_str())],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![("token", "unknown"), ("client_id", client_id.as_str())],
            StatusCode::OK,
        ),
    ] {
        assert_eq!(post_form(&h.app, "/revoke", &form).await.status, status);
    }

    let r = post_form(
        &h.app,
        "/revoke",
        &[
            ("token", &refresh),
            ("token_type_hint", "refresh_token"),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        mcp(&h.app, Some(&access), 2).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh_with(&h.app, &refresh, &client_id).await.json()["error"],
        "invalid_grant"
    );
}

/// L-4: 外から来た値は構造化フィールドで出し、改行で偽のログ行を作らせない。
#[tokio::test]
async fn untrusted_values_cannot_forge_log_lines() {
    let logs = crate::relay::tests::capture_logs();
    let fetcher = EchoFetcher::new(0);
    let oauth = oauth_with(fetcher);
    let injected = "https://attacker.example/x\nFORGED LOG LINE level=ERROR";
    assert!(crate::auth::is_cimd_client_id(injected));
    assert!(oauth.get_client(injected).await.unwrap().is_none());
    let out = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(out.contains("cimd host is not allowed"), "{out}");
    assert!(out.contains("\\nFORGED LOG LINE"), "{out}");
    assert!(
        !out.lines().any(|l| l.starts_with("FORGED")),
        "forged line in:\n{out}"
    );
}
