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

async fn github_state(app: &Router, client_id: &str, challenge: &str, resource: &str) -> String {
    let started = get(app, &authorize_path(client_id, challenge, Some(resource))).await;
    assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    let location = started.location();
    assert!(location
        .as_str()
        .starts_with("https://github.com/login/oauth/authorize"));
    query(&location)["state"].clone()
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
    let state = github_state(app, client_id, challenge, resource).await;
    let finished = get(
        app,
        &format!(
            "/oauth/callback/github?{}",
            encode(&[("code", login), ("state", &state)])
        ),
    )
    .await;
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
    let state = github_state(&h.app, &client_id, &challenge, &resource()).await;
    let path = format!(
        "/oauth/callback/github?{}",
        encode(&[("code", "ok"), ("state", &state)])
    );
    let denied = get(&h.app, &path).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert!(denied
        .body
        .contains("この GitHub アカウントは許可されていない。"));
    assert!(denied.body.contains("login: someoneelse"));
    assert!(denied.body.contains("id: 1"));
    let replay = get(&h.app, &path).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reused_login_with_another_id_gets_no_code() {
    // legokichi が改名され、別人が同じ login を取った場合。id が違うので弾く。
    let h = harness_with(&[("ok", "99999999", "legokichi")], true, None);
    let client_id = register_client(&h.app).await;
    let (_verifier, challenge) = pkce();
    let state = github_state(&h.app, &client_id, &challenge, &resource()).await;
    let denied = get(
        &h.app,
        &format!(
            "/oauth/callback/github?{}",
            encode(&[("code", "ok"), ("state", &state)])
        ),
    )
    .await;
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
    let url = "https://client.example/oauth.json";
    let h = harness_with(
        &[("ok", "2429307", "legokichi")],
        true,
        Some(
            json!({ "client_id": url, "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none" }),
        ),
    );
    let (_verifier, challenge) = pkce();
    let started = get(&h.app, &authorize_path(url, &challenge, Some(&resource()))).await;
    assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    assert!(started
        .location()
        .as_str()
        .starts_with("https://github.com/login/oauth/authorize"));

    let h = harness_with(
        &[],
        true,
        Some(
            json!({ "client_id": "https://other.example/oauth.json", "redirect_uris": [REDIRECT_URI] }),
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
    let started = get(&h.app, &path).await;
    assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    let state = query(&started.location())["state"].clone();
    let finished = get(
        &h.app,
        &format!(
            "/oauth/callback/github?{}",
            encode(&[("code", "ok"), ("state", &state)])
        ),
    )
    .await;
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
    let started = get(&h.app, &authorize_path(&client_id, &challenge, None)).await;
    assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    let state = query(&started.location())["state"].clone();
    let finished = get(
        &h.app,
        &format!(
            "/oauth/callback/github?{}",
            encode(&[("code", "ok"), ("state", &state)])
        ),
    )
    .await;
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
    let started = get(
        &h.app,
        &authorize_with_redirect(&client_id, &challenge, Some(redirect)),
    )
    .await;
    assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    assert!(started
        .location()
        .as_str()
        .starts_with("https://github.com/login/oauth/authorize"));
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
        let started = get(
            &h.app,
            &authorize_with_redirect(&client_id, &challenge, Some(redirect)),
        )
        .await;
        assert_eq!(
            started.status,
            StatusCode::FOUND,
            "{redirect}: {}",
            started.body
        );
        assert!(started
            .location()
            .as_str()
            .starts_with("https://github.com/login/oauth/authorize"));
    }
}

#[tokio::test]
async fn cimd_with_redirect_uris_outside_the_allowlist_is_rejected() {
    let url = "https://client.example/oauth.json";
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
    let state = github_state(&h.app, &client_id, &challenge, &resource()).await;
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
