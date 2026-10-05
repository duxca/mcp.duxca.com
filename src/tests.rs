//! mcp-test の tests/test_auth.py を移植した結合テスト。

use crate::auth::{
    is_cimd_client_id, pkce_s256, token_urlsafe, ClientMetadataFetcher, GitHubLogin,
    GitHubLoginError, OAuthServer, MCP_PATH,
};
use crate::backend::McpBackend;
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

const PUBLIC_URL: &str = "https://demo.trycloudflare.com";
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";

fn resource() -> String {
    format!("{PUBLIC_URL}{MCP_PATH}")
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

struct FakeBackend;

#[async_trait]
impl McpBackend for FakeBackend {
    async fn handle(&self, message: Value) -> Option<Value> {
        Some(json!({
            "jsonrpc": "2.0",
            "id": message.get("id").cloned(),
            "result": { "tools": [{ "name": "Bash" }] },
        }))
    }
}

struct Harness {
    app: Router,
    allowed: Arc<RwLock<HashSet<String>>>,
}

fn harness_with(logins: &[(&str, &str, &str)], configured: bool, cimd: Option<Value>) -> Harness {
    let allowed = Arc::new(RwLock::new(HashSet::from(["2429307".to_string()])));
    let github = FakeGitHub {
        logins: logins
            .iter()
            .map(|(code, id, login)| (code.to_string(), (id.to_string(), login.to_string())))
            .collect(),
        configured,
    };
    let oauth = Arc::new(OAuthServer::new(
        PUBLIC_URL,
        allowed.clone(),
        Arc::new(github),
        Arc::new(FakeFetcher(cimd)),
    ));
    let app = router(AppState {
        public_url: PUBLIC_URL.into(),
        backend: Arc::new(FakeBackend),
        oauth,
    });
    Harness { app, allowed }
}

fn harness() -> Harness {
    harness_with(&[("ok", "2429307", "legokichi")], true, None)
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn location(&self) -> Url {
        Url::parse(self.headers[header::LOCATION].to_str().unwrap()).unwrap()
    }
}

fn query(url: &Url) -> HashMap<String, String> {
    url.query_pairs().into_owned().collect()
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn get(app: &Router, path: &str) -> Reply {
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
    let mut req = Request::post(MCP_PATH).header(header::CONTENT_TYPE, "application/json");
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

async fn github_state(app: &Router, client_id: &str, challenge: &str) -> String {
    let started = get(
        app,
        &authorize_path(client_id, challenge, Some(&resource())),
    )
    .await;
    assert_eq!(started.status, StatusCode::FOUND, "{}", started.body);
    let location = started.location();
    assert!(location
        .as_str()
        .starts_with("https://github.com/login/oauth/authorize"));
    query(&location)["state"].clone()
}

async fn authorization_code(app: &Router, client_id: &str, challenge: &str) -> String {
    let state = github_state(app, client_id, challenge).await;
    let finished = get(
        app,
        &format!(
            "/oauth/callback/github?{}",
            encode(&[("code", "ok"), ("state", &state)])
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
    let client_id = register_client(app).await;
    let (verifier, challenge) = pkce();
    let code = authorization_code(app, &client_id, &challenge).await;
    let token = post_form(
        app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", &verifier),
            ("resource", &resource()),
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
    ] {
        assert!(!is_global_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
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
        &format!("/.well-known/oauth-protected-resource{MCP_PATH}"),
    )
    .await;
    assert_eq!(prm.status, StatusCode::OK);
    assert_eq!(prm.json()["resource"], resource());
    assert_eq!(prm.json()["authorization_servers"], json!([PUBLIC_URL]));

    let denied = mcp(&h.app, None, 1).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    let www = denied.headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        www.contains(&format!("/.well-known/oauth-protected-resource{MCP_PATH}")),
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
    assert_eq!(listed.json()["result"]["tools"][0]["name"], "Bash");

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
    assert_eq!(
        mcp(&h.app, Some(&access), 4).await.status,
        StatusCode::UNAUTHORIZED
    );

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
    let state = github_state(&h.app, &client_id, &challenge).await;
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
    let state = github_state(&h.app, &client_id, &challenge).await;
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
    let started = get(
        &h.app,
        &authorize_path(&client_id, &challenge, Some("https://evil.example/mcp")),
    )
    .await;
    assert_eq!(started.status, StatusCode::FOUND);
    let location = started.location();
    assert!(location.as_str().starts_with(REDIRECT_URI));
    let q = query(&location);
    assert_eq!(q["error"], "invalid_target");
    assert_eq!(q["state"], "client-state");
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
