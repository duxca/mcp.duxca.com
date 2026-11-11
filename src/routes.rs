//! HTTP ルート。OAuth の各エンドポイントは MCP Python SDK（mcp-test が使うもの）と同じ形。

use crate::auth::{
    consent_csrf_token, construct_redirect_uri, is_browser_secret, is_cimd_client_id,
    is_s256_challenge, normalize_url, pkce_s256, token_urlsafe, verify_consent_csrf,
    AuthorizationParams, CallbackOutcome, ClientRecord, IssuedToken, OAuthServer, TokenError,
    AUTHORIZATION_PATH, CONSENT_PATH, GITHUB_SETUP_PATH, MAX_OAUTH_BODY_BYTES, MAX_SCOPE_BYTES,
    MAX_STATE_BYTES, MAX_URI_LEN, PENDING_TTL, REDIRECT_PATH, REGISTRATION_PATH, REVOCATION_PATH,
    TOKEN_PATH,
};
use crate::db::DbError;
use crate::relay::Relay;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, RawQuery, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub oauth: Arc<OAuthServer>,
    /// `/relay/v1`（常時有効。OAuth の subject ごとに部屋を分ける）
    pub relay: Arc<Relay>,
}

pub fn router(state: AppState) -> Router {
    let relay = state.relay.clone();
    // 未認証で叩ける OAuth のエンドポイントは小さなボディしか受けない
    let small = || DefaultBodyLimit::max(MAX_OAUTH_BODY_BYTES);
    let app = Router::new()
        .route(
            crate::relay::PREFIX,
            any(relay_mcp).layer(DefaultBodyLimit::max(crate::relay::MAX_BODY_BYTES)),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_metadata),
        )
        .route(
            &format!(
                "/.well-known/oauth-protected-resource{}",
                crate::relay::PREFIX
            ),
            get(resource_metadata),
        )
        // 全リソース一覧（拡張）。パス固有エンドポイントが本命。
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata_index),
        )
        .route(
            AUTHORIZATION_PATH,
            get(authorize).post(authorize).layer(small()),
        )
        .route(CONSENT_PATH, post(authorize_consent).layer(small()))
        .route(TOKEN_PATH, post(token).layer(small()))
        .route(REGISTRATION_PATH, post(register).layer(small()))
        .route(REVOCATION_PATH, post(revoke).layer(small()))
        .route(REDIRECT_PATH, get(github_callback))
        .route(GITHUB_SETUP_PATH, get(github_setup))
        .with_state(state);
    app.merge(crate::relay::router(relay))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn text(status: u16, body: String) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    no_store(
        (
            status,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
            .into_response(),
    )
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    no_store(response)
}

/// DB の失敗は 503。401 や invalid_grant にはしない（クライアントに再認可を促してしまう）。
impl IntoResponse for DbError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self, "store failed");
        no_store(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "temporarily_unavailable",
                    "error_description": "the server's storage failed; try again later",
                })),
            )
                .into_response(),
        )
    }
}

/// x-www-form-urlencoded を辞書にする（同じキーは後勝ち）。
fn parse_form(raw: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(raw).into_owned().collect()
}

// ---------------------------------------------------------------------------
// メタデータ

async fn oauth_metadata(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(state.oauth.metadata()),
    )
        .into_response()
}

async fn resource_metadata_index(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(state.oauth.protected_resources_index()),
    )
        .into_response()
}

async fn resource_metadata(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(state.oauth.protected_resource_metadata()),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// /authorize, /authorize/consent

/// 同意画面のフォームに載せ直す、元の認可要求の引数。
const AUTHORIZATION_FIELDS: [&str; 8] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
];

/// RFC 6749 4.1.2.1 のエラー応答（戻し先が確かなとき）。
fn error_redirect(uri: &str, error: &str, description: &str, state: Option<&str>) -> Response {
    redirect(&construct_redirect_uri(
        uri,
        &[
            ("error", Some(error)),
            ("error_description", Some(description)),
            ("state", state),
        ],
    ))
}

struct AuthorizeContext {
    params: HashMap<String, String>,
    client: Option<ClientRecord>,
    redirect_uri: Option<String>,
    state: Option<String>,
}

impl AuthorizeContext {
    /// RFC 6749 4.1.2.1: client と redirect_uri が確かなら戻し先へ、そうでなければ 400 JSON。
    async fn error(
        mut self,
        oauth: &OAuthServer,
        error: &str,
        description: &str,
        load_client: bool,
    ) -> Result<Response, DbError> {
        if self.client.is_none() && load_client {
            if let Some(id) = self.params.get("client_id").filter(|s| !s.is_empty()) {
                self.client = oauth.get_client(id).await?;
            }
        }
        if self.redirect_uri.is_none() {
            if let Some(client) = &self.client {
                let raw = self.params.get("redirect_uri").map(String::as_str);
                if raw.is_none() || raw.and_then(normalize_url).is_some() {
                    self.redirect_uri = client
                        .validate_redirect_uri(raw, &oauth.redirect_allowlist)
                        .ok();
                }
            }
        }
        Ok(match (&self.redirect_uri, &self.client) {
            (Some(uri), Some(_)) => error_redirect(uri, error, description, self.state.as_deref()),
            _ => {
                let mut body = json!({ "error": error, "error_description": description });
                if let Some(state) = &self.state {
                    body["state"] = json!(state);
                }
                no_store((StatusCode::BAD_REQUEST, Json(body)).into_response())
            }
        })
    }
}

/// 検証済みの認可要求。
struct AuthorizationRequest {
    client: ClientRecord,
    params: AuthorizationParams,
    /// 同意画面のフォームに載せ直す元の引数
    fields: Vec<(&'static str, String)>,
}

/// 入力を検証する（SDK の AuthorizationRequest 相当 + 長さの上限 + resource）。
/// エラーは戻し先へのリダイレクトか 400 JSON の応答にして返す。
async fn validate_authorization(
    oauth: &OAuthServer,
    params: HashMap<String, String>,
) -> Result<Result<AuthorizationRequest, Response>, DbError> {
    // 長すぎる state はエラー応答にも載せない
    let state = params
        .get("state")
        .filter(|s| s.len() <= MAX_STATE_BYTES)
        .cloned();
    let mut ctx = AuthorizeContext {
        state,
        params,
        client: None,
        redirect_uri: None,
    };

    let p = &ctx.params;
    let too_long = |key: &str, max: usize| p.get(key).is_some_and(|v| v.len() > max);
    let mut problems: Vec<String> = Vec::new();
    let mut error = "invalid_request";
    match p.get("client_id") {
        None => problems.push("client_id: Field required".into()),
        Some(_) if too_long("client_id", MAX_URI_LEN) => {
            problems.push(format!("client_id: at most {MAX_URI_LEN} bytes"))
        }
        Some(_) => {}
    }
    match p.get("response_type").map(String::as_str) {
        Some("code") => {}
        Some(_) => {
            error = "unsupported_response_type";
            problems.push("response_type: Input should be 'code'".into());
        }
        None => problems.push("response_type: Field required".into()),
    }
    match p.get("code_challenge") {
        None => problems.push("code_challenge: Field required".into()),
        Some(c) if !is_s256_challenge(c) => problems.push(
            "code_challenge: Input should be 43 base64url characters (S256, RFC 7636)".into(),
        ),
        Some(_) => {}
    }
    if let Some(m) = p.get("code_challenge_method") {
        if m != "S256" {
            problems.push("code_challenge_method: Input should be 'S256'".into());
        }
    }
    if let Some(uri) = p.get("redirect_uri") {
        if uri.len() > MAX_URI_LEN || normalize_url(uri).is_none() {
            problems.push("redirect_uri: Input should be a valid URL".into());
        }
    }
    if too_long("state", MAX_STATE_BYTES) {
        problems.push(format!("state: at most {MAX_STATE_BYTES} bytes"));
    }
    if too_long("scope", MAX_SCOPE_BYTES) {
        problems.push(format!("scope: at most {MAX_SCOPE_BYTES} bytes"));
    }
    if too_long("resource", MAX_URI_LEN) {
        problems.push(format!("resource: at most {MAX_URI_LEN} bytes"));
    }
    if !problems.is_empty() {
        let description = problems.join("\n");
        return ctx.error(oauth, error, &description, true).await.map(Err);
    }

    let client_id = ctx.params["client_id"].clone();
    let Some(client) = oauth.get_client(&client_id).await? else {
        let description = format!("Client ID '{client_id}' not found");
        return ctx
            .error(oauth, "invalid_request", &description, false)
            .await
            .map(Err);
    };
    ctx.client = Some(client.clone());

    let requested_redirect = ctx.params.get("redirect_uri").cloned();
    let redirect_uri = match client
        .validate_redirect_uri(requested_redirect.as_deref(), &oauth.redirect_allowlist)
    {
        Ok(uri) => uri,
        Err(description) => {
            return ctx
                .error(oauth, "invalid_request", &description, true)
                .await
                .map(Err)
        }
    };
    ctx.redirect_uri = Some(redirect_uri.clone());

    let scopes = match client.validate_scope(ctx.params.get("scope").map(String::as_str)) {
        Ok(scopes) => scopes.unwrap_or_default(),
        Err(description) => {
            return ctx
                .error(oauth, "invalid_scope", &description, true)
                .await
                .map(Err)
        }
    };
    let resource = ctx.params.get("resource").cloned();
    if let Err(e) = oauth.check_resource(resource.as_deref()) {
        return ctx
            .error(oauth, e.error, &e.description, true)
            .await
            .map(Err);
    }

    let fields = AUTHORIZATION_FIELDS
        .iter()
        .filter_map(|&k| ctx.params.get(k).map(|v| (k, v.clone())))
        .collect();
    Ok(Ok(AuthorizationRequest {
        params: AuthorizationParams {
            state: ctx.state.clone(),
            scopes,
            code_challenge: ctx.params["code_challenge"].clone(),
            redirect_uri,
            redirect_uri_provided_explicitly: requested_redirect.is_some(),
            resource,
        },
        client,
        fields,
    }))
}

/// 認可を始めたブラウザに置く Cookie の名前。HTTPS では `__Host-` を付ける（サブドメインから置けない）。
fn browser_cookie_name(oauth: &OAuthServer) -> &'static str {
    if oauth.issuer.starts_with("https://") {
        "__Host-mcp_authz"
    } else {
        "mcp_authz"
    }
}

fn browser_cookie(oauth: &OAuthServer, headers: &HeaderMap) -> Option<String> {
    let name = browser_cookie_name(oauth);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, v)| *k == name && is_browser_secret(v))
        .map(|(_, v)| v.to_string())
}

/// 同時に進む認可（別のタブなど）を壊さないよう、既にあれば同じ値を使い続ける。
fn set_browser_cookie(oauth: &OAuthServer, response: &mut Response, value: &str) {
    let secure = if oauth.issuer.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}={value}; Path=/; Max-Age={PENDING_TTL}; HttpOnly; SameSite=Lax{secure}",
        browser_cookie_name(oauth)
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// 同意の済んだ要求を GitHub へ送る。pending はこのブラウザの Cookie に結び付ける。
fn start_github_login(
    oauth: &OAuthServer,
    request: AuthorizationRequest,
    headers: &HeaderMap,
) -> Result<Response, DbError> {
    let browser = browser_cookie(oauth, headers).unwrap_or_else(token_urlsafe);
    let AuthorizationRequest { client, params, .. } = request;
    let (redirect_uri, state) = (params.redirect_uri.clone(), params.state.clone());
    Ok(match oauth.authorize(&client, params, &browser)? {
        Ok(next) => {
            let mut response = redirect(&next);
            set_browser_cookie(oauth, &mut response, &browser);
            response
        }
        Err(e) => error_redirect(&redirect_uri, e.error, &e.description, state.as_deref()),
    })
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// 同意画面。client_name は自己申告なので、client_id と戻り先のオリジンも見せる。
fn consent_html(request: &AuthorizationRequest, csrf: &str) -> String {
    let client = &request.client;
    let name = match client
        .client_name
        .as_deref()
        .filter(|n| !n.trim().is_empty())
    {
        Some(name) => html_escape(name),
        None => "（名前の申告なし）".into(),
    };
    let client_id = if is_cimd_client_id(&client.client_id) {
        let host = url::Url::parse(&client.client_id)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default();
        format!(
            "<strong>{}</strong> が公開している文書<br><span class=\"note\">{}</span>",
            html_escape(&host),
            html_escape(&client.client_id)
        )
    } else {
        format!(
            "{}<br><span class=\"note\">このサーバに動的登録されたクライアント</span>",
            html_escape(&client.client_id)
        )
    };
    let redirect = url::Url::parse(&request.params.redirect_uri).ok();
    let origin = redirect
        .as_ref()
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_default();
    let loopback = redirect.as_ref().is_some_and(|u| {
        u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
    });
    let origin_note = if loopback {
        "<br><span class=\"note\">この端末の上で動くアプリ</span>"
    } else {
        ""
    };
    let hidden: String = request
        .fields
        .iter()
        .map(|(k, v)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">\n",
                html_escape(k),
                html_escape(v)
            )
        })
        .collect();
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>接続の確認 - mcp.duxca.com</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.6; }}
dt {{ font-weight: bold; margin-top: .8rem; }}
dd {{ margin: 0; word-break: break-all; }}
.note {{ color: #555; font-size: .9rem; }}
.warn {{ background: #fff4e5; border: 1px solid #f0b46c; padding: .8rem; border-radius: 6px; }}
button {{ font-size: 1rem; padding: .5rem 1.2rem; margin: 1rem .8rem 0 0; }}
</style>
</head>
<body>
<h1>このアプリに接続を許可するか</h1>
<p class="warn">自分でこのアプリから接続を始めたときだけ許可する。リンクを開いただけでこの画面が出たなら拒否する。<br>
許可すると、このアプリは relay の部屋のメッセージと添付をすべて読み書きできるようになる。</p>
<dl>
<dt>アプリ名（アプリの自己申告。本物とは限らない）</dt>
<dd>{name}</dd>
<dt>client_id</dt>
<dd>{client_id}</dd>
<dt>許可したあとに戻る先</dt>
<dd>{origin}{origin_note}</dd>
</dl>
<form method="post" action="{CONSENT_PATH}">
<input type="hidden" name="consent_csrf" value="{csrf}">
{hidden}<button type="submit" name="consent_action" value="deny">拒否</button>
<button type="submit" name="consent_action" value="approve">許可</button>
</form>
<p class="note">許可して GitHub でのログインまで済むと、同じ client_id と戻り先の組み合わせでは次からこの画面を出さない。</p>
</body>
</html>
"#,
        origin = html_escape(&origin),
        csrf = html_escape(csrf),
    )
}

fn consent_page(
    oauth: &OAuthServer,
    request: &AuthorizationRequest,
    headers: &HeaderMap,
) -> Response {
    let browser = browser_cookie(oauth, headers).unwrap_or_else(token_urlsafe);
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        consent_html(request, &consent_csrf_token(&browser)),
    )
        .into_response();
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // クリックジャッキング対策。form-action は GitHub へのリダイレクトも縛るので付けない
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    set_browser_cookie(oauth, &mut response, &browser);
    response
}

/// 承認済みの (client_id, redirect_uri) なら GitHub へ、そうでなければ同意画面を返す。
async fn authorize(
    State(state): State<AppState>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, DbError> {
    let oauth = state.oauth.as_ref();
    let params = if method == Method::POST {
        parse_form(&body)
    } else {
        parse_form(query.unwrap_or_default().as_bytes())
    };
    let request = match validate_authorization(oauth, params).await? {
        Ok(request) => request,
        Err(response) => return Ok(response),
    };
    if !oauth.github.configured() {
        return Ok(redirect(&oauth.setup_url()));
    }
    if oauth.has_consent(&request.client.client_id, &request.params.redirect_uri)? {
        return start_github_login(oauth, request, &headers);
    }
    Ok(consent_page(oauth, &request, &headers))
}

/// 同意画面の「許可 / 拒否」。CSRF トークンは同じブラウザの Cookie から作ったものに限る。
async fn authorize_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, DbError> {
    let oauth = state.oauth.as_ref();
    let mut form = parse_form(&body);
    let csrf = form.remove("consent_csrf");
    let action = form.remove("consent_action");
    let csrf_ok = match (browser_cookie(oauth, &headers), csrf) {
        (Some(browser), Some(token)) => verify_consent_csrf(&browser, &token),
        _ => false,
    };
    if !csrf_ok {
        return Ok(text(
            403,
            "同意を確かめられなかった（Cookie が無いか、画面が古い）。\n接続をやり直す。\n".into(),
        ));
    }
    form.retain(|k, _| AUTHORIZATION_FIELDS.contains(&k.as_str()));
    let request = match validate_authorization(oauth, form).await? {
        Ok(request) => request,
        Err(response) => return Ok(response),
    };
    match action.as_deref() {
        Some("approve") => start_github_login(oauth, request, &headers),
        Some("deny") => Ok(error_redirect(
            &request.params.redirect_uri,
            "access_denied",
            "the resource owner denied the request",
            request.params.state.as_deref(),
        )),
        _ => Ok(text(
            400,
            "consent_action は approve か deny にする。\n".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// /oauth/callback/github, /oauth/setup/github

async fn github_callback(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<Response, DbError> {
    let q = parse_form(query.unwrap_or_default().as_bytes());
    let browser = browser_cookie(&state.oauth, &headers);
    let outcome = state
        .oauth
        .complete_github_callback(
            q.get("code").map(String::as_str),
            q.get("state").map(String::as_str),
            q.get("error").map(String::as_str),
            browser.as_deref(),
        )
        .await?;
    Ok(match outcome {
        CallbackOutcome::Redirect(url) => redirect(&url),
        CallbackOutcome::Text(status, body) => text(status, body),
    })
}

async fn github_setup(State(state): State<AppState>) -> Response {
    if state.oauth.github.configured() {
        return text(
            200,
            format!(
                "GitHub OAuth は設定済み。\nコールバック URL は {}\n",
                state.oauth.github.redirect_uri()
            ),
        );
    }
    text(503, state.oauth.setup_text())
}

// ---------------------------------------------------------------------------
// /token

fn token_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn token_error(error: &str, description: &str) -> Response {
    token_response(
        StatusCode::BAD_REQUEST,
        json!({ "error": error, "error_description": description }),
    )
}

impl From<TokenError> for Response {
    fn from(e: TokenError) -> Self {
        token_error(e.error, &e.description)
    }
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, DbError> {
    let oauth = state.oauth.as_ref();
    let form = parse_form(&body);
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let client = match oauth.authenticate_client(&form, authorization).await? {
        Ok(client) => client,
        Err(message) => {
            return Ok(token_response(
                StatusCode::UNAUTHORIZED,
                json!({ "error": "invalid_client", "error_description": message }),
            ))
        }
    };

    let grant_type = match form.get("grant_type").map(String::as_str) {
        Some(g @ ("authorization_code" | "refresh_token")) => g,
        Some(_) => {
            return Ok(token_error(
                "unsupported_grant_type",
                "Unsupported grant type",
            ))
        }
        None => return Ok(token_error("invalid_request", "grant_type: Field required")),
    };
    if !client.grant_types.iter().any(|g| g == grant_type) {
        return Ok(token_error(
            "unsupported_grant_type",
            &format!(
                "Unsupported grant type (supported grant types are {:?})",
                client.grant_types
            ),
        ));
    }

    let tokens = if grant_type == "authorization_code" {
        let (Some(code), Some(verifier)) = (form.get("code"), form.get("code_verifier")) else {
            return Ok(token_error(
                "invalid_request",
                "code and code_verifier are required",
            ));
        };
        let token_redirect = match form.get("redirect_uri") {
            Some(raw) => match normalize_url(raw) {
                Some(uri) => Some(uri),
                None => {
                    return Ok(token_error(
                        "invalid_request",
                        "redirect_uri: Input should be a valid URL",
                    ))
                }
            },
            None => None,
        };
        let Some(auth_code) = oauth.load_authorization_code(&client, code)? else {
            return Ok(token_error(
                "invalid_grant",
                "authorization code does not exist",
            ));
        };
        if auth_code.expires_at < crate::auth::now() {
            return Ok(token_error(
                "invalid_grant",
                "authorization code has expired",
            ));
        }
        // /authorize と /token で redirect_uri が変わっていないこと（RFC 6749 10.6）
        let redirect_ok = if auth_code.redirect_uri_provided_explicitly {
            token_redirect.as_deref() == Some(auth_code.redirect_uri.as_str())
        } else {
            token_redirect.is_none()
                || token_redirect.as_deref() == Some(auth_code.redirect_uri.as_str())
        };
        if !redirect_ok {
            return Ok(token_error(
                "invalid_request",
                "redirect_uri did not match the one used when creating auth code",
            ));
        }
        if pkce_s256(verifier) != auth_code.code_challenge {
            return Ok(token_error("invalid_grant", "incorrect code_verifier"));
        }
        match oauth.exchange_authorization_code(&client, &auth_code)? {
            Ok(t) => t,
            Err(e) => return Ok(e.into()),
        }
    } else {
        let Some(refresh) = form.get("refresh_token") else {
            return Ok(token_error(
                "invalid_request",
                "refresh_token: Field required",
            ));
        };
        let Some(current) = oauth.load_refresh_token(&client, refresh)? else {
            if oauth.revoke_on_refresh_reuse(&client, refresh)? {
                return Ok(token_error(
                    "invalid_grant",
                    "refresh token was already used; every token of this client has been revoked",
                ));
            }
            return Ok(token_error("invalid_grant", "refresh token does not exist"));
        };
        if current.expires_at < crate::auth::now() {
            return Ok(token_error("invalid_grant", "refresh token has expired"));
        }
        let scopes: Vec<String> = match form.get("scope").filter(|s| !s.is_empty()) {
            Some(s) => s.split(' ').map(str::to_string).collect(),
            None => current.scopes.clone(),
        };
        if let Some(bad) = scopes.iter().find(|s| !current.scopes.contains(s)) {
            return Ok(token_error(
                "invalid_scope",
                &format!("cannot request scope `{bad}` not provided by refresh token"),
            ));
        }
        match oauth.exchange_refresh_token(&client, refresh, scopes)? {
            Ok(t) => t,
            Err(e) => return Ok(e.into()),
        }
    };
    Ok(token_response(
        StatusCode::OK,
        serde_json::to_value(tokens).unwrap_or_default(),
    ))
}

// ---------------------------------------------------------------------------
// /register（RFC 7591）

async fn register(State(state): State<AppState>, body: Bytes) -> Result<Response, DbError> {
    let invalid = |description: String| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_client_metadata", "error_description": description })),
        )
            .into_response()
    };
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Ok(invalid(format!("Invalid JSON: {e}"))),
    };
    let client =
        match crate::auth::client_from_registration(&value, &state.oauth.redirect_allowlist) {
            Ok(client) => client,
            Err(description) => return Ok(invalid(description)),
        };
    let unavailable = |status: StatusCode, description: &str| {
        let mut response = (
            status,
            Json(json!({ "error": "temporarily_unavailable", "error_description": description })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        no_store(response)
    };
    if !state.oauth.admit_registration() {
        tracing::warn!("client registration refused: too many registrations this minute");
        return Ok(unavailable(
            StatusCode::TOO_MANY_REQUESTS,
            "too many client registrations; try again in a minute",
        ));
    }
    // 平文の client_secret を返すのはこの 1 回だけ（DB にはハッシュだけを置く）
    let body = serde_json::to_value(&client).unwrap_or_default();
    let (client_name, method) = (
        client.client_name.clone(),
        client.token_endpoint_auth_method.clone(),
    );
    if !state.oauth.register_client(client)? {
        tracing::warn!("client registration refused: every registered client is in use");
        return Ok(unavailable(
            StatusCode::SERVICE_UNAVAILABLE,
            "the client registry is full",
        ));
    }
    tracing::info!(
        client_name = client_name.as_deref().unwrap_or("-"),
        method = %method,
        "registered oauth client"
    );
    Ok(no_store((StatusCode::CREATED, Json(body)).into_response()))
}

// ---------------------------------------------------------------------------
// /revoke（RFC 7009）

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, DbError> {
    let oauth = state.oauth.as_ref();
    let form = parse_form(&body);
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let client = match oauth.authenticate_client(&form, authorization).await? {
        Ok(client) => client,
        Err(message) => {
            return Ok(token_response(
                StatusCode::UNAUTHORIZED,
                json!({ "error": "invalid_client", "error_description": message }),
            ))
        }
    };
    let Some(token) = form.get("token").filter(|t| !t.is_empty()) else {
        return Ok(token_error("invalid_request", "token: Field required"));
    };
    // 知らないトークンでも 200（RFC 7009 §2.2）
    oauth.revoke(&client, token)?;
    Ok(token_response(StatusCode::OK, json!({})))
}

// ---------------------------------------------------------------------------
// /relay/v1（POST JSON-RPC、GET 405、DELETE 200）

fn unauthorized(oauth: &OAuthServer) -> Response {
    let www = format!(
        "Bearer error=\"invalid_token\", error_description=\"Authentication required\", resource_metadata=\"{}\"",
        oauth.resource_metadata_url()
    );
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid_token", "error_description": "Authentication required" })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&www) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if raw.len() > 7 && raw[..7].eq_ignore_ascii_case("bearer ") {
        Some(&raw[7..])
    } else {
        None
    }
}

/// Bearer を relay に束ねられたトークンとして照合する。
fn authenticate(oauth: &OAuthServer, headers: &HeaderMap) -> Result<IssuedToken, Box<Response>> {
    let Some(token) = bearer(headers) else {
        return Err(Box::new(unauthorized(oauth)));
    };
    oauth
        .load_access_token(token, &oauth.resource_url)
        .map_err(|e| Box::new(e.into_response()))?
        .ok_or_else(|| Box::new(unauthorized(oauth)))
}

async fn relay_mcp(State(state): State<AppState>, request: Request) -> Response {
    let path = crate::relay::PREFIX;
    let principal = match authenticate(&state.oauth, request.headers()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    tracing::info!(
        path,
        subject = %principal.subject,
        http_method = %request.method(),
        "mcp"
    );
    crate::relay::serve(
        state.relay.clone(),
        principal.subject,
        principal.client_id,
        request,
    )
    .await
}
