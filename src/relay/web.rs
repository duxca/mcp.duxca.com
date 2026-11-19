//! `/relay/` のチャット画面。持ち主がブラウザから agent `user` として relay で会話する。
//! 中身は静的ファイルだけで、バイナリに埋め込む。認可は画面が公開クライアントとして
//! `/register` → `/authorize`（PKCE）→ `/token` を自分で行い、`POST /relay/v1` を呼ぶ。

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

pub const WEB_PATH: &str = "/relay/";
/// 画面の redirect_uri（`{PUBLIC_URL}/relay/callback`）。中身は `/relay/` と同じ画面。
pub const CALLBACK_PATH: &str = "/relay/callback";

const INDEX_HTML: &str = include_str!("web/index.html");
const APP_JS: &str = include_str!("web/app.js");
const APP_CSS: &str = include_str!("web/app.css");

/// 通信は自オリジンだけ。本文は DOM のテキストとしてしか描かないので、Trusted Types で
/// innerHTML などの文字列から HTML を作る口も閉じておく。
pub const CSP: &str =
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; \
require-trusted-types-for 'script'; trusted-types 'none'";

pub fn router() -> Router {
    Router::new()
        .route("/relay", get(|| async { Redirect::permanent(WEB_PATH) }))
        .route(WEB_PATH, get(|| async { page() }))
        .route(CALLBACK_PATH, get(|| async { page() }))
        .route(
            "/relay/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route(
            "/relay/app.css",
            get(|| async { asset("text/css; charset=utf-8", APP_CSS) }),
        )
}

fn with_headers(mut response: Response, cache: &'static str) -> Response {
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // callback の URL には認可コードが載る
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

fn page() -> Response {
    with_headers(
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            INDEX_HTML,
        )
            .into_response(),
        "no-store",
    )
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    with_headers(
        ([(header::CONTENT_TYPE, content_type)], body).into_response(),
        "no-cache",
    )
}
