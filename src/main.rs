mod auth;
mod backend;
mod config;
mod routes;
#[cfg(test)]
mod tests;

use auth::{GitHubLogin, GitHubOAuth, HttpClientMetadataFetcher, OAuthServer};
use backend::StdioMcpBackend;
use config::Config;
use routes::{router, AppState};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .init();

    let config = Config::from_env()?;
    let public_url = config.normalize_public_url()?;
    let github = Arc::new(GitHubOAuth::new(
        config.github_client_id.clone(),
        config.github_client_secret.clone(),
        format!("{public_url}{}", auth::GITHUB_CALLBACK_PATH),
    ));
    if !github.configured() {
        tracing::warn!("GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET 未設定。OAuth は動かない");
    }

    let allowed_ids = Arc::new(RwLock::new(config.allowed_ids()));
    tracing::info!(
        %public_url,
        port = config.port,
        allowed = ?allowed_ids.read().ok().as_deref(),
        "starting mcp.duxca.com gateway"
    );

    let oauth = Arc::new(OAuthServer::new(
        &public_url,
        allowed_ids,
        github,
        Arc::new(HttpClientMetadataFetcher),
    ));

    let cwd = config
        .claude_cwd
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
        });
    let backend = StdioMcpBackend::new(config.claude_command_argv(), cwd);

    let state = AppState {
        public_url,
        backend,
        oauth,
    };

    let app = router(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
