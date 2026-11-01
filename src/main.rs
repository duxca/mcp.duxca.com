mod auth;
mod config;
mod relay;
mod routes;
#[cfg(test)]
mod tests;

use auth::{GitHubLogin, GitHubOAuth, HttpClientMetadataFetcher, OAuthServer};
use config::Config;
use routes::{router, AppState};
use std::sync::{Arc, RwLock};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            // RUST_LOG 未設定でも relay の会話ログ（info）が journald に出るように
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let config = Config::from_env()?;
    let public_url = config.normalize_public_url()?;
    let github = Arc::new(GitHubOAuth::new(
        config.github_client_id.clone(),
        config.github_client_secret.clone(),
        format!("{public_url}{}", auth::REDIRECT_PATH),
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
        config.redirect_allowlist()?,
    ));

    let relay = Arc::new(relay::Relay::new(
        &public_url,
        config.relay_max_total_storage_bytes,
    ));
    tracing::info!(endpoint = %relay.base_url(), "relay ready (OAuth, rooms per GitHub id)");

    let relay_on_shutdown = relay.clone();
    let state = AppState { oauth, relay };

    let app = router(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = config.listen_addr()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr} (Ctrl+C for graceful shutdown)");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            relay_on_shutdown.store.close();
        })
        .await?;
    tracing::info!("gateway stopped");
    Ok(())
}

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("received Ctrl+C; shutting down"),
        Err(err) => tracing::error!(%err, "failed to install Ctrl+C handler"),
    }
}
