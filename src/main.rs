mod auth;
mod backend;
mod config;
mod routes;
#[cfg(test)]
mod tests;

use auth::{GitHubLogin, GitHubOAuth, HttpClientMetadataFetcher, OAuthServer};
use backend::{BackendRegistry, StdioMcpBackend};
use config::Config;
use routes::{router, AppState};
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
        format!("{public_url}{}", auth::REDIRECT_PATH),
    ));
    if !github.configured() {
        tracing::warn!("GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET 未設定。OAuth は動かない");
    }

    let services = config.services()?;
    if services.is_empty() {
        anyhow::bail!("no MCP services configured");
    }
    let service_paths: Vec<String> = services.iter().map(|s| s.path.clone()).collect();
    for svc in &services {
        tracing::info!(
            path = %svc.path,
            command = %svc.command.join(" "),
            cwd = %svc.cwd.display(),
            "configured MCP service"
        );
    }

    let allowed_ids = Arc::new(RwLock::new(config.allowed_ids()));
    tracing::info!(
        %public_url,
        port = config.port,
        allowed = ?allowed_ids.read().ok().as_deref(),
        services = ?service_paths,
        "starting mcp.duxca.com gateway"
    );

    let oauth = Arc::new(OAuthServer::new(
        &public_url,
        allowed_ids,
        github,
        Arc::new(HttpClientMetadataFetcher),
        service_paths.clone(),
        config.redirect_allowlist()?,
    ));

    let mut backends = BackendRegistry::new();
    for svc in &services {
        let backend = StdioMcpBackend::named(
            format!("{}/{}", svc.name, svc.version),
            svc.command.clone(),
            svc.cwd.clone(),
        );
        backends.insert(svc.path.clone(), backend);
    }

    let state = AppState {
        backends: Arc::new(backends),
        oauth,
    };

    let app = router(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = config.listen_addr()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr} (Ctrl+C for graceful shutdown)");
    // StdioMcpBackend uses kill_on_drop(true); dropping AppState on shutdown
    // tears down MCP child processes with the gateway.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
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
