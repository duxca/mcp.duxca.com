mod auth;
mod config;
mod db;
mod relay;
mod routes;
#[cfg(test)]
mod tests;

use auth::{GitHubLogin, GitHubOAuth, HttpClientMetadataFetcher, OAuthServer};
use config::Config;
use routes::{router, AppState};
use std::future::IntoFuture;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
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
        database = %config.database_path,
        "starting mcp.duxca.com gateway"
    );
    let db = db::Db::open(&config.database_path, config.sqlite_wal_autocheckpoint)?;

    let oauth = Arc::new(OAuthServer::new(
        &public_url,
        allowed_ids,
        github,
        Arc::new(HttpClientMetadataFetcher),
        config.redirect_allowlist()?,
        db.clone(),
    ));

    let relay = Arc::new(relay::Relay::new(
        &public_url,
        config.relay_max_total_storage_bytes,
        db,
    ));
    tracing::info!(endpoint = %relay.base_url(), "relay ready (OAuth, rooms per GitHub id)");

    let relay_on_shutdown = relay.clone();
    let state = AppState { oauth, relay };

    let app = router(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = config.listen_addr()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr} (Ctrl+C / SIGTERM for graceful shutdown)");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        shutdown_signal().await;
        relay_on_shutdown.store.close();
        let _ = shutdown_tx.send(());
    });
    // Cloud Run は SIGTERM の 10 秒後に SIGKILL する。litestream の最終同期の時間を残すため、
    // 処理中の要求（webhook・GitHub・CIMD の外部呼び出し）を待つのは 3 秒までにする
    tokio::select! {
        result = server.into_future() => result?,
        _ = async {
            let _ = shutdown_rx.await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        } => tracing::warn!("graceful shutdown timed out, dropping in-flight requests"),
    }
    tracing::info!("gateway stopped");
    Ok(())
}

async fn shutdown_signal() {
    let mut term = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        r = tokio::signal::ctrl_c() => match r {
            Ok(()) => tracing::info!("received Ctrl+C; shutting down"),
            Err(err) => tracing::error!(%err, "failed to install Ctrl+C handler"),
        },
        _ = term.recv() => tracing::info!("received SIGTERM; shutting down"),
    }
}
