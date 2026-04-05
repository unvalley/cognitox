use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use bpaf::Bpaf;
use cognito_emulator::{api, storage::Storage};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// AWS Cognito User Pools emulator for local development.
///
/// Implements all 119 cognito-idp API operations so you can develop and
/// test Cognito-dependent applications without connecting to AWS.
///
///   Admin Console:  http://localhost:<PORT>/admin/
///   Hosted UI:      http://localhost:<PORT>/login?...
///   Health check:   http://localhost:<PORT>/health
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options, version)]
struct Cli {
    /// Port to listen on
    #[bpaf(short, long, env("PORT"), fallback(9229), display_fallback)]
    port: u16,

    /// Path to persist emulator state (JSON snapshot). If set, state survives restarts.
    #[bpaf(short, long, env("DATA_FILE"), argument("FILE"))]
    data_file: Option<PathBuf>,

    /// Log level filter (e.g. "debug", "cognito_emulator=debug,tower_http=info")
    #[bpaf(short, long, env("RUST_LOG"), argument("FILTER"))]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() {
    // Load environment variables (before CLI parsing so env vars are available)
    dotenvy::dotenv().ok();

    let cli = cli().run();

    // Initialize logging
    let log_filter = cli
        .log_level
        .unwrap_or_else(|| "cognito_emulator=debug,tower_http=debug".to_string());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize storage
    let storage = Arc::new(
        Storage::try_with_data_file(cli.data_file).unwrap_or_else(|e| {
            tracing::error!("Failed to initialize storage: {e}");
            std::process::exit(1);
        }),
    );

    // Build router
    let app = api::create_router((*storage).clone())
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    tracing::info!("Starting Cognito emulator on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    let shutdown_storage = storage.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to listen for ctrl+c");
            tracing::info!("Shutdown signal received, flushing persistence...");
            if let Err(e) = shutdown_storage.flush_persistence().await {
                tracing::error!("Failed to flush persistence on shutdown: {e}");
            }
            tracing::info!("Shutdown complete");
        })
        .await
        .expect("server exited with error");
}
