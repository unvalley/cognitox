use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use bpaf::Bpaf;
use cognito_emulator::{api, config::StorageConfig, storage::Storage};
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

    /// Storage mode: "memory" (no persistence) or "persistent" (file-backed).
    /// When "persistent", --data-file is required.
    #[bpaf(
        long,
        env("COGNITOX_STORAGE_MODE"),
        fallback(String::from("memory")),
        display_fallback
    )]
    storage_mode: String,

    /// Path to persist emulator state (JSON snapshot). Required when --storage-mode=persistent.
    #[bpaf(short, long, env("DATA_FILE"), argument("FILE"))]
    data_file: Option<PathBuf>,

    /// Log level filter (e.g. "debug", "cognito_emulator=debug,tower_http=info")
    #[bpaf(short, long, env("RUST_LOG"), argument("FILTER"))]
    log_level: Option<String>,
}

impl Cli {
    fn storage_config(&self) -> Result<StorageConfig, String> {
        match self.storage_mode.as_str() {
            "memory" => {
                // If data_file is provided but mode is memory, upgrade to persistent
                // for backward compatibility with the old --data-file-only interface.
                match &self.data_file {
                    Some(path) => Ok(StorageConfig::persistent(path.clone())),
                    None => Ok(StorageConfig::memory()),
                }
            }
            "persistent" => {
                let path = self.data_file.clone().ok_or_else(|| {
                    "--data-file is required when --storage-mode=persistent".to_string()
                })?;
                Ok(StorageConfig::persistent(path))
            }
            other => Err(format!(
                "Unknown storage mode: {other}. Expected \"memory\" or \"persistent\"."
            )),
        }
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables (before CLI parsing so env vars are available)
    dotenvy::dotenv().ok();

    let cli = cli().run();

    // Initialize logging
    let log_filter = cli
        .log_level
        .clone()
        .unwrap_or_else(|| "cognito_emulator=debug,tower_http=debug".to_string());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Build storage config
    let storage_config = cli.storage_config().unwrap_or_else(|e| {
        tracing::error!("{e}");
        std::process::exit(1);
    });

    // Initialize storage
    let storage = Arc::new(Storage::with_config(storage_config).unwrap_or_else(|e| {
        tracing::error!("Failed to initialize storage: {e}");
        std::process::exit(1);
    }));

    tracing::info!("Storage backend: {}", storage.backend_description());

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
