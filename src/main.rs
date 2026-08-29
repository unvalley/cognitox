use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use bpaf::Bpaf;
use cognitox::{api, config::StorageConfig, jwt::set_issuer_base_url, storage::Storage};
use tokio::signal;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_PORT: u16 = 9229;
const DEFAULT_STORAGE_MODE: &str = "persistent";
const DEFAULT_DATA_FILE: &str = "cognitox-data.json";
const DEFAULT_LOG_FILTER: &str = "cognitox=info,tower_http=info";

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
    #[bpaf(
        short,
        long,
        env("COGNITOX_PORT"),
        fallback(DEFAULT_PORT),
        display_fallback
    )]
    port: u16,

    /// Storage mode: "persistent" (file-backed, default) or "memory" (no persistence).
    /// When "persistent", --data-file defaults to "cognitox-data.json".
    #[bpaf(
        long,
        env("COGNITOX_STORAGE_MODE"),
        fallback(String::from(DEFAULT_STORAGE_MODE)),
        display_fallback
    )]
    storage_mode: String,

    /// Path to persist emulator state (JSON snapshot).
    /// Defaults to "cognitox-data.json" when --storage-mode=persistent.
    #[bpaf(short, long, env("COGNITOX_DATA_FILE"), argument("FILE"))]
    data_file: Option<PathBuf>,

    /// Log level filter (e.g. "debug", "cognitox=debug,tower_http=info")
    #[bpaf(short, long, env("RUST_LOG"), argument("FILTER"))]
    log_level: Option<String>,
}

impl Cli {
    fn log_filter(&self) -> String {
        self.log_level
            .clone()
            .unwrap_or_else(|| DEFAULT_LOG_FILTER.to_string())
    }

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
                let path = self
                    .data_file
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_FILE));
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
    let log_filter = cli.log_filter();
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

    if std::env::var("COGNITOX_ISSUER_BASE_URL").is_err()
        && let Err(e) = set_issuer_base_url(format!("http://localhost:{}", cli.port))
    {
        tracing::warn!("Failed to configure JWT issuer base URL: {e}");
    }

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
            wait_for_shutdown_signal().await;
            tracing::info!("Shutdown signal received, flushing persistence...");
            if let Err(e) = shutdown_storage.flush_persistence().await {
                tracing::error!("Failed to flush persistence on shutdown: {e}");
            }
            tracing::info!("Shutdown complete");
        })
        .await
        .expect("server exited with error");
}

/// Wait for a signal used by both local terminals and container supervisors.
/// Docker and Kubernetes send SIGTERM, while Ctrl+C sends SIGINT.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(signal) => Some(signal),
            Err(error) => {
                tracing::error!("failed to install SIGTERM handler: {error}");
                None
            }
        };

        if let Some(ref mut terminate) = terminate {
            tokio::select! {
                result = signal::ctrl_c() => {
                    if let Err(error) = result {
                        tracing::error!("failed to listen for ctrl+c: {error}");
                    }
                }
                _ = terminate.recv() => {}
            }
        } else if let Err(error) = signal::ctrl_c().await {
            tracing::error!("failed to listen for ctrl+c: {error}");
        }
    }

    #[cfg(not(unix))]
    if let Err(error) = signal::ctrl_c().await {
        tracing::error!("failed to listen for ctrl+c: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_for_test() -> Cli {
        Cli {
            port: DEFAULT_PORT,
            storage_mode: DEFAULT_STORAGE_MODE.to_string(),
            data_file: None,
            log_level: None,
        }
    }

    #[test]
    fn default_log_filter_is_info() {
        assert_eq!(cli_for_test().log_filter(), DEFAULT_LOG_FILTER);
    }

    #[test]
    fn explicit_log_filter_overrides_default() {
        let mut cli = cli_for_test();
        cli.log_level = Some("cognitox=warn".to_string());
        assert_eq!(cli.log_filter(), "cognitox=warn");
    }
}
