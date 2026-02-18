use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use cognito_emulator::{api, storage::Storage};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn default_data_file_path() -> PathBuf {
    // Decision note:
    // We default to /data in containers to align with common Docker persistence patterns
    // used by local emulators/object stores (e.g., DynamoDB Local/MinIO-style mounts),
    // so users can persist with a simple volume mount. Outside containers, we store in
    // ./.cognitox to keep local state project-scoped and avoid top-level file clutter.
    // DATA_FILE still takes precedence for explicit overrides.
    if Path::new("/data").is_dir() || Path::new("/.dockerenv").exists() {
        return PathBuf::from("/data/storage.json");
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".cognitox")
        .join("storage.json")
}

fn resolve_data_file_path() -> PathBuf {
    match std::env::var("DATA_FILE") {
        Ok(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => default_data_file_path(),
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cognito_emulator=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize storage
    let data_file = resolve_data_file_path();
    tracing::info!("Using data file: {}", data_file.display());
    let storage = Storage::try_with_data_file(Some(data_file)).unwrap_or_else(|e| {
        tracing::error!("Failed to initialize storage: {e}");
        std::process::exit(1);
    });

    // Build router
    let app = api::create_router(storage)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Start server
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9229);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Starting Cognito emulator on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
