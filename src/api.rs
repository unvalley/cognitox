pub mod cognito_idp;
pub mod extractor;

use axum::{
    Json, Router,
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::storage::Storage;

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub fn create_router(storage: Storage) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", post(cognito_idp::handle_request))
        .with_state(storage)
}
