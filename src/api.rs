pub mod cognito_idp;
pub mod extractor;

use axum::{
    Json, Router,
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::jwt::get_jwks;
use crate::storage::Storage;

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// JWKS endpoint for JWT public key distribution
async fn jwks() -> Json<Value> {
    Json(get_jwks())
}

pub fn create_router(storage: Storage) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/", post(cognito_idp::handle_request))
        .with_state(storage)
}
