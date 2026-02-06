pub mod cognito_idp;
pub mod extractor;
pub mod oauth2;

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
        // Health check
        .route("/health", get(health))
        // OpenID Connect Discovery
        .route(
            "/.well-known/openid-configuration",
            get(oauth2::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        // OAuth 2.0 endpoints
        .route("/oauth2/authorize", get(oauth2::authorize))
        .route("/oauth2/token", post(oauth2::token))
        .route("/oauth2/userInfo", get(oauth2::userinfo))
        // Cognito API
        .route("/", post(cognito_idp::handle_request))
        .with_state(storage)
}
