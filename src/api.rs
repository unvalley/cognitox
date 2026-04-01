pub mod cognito_idp;
pub mod extractor;
pub mod hosted_ui;
pub mod oauth2;

use axum::{
    Json, Router,
    routing::{get, post},
};
use serde_json::{Value, json};
use tower_http::services::{ServeDir, ServeFile};

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
    // Preact UI static files (if available)
    let ui_service =
        ServeDir::new("ui/dist").not_found_service(ServeFile::new("ui/dist/index.html"));

    // Admin UI static files - disable index.html auto-serve so admin.html is used via fallback
    let admin_service = ServeDir::new("ui/dist")
        .append_index_html_on_directories(false)
        .not_found_service(ServeFile::new("ui/dist/admin.html"));

    // Static assets served from root /assets/* for SPA deep links
    let assets_service = ServeDir::new("ui/dist/assets");

    Router::new()
        // Static assets (must be before SPA routes)
        .nest_service("/assets", assets_service)
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
        // Rust-based Hosted UI (fallback/simple mode)
        .route(
            "/login",
            get(hosted_ui::login_page).post(hosted_ui::login_submit),
        )
        .route(
            "/signup",
            get(hosted_ui::signup_page).post(hosted_ui::signup_submit),
        )
        .route(
            "/confirm",
            get(hosted_ui::confirm_page).post(hosted_ui::confirm_submit),
        )
        .route(
            "/forgot-password",
            get(hosted_ui::forgot_password_page).post(hosted_ui::forgot_password_submit),
        )
        .route(
            "/reset-password",
            get(hosted_ui::reset_password_page).post(hosted_ui::reset_password_submit),
        )
        // Preact UI (modern mode) - serves SPA at /ui/*
        .nest_service("/ui", ui_service)
        // Admin UI - serves SPA at /admin/*
        .nest_service("/admin", admin_service)
        // Cognito API
        .route("/", post(cognito_idp::handle_request))
        .with_state(storage)
}
