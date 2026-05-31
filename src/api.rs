pub mod cognito_idp;
pub mod extractor;
pub mod hosted_ui;
pub mod oauth2;

use axum::{
    Json, Router,
    body::Body,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rust_embed::RustEmbed;
use serde_json::{Value, json};

use crate::jwt::get_jwks;
use crate::storage::Storage;

/// Admin/Preact UI bundled at compile time.
///
/// The assets are staged into `$OUT_DIR/ui/` by `build.rs` — either copied
/// from `ui/dist/` when a real `pnpm --dir ui build` has been run, or
/// populated with minimal placeholders otherwise. The indirection keeps
/// `cargo publish --verify` happy (build scripts may only write inside
/// `OUT_DIR`) and lets fresh clones compile without Node installed.
#[derive(RustEmbed)]
#[folder = "$OUT_DIR/ui/"]
struct UiAssets;

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// JWKS endpoint for JWT public key distribution
async fn jwks() -> Json<Value> {
    Json(get_jwks())
}

/// Serve an embedded file by path, or a fallback asset (SPA entry HTML) on miss.
fn serve_embedded(path: &str, fallback: &str) -> Response {
    let file = UiAssets::get(path).or_else(|| UiAssets::get(fallback));
    match file {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(content.data.into_owned()))
                .unwrap()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

async fn assets_handler(Path(path): Path<String>) -> Response {
    let full = format!("assets/{path}");
    match UiAssets::get(&full) {
        Some(content) => {
            let mime = mime_guess::from_path(&full).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(content.data.into_owned()))
                .unwrap()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

async fn admin_index() -> Response {
    serve_embedded("index.html", "index.html")
}

async fn admin_handler(Path(path): Path<String>) -> Response {
    // Admin SPA: fall back to index.html for deep links
    serve_embedded(&path, "index.html")
}

async fn ui_index() -> Response {
    serve_embedded("index.html", "index.html")
}

async fn ui_handler(Path(path): Path<String>) -> Response {
    // Preact UI SPA: fall back to index.html for deep links
    serve_embedded(&path, "index.html")
}

pub fn create_router(storage: Storage) -> Router {
    Router::new()
        // Static assets (must be before SPA routes)
        .route("/assets/{*path}", get(assets_handler))
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
        .route("/logout", get(oauth2::logout))
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
        .route("/ui", get(ui_index))
        .route("/ui/", get(ui_index))
        .route("/ui/{*path}", get(ui_handler))
        // Admin UI - serves SPA at /admin/*
        .route("/admin", get(admin_index))
        .route("/admin/", get(admin_index))
        .route("/admin/{*path}", get(admin_handler))
        // Cognito API
        .route("/", post(cognito_idp::handle_request))
        .with_state(storage)
}
