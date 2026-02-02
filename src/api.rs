pub mod cognito_idp;
pub mod extractor;

use axum::{Router, routing::post};

use crate::storage::Storage;

pub fn create_router(storage: Storage) -> Router {
    Router::new()
        .route("/", post(cognito_idp::handle_request))
        .with_state(storage)
}
