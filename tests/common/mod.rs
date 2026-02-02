//! Common test utilities

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use cognito_emulator::{api, storage::Storage};
use serde_json::Value;
use tower::ServiceExt;

pub struct TestClient {
    storage: Storage,
}

impl TestClient {
    pub fn new() -> Self {
        Self {
            storage: Storage::new(),
        }
    }

    pub async fn request(&self, target: &str, body: Value) -> (StatusCode, Value) {
        let app = api::create_router(self.storage.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/x-amz-json-1.1")
            .header(
                "x-amz-target",
                format!("AWSCognitoIdentityProviderService.{}", target),
            )
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);

        (status, json)
    }
}

impl Default for TestClient {
    fn default() -> Self {
        Self::new()
    }
}
