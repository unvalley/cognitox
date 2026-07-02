//! Common test utilities
//!
//! Each integration test file includes this module separately, so helpers used
//! by only some files look dead to the others. Allow it module-wide.
#![allow(dead_code)]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use cognitox::{api, storage::Storage};
use serde_json::Value;
use tower::ServiceExt;

pub struct TestClient {
    storage: Storage,
}

/// Response wrapper for test assertions
pub struct TestResponse {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl TestResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &axum::http::HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// Async response wrapper for reqwest-like API
pub struct AsyncResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl AsyncResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

impl TestClient {
    pub fn new() -> Self {
        Self {
            storage: Storage::new(),
        }
    }

    /// Make a Cognito API request and return just the JSON body (for success cases)
    pub async fn cognito_request(&self, target: &str, body: Value) -> Value {
        let (status, json) = self.request(target, body).await;
        assert!(
            status.is_success(),
            "Expected success, got {}: {:?}",
            status,
            json
        );
        json
    }

    /// Make a Cognito API request and return the raw response (for error case testing)
    pub async fn cognito_request_raw(&self, target: &str, body: Value) -> AsyncResponse {
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
            .unwrap()
            .to_vec();

        AsyncResponse { status, body }
    }

    /// Make a Cognito API request (legacy method)
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

    /// Make a GET request
    pub async fn get(&self, uri: &str) -> TestResponse {
        self.get_with_headers(uri, &[]).await
    }

    /// Make a GET request with additional headers
    pub async fn get_with_headers(&self, uri: &str, headers: &[(&str, &str)]) -> TestResponse {
        let app = api::create_router(self.storage.clone());

        let mut request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "localhost:9229");

        for (name, value) in headers {
            request = request.header(*name, *value);
        }

        let request = request.body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        TestResponse {
            status,
            headers,
            body,
        }
    }

    /// Make a GET request with Authorization header
    pub async fn get_with_auth(&self, uri: &str, token: &str) -> TestResponse {
        let app = api::create_router(self.storage.clone());

        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "localhost:9229")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        TestResponse {
            status,
            headers,
            body,
        }
    }

    /// Make a POST request with form data
    pub async fn post_form(&self, uri: &str, params: &[(&str, &str)]) -> TestResponse {
        let app = api::create_router(self.storage.clone());

        let form_body = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("host", "localhost:9229")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        TestResponse {
            status,
            headers,
            body,
        }
    }
}

impl Default for TestClient {
    fn default() -> Self {
        Self::new()
    }
}
