//! Custom extractors for AWS Cognito API compatibility

use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
    http::header,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// Custom JSON extractor that accepts both `application/json` and `application/x-amz-json-1.1`
pub struct AmzJson<T>(pub T);

/// Malformed request body. Rendered as a Cognito-style
/// `SerializationException` so SDK clients parse it like any other API error.
#[derive(Debug)]
pub struct AmzJsonRejection {
    message: String,
}

impl IntoResponse for AmzJsonRejection {
    fn into_response(self) -> Response {
        AppError::Serialization(self.message).into_response()
    }
}

impl<S, T> FromRequest<S> for AmzJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AmzJsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Check content-type
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let is_json = content_type.starts_with("application/json")
            || content_type.starts_with("application/x-amz-json");

        if !is_json && !content_type.is_empty() {
            return Err(AmzJsonRejection {
                message: format!("Unsupported content-type: {}", content_type),
            });
        }

        // Extract body
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| AmzJsonRejection {
                message: format!("Failed to read body: {}", e),
            })?;

        // Parse JSON
        let value = serde_json::from_slice(&bytes).map_err(|e| AmzJsonRejection {
            message: format!("Invalid JSON: {}", e),
        })?;

        Ok(AmzJson(value))
    }
}
