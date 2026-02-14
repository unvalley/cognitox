use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::error::{AppError, Result};

/// Deserialize request payload into a typed request.
pub fn parse_request<T: DeserializeOwned>(body: Value) -> Result<T> {
    serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))
}

/// Serialize typed response into Cognito JSON payload.
pub fn to_response_value<T: Serialize>(response: T) -> Result<Value> {
    serde_json::to_value(response).map_err(|e| AppError::Internal(format!("Invalid response: {e}")))
}
