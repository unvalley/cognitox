//! RespondToAuthChallenge API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html>

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{AppError, Result};
use crate::storage::Storage;
use crate::types::ClientId;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    #[allow(dead_code)]
    client_id: ClientId,
    challenge_name: String,
    #[allow(dead_code)]
    challenge_responses: Option<HashMap<String, String>>,
}

pub async fn handler(_storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    Err(AppError::NotImplemented(format!(
        "Challenge: {}",
        req.challenge_name
    )))
}
