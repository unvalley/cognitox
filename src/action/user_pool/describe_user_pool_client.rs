//! DescribeUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPoolClient.html>

use serde::Deserialize;
use serde_json::{Value, json};

use super::create_user_pool_client::build_client_response;
use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
    client_id: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    if client.user_pool_id != req.user_pool_id {
        return Err(AppError::UserPoolClientNotFound);
    }

    Ok(json!({
        "UserPoolClient": build_client_response(&client)
    }))
}
