//! DeleteUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUser.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::extract_user_id_from_token;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user_id =
        extract_user_id_from_token(&req.access_token).ok_or(AppError::InvalidAccessToken)?;

    storage
        .delete_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;
    storage.delete_refresh_tokens_for_user(&user_id).await;

    Ok(json!({}))
}
