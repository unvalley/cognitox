//! ConfirmForgotPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::hash_password;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: String,
    username: String,
    confirmation_code: String,
    password: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    let mut user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let reset_code = storage
        .get_password_reset_code(&user.id)
        .await
        .ok_or(AppError::InvalidConfirmationCode)?;

    if reset_code.code != req.confirmation_code {
        return Err(AppError::InvalidConfirmationCode);
    }

    if reset_code.expires_at < Utc::now() {
        storage.delete_password_reset_code(&user.id).await;
        return Err(AppError::ExpiredCode);
    }

    user.password_hash = hash_password(&req.password);
    user.last_modified_date = Utc::now();

    storage.update_user(user.clone()).await;
    storage.delete_password_reset_code(&user.id).await;

    Ok(json!({}))
}
