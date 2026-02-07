//! ConfirmForgotPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::ClientId,
    validation::validate_password,
};

use super::helpers::{hash_password, normalize_confirmation_code};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
    confirmation_code: String,
    password: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate new password
    validate_password(&req.password)?;

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

    // Normalize codes for comparison (removes dashes, converts to uppercase)
    if normalize_confirmation_code(&reset_code.code)
        != normalize_confirmation_code(&req.confirmation_code)
    {
        return Err(AppError::InvalidConfirmationCode);
    }

    if reset_code.expires_at < Utc::now() {
        storage.delete_password_reset_code(&user.id).await;
        return Err(AppError::ExpiredCode);
    }

    user.password_hash = hash_password(&req.password).map_err(AppError::Internal)?;
    user.last_modified_date = Utc::now();

    storage.update_user(user.clone()).await;
    storage.delete_password_reset_code(&user.id).await;

    Ok(json!({}))
}
